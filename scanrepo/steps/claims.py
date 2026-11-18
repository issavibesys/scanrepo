"""Step 2: claim verification.

Extracts claims from the README ("zero dependencies", "no telemetry", "10x faster", "audited") and
looks for evidence for or against each one in the repository. A claim is never "proven" by a static
scan; the status says what evidence was found:

  supported               positive evidence in the repository
  no_contradiction_found  a negative claim (e.g. "no telemetry") and the scan found nothing against it
  unsupported             no evidence either way
  contradicted            the repository contains evidence against the claim
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from ..context import ScanContext
from ..fsutil import CODE_EXTS
from ..models import Claim, Finding, StepResult
from .behavior import scan_behavior
from .common import sanitize
from .deps import _norm, parse_manifests
from .inventory import collect, normalize_family

LABELS = {
    "zero_dependencies": "zero dependencies", "security_superlative": "absolute security claim",
    "audited": "security audit", "no_telemetry": "no telemetry / privacy", "offline_local": "offline / local only",
    "performance": "performance", "test_coverage": "test coverage", "production_ready": "production readiness",
    "license": "license", "open_source": "open source", "popularity": "popularity",
}


@dataclass
class Verdict:
    status: str
    severity: str = "info"
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    detail: str = ""


def _facts(ctx: ScanContext) -> dict[str, Any]:
    inv, dp, beh = collect(ctx), parse_manifests(ctx), scan_behavior(ctx)
    rels = {f.rel.lower() for f in ctx.files}
    ci_text = ""
    for rel in inv["ci_files"]:
        rf = next(f for f in ctx.files if f.rel == rel)
        ci_text += (ctx.read(rf, cache=True) or "").lower()
    cov_names = {".coveragerc", "codecov.yml", ".codecov.yml", "coverage.xml", "lcov.info", ".nycrc", ".nycrc.json", "coverage.json"}
    return {
        "inv": inv, "deps": dp, "beh": beh,
        "tests": [f for f in ctx.files if f.context == "test" and f.ext in CODE_EXTS],
        "src": [f for f in ctx.files if f.context == "production" and f.ext in CODE_EXTS],
        "security_md": [r for r in ("security.md", ".github/security.md", "docs/security.md") if r in rels],
        "audit_files": [f.rel for f in ctx.files if "audit" in f.name_lower and f.ext in ("md", "pdf", "txt", "rst", "html")],
        "bench": [f.rel for f in ctx.files if "bench" in f.rel.lower()],
        "coverage": [f.rel for f in ctx.files if f.name_lower in cov_names] or (["CI config mentions coverage"] if re.search(r"coverage|codecov|coveralls", ci_text) else []),
        "has_ci": bool(inv["ci_files"]),
    }


# ----------------------------------------------------------------------------- verifiers

def v_zero_deps(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    dp = f["deps"]
    if not dp["parsed"] and not dp["unparsed"]:
        return Verdict("unsupported", "low", 0.3, [], "No dependency manifest found, so the claim cannot be checked.")
    root = [d for d in dp["deps"] if d.file.count("/") == 0] or dp["deps"]
    runtime = [d for d in root if d.kind == "runtime"]
    if runtime:
        names = ", ".join(sorted({d.name for d in runtime})[:5])
        return Verdict("contradicted", "medium", 0.85, [f"{len(runtime)} runtime dependencies declared: {names}"],
                       "The manifests list runtime dependencies.")
    if dp["unparsed"]:
        return Verdict("no_contradiction_found", "info", 0.4, [f"parsed manifests list no runtime dependencies; not parsed: {', '.join(dp['unparsed'][:3])}"])
    return Verdict("supported", "info", 0.8, ["manifests declare 0 runtime dependencies"])


def v_security_superlative(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    ev = ["SECURITY.md present (a policy, not proof of security)"] if f["security_md"] else ["no SECURITY.md"]
    return Verdict("unsupported", "low", 0.5, ev, "Absolute security claims cannot be demonstrated by a repository. Treat as marketing.")


def v_audited(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    if f["audit_files"]:
        return Verdict("supported", "info", 0.5, [f"audit-related file: {f['audit_files'][0]}"], "A file exists, but its authenticity and scope are not verified.")
    return Verdict("unsupported", "medium", 0.6, ["no audit report found in the repository"],
                   "Ask for the report: who audited it, when, which version, and what the findings were.")


def v_no_telemetry(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    hits = [x for x in f["beh"]["findings"] if x.rule_id in ("beh.telemetry-sdk", "beh.telemetry-endpoint") and x.context == "production"]
    if hits:
        ev = [f"{x.file}:{x.line} {x.title}" for x in hits[:3]]
        return Verdict("contradicted", "high", 0.55, ev, "Telemetry/analytics code or endpoints are present. Check whether they are opt-in and what they send.")
    return Verdict("no_contradiction_found", "info", 0.4, ["no telemetry SDK or endpoint found in production code (static scan only)"])


def v_offline(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    hosts = f["beh"]["domains"]
    if hosts:
        names = ", ".join(sorted(hosts)[:4])
        return Verdict("contradicted", "low", 0.35, [f"{len(hosts)} external host(s) referenced in production code, e.g. {sanitize(names, 100)}"],
                       "The code references network endpoints; some may be optional or unrelated to the claim.")
    return Verdict("no_contradiction_found", "info", 0.4, ["no external hosts referenced in production code"])


def v_performance(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    if f["bench"]:
        return Verdict("supported", "info", 0.4, [f"benchmark files exist: {f['bench'][0]}"], "Benchmark code exists; its results were not reproduced.")
    return Verdict("unsupported", "low", 0.6, ["no benchmark code found"], "Performance claims need reproducible benchmarks.")


def v_test_coverage(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    n_t, n_s = len(f["tests"]), len(f["src"])
    if n_t == 0:
        return Verdict("unsupported", "medium", 0.6, ["no test files found"], "The claim mentions testing but the repository contains no tests.")
    if "100%" in text and not f["coverage"]:
        return Verdict("unsupported", "low", 0.5, [f"{n_t} test file(s) but no coverage configuration or report"], "A 100% figure needs a coverage report.")
    if n_s >= 20 and n_t / n_s < 0.05:
        return Verdict("unsupported", "low", 0.4, [f"{n_t} test file(s) for {n_s} source files"], "Very few tests relative to the amount of code.")
    return Verdict("no_contradiction_found", "info", 0.4, [f"{n_t} test file(s) for {n_s} source files"], "Tests exist; their quality and coverage were not measured.")


def v_production_ready(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    age = f["inv"]["git"].get("age_days")
    if "battle" in text.lower() and age is not None and age < 60:
        return Verdict("contradicted", "medium", 0.5, [f"first commit {age} day(s) ago"], "'Battle-tested' needs a track record. This repository is very young.")
    if not f["tests"]:
        return Verdict("unsupported", "medium", 0.5, ["no test files found"], "Production readiness without any tests is hard to believe.")
    if f["has_ci"]:
        return Verdict("no_contradiction_found", "info", 0.4, [f"{len(f['tests'])} test file(s) and CI configuration present"])
    return Verdict("unsupported", "low", 0.4, [f"{len(f['tests'])} test file(s) but no CI configuration"])


def v_license(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    token = next((g for g in m.groups() if g), None)
    claimed = normalize_family(token) if token else None
    inv = f["inv"]
    if not claimed:
        return Verdict("unsupported", "low", 0.3, [], "Could not interpret the claimed license.")
    if not inv["license_file"]:
        return Verdict("contradicted", "medium", 0.6, ["no license file at the repository root"], "The README names a license but the repository ships none.")
    detected = inv["license_detected"]
    if detected is None:
        return Verdict("unsupported", "low", 0.4, [f"{inv['license_file']} present but not recognised"], "")
    if detected == claimed:
        return Verdict("supported", "info", 0.8, [f"{inv['license_file']} reads as {detected}"])
    return Verdict("contradicted", "high", 0.6, [f"{inv['license_file']} reads as {detected}, README says {claimed}"], "License text and README disagree.")


def v_open_source(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    inv = f["inv"]
    if inv["license_file"]:
        return Verdict("supported", "info", 0.6, [f"license file: {inv['license_file']} ({inv['license_detected'] or 'unrecognised'})"])
    return Verdict("contradicted", "medium", 0.5, ["no license file"], "Without a license the code is not open source in the legal sense.")


def v_popularity(text: str, m: Any, f: dict[str, Any]) -> Verdict:
    return Verdict("unsupported", "info", 0.3, [], "Popularity cannot be verified from the repository. Check registry download stats and the publisher.")


VERIFIERS: dict[str, Callable[[str, Any, dict[str, Any]], Verdict]] = {
    "zero_dependencies": v_zero_deps, "security_superlative": v_security_superlative, "audited": v_audited,
    "no_telemetry": v_no_telemetry, "offline_local": v_offline, "performance": v_performance,
    "test_coverage": v_test_coverage, "production_ready": v_production_ready, "license": v_license,
    "open_source": v_open_source, "popularity": v_popularity,
}


# ----------------------------------------------------------------------------- README extraction

def _plain(line: str) -> str:
    s = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", line)
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    return s.strip(" #*->|\t")


def _quoted(line: str, pos: int) -> bool:
    """True when the match sits inside `code` or "quotes": those are examples, not the project's own claims."""
    before = line[:pos]
    return before.count("`") % 2 == 1 or before.count('"') % 2 == 1


def _extract(ctx: ScanContext, readmes: list[Any]) -> list[tuple[str, Any, int, str, Any]]:
    out: list[tuple[str, Any, int, str, Any]] = []
    per_cat: Counter = Counter()
    for rf in readmes:
        in_fence = False
        for i, line in enumerate((ctx.read(rf, cache=True) or "").splitlines(), 1):
            if line.strip().startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for rule in ctx.rules.groups["claims"]:
                cat = rule["category"]
                m = rule["_re"].search(line)
                if m and _quoted(line, m.start()):
                    continue
                if m and per_cat[cat] < 6 and cat in VERIFIERS:
                    per_cat[cat] += 1
                    out.append((cat, rf, i, _plain(line) or f"badge: {m.group(0)}", m))
    return out


# ----------------------------------------------------------------------------- README consistency checks

_INSTALL = (
    ("npm", re.compile(r"\b(?:npm|pnpm)[ \t]+(?:i|install|add)[ \t]+((?:-{1,2}[\w-]+(?:=\S+)?[ \t]+)*)(@?[\w.-]+(?:/[\w.-]+)?)")),
    ("npm", re.compile(r"\byarn[ \t]+add[ \t]+((?:-{1,2}[\w-]+[ \t]+)*)(@?[\w.-]+(?:/[\w.-]+)?)")),
    ("pypi", re.compile(r"\bpip3?[ \t]+install[ \t]+((?:-{1,2}[\w-]+(?:=\S+)?[ \t]+)*)([A-Za-z0-9][\w.-]*)")),
    ("cargo", re.compile(r"\bcargo[ \t]+install[ \t]+((?:-{1,2}[\w-]+[ \t]+)*)([A-Za-z0-9][\w-]*)")),
)
_MANIFEST_FOR = {"npm": ("package.json",), "pypi": ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"), "cargo": ("cargo.toml",)}
_ARCHIVE_URL = re.compile(r"https?://[^\s)>\"']+\.(?:zip|exe|msi|dmg|7z|rar|pkg|apk|tar\.gz)\b", re.I)
_PIPE_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
_TRUSTED_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "pypi.org", "npmjs.com", "crates.io", "files.pythonhosted.org")
_STOP = set("the and with that this from your have will for are you can not use using install usage return when then also into more most some such like each other only over than them these those what which while where would about after before".split())


def _readme_checks(ctx: ScanContext, f: dict[str, Any], readmes: list[Any]) -> list[Finding]:
    out: list[Finding] = []
    dp, inv = f["deps"], f["inv"]
    declared = {(d.eco, _norm(d.name, d.eco)) for d in dp["deps"]}
    popular = ctx.rules.popular
    parsed_lower = {p.lower().rsplit("/", 1)[-1] for p in dp["parsed"] + dp["unparsed"]}
    origin = (inv["git"].get("origin") or "").lower()
    n_install = 0
    for rf in readmes:
        text = ctx.read(rf, cache=True) or ""
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for eco, rx in _INSTALL:
                for m in rx.finditer(line):
                    name = m.group(2)
                    n = _norm(name, eco)
                    if n.endswith((".txt", ".in", ".toml", ".cfg", ".json", ".lock")) or n in ("http", "https", "git", "pip", "npm", "yarn", "pnpm"):
                        continue
                    if n in dp["names"][eco] or (eco, n) in declared or n in popular.get(eco, ()):
                        continue
                    has_pkg_def = bool(dp["names"][eco])
                    has_manifest = any(x in parsed_lower for x in _MANIFEST_FOR[eco])
                    if n_install >= 5:
                        continue
                    if has_pkg_def:
                        n_install += 1
                        out.append(Finding("claims", "readme.install-name-mismatch", f"README installs '{sanitize(name, 60)}' but this repository's package has another name",
                                           "medium", 0.5, rf.rel, i, sanitize(line, 200), "production",
                                           f"Package name(s) defined here: {', '.join(sorted(dp['names'][eco]))[:100]}. A mismatch is typical for fake copies of a project."))
                    elif not has_manifest:
                        n_install += 1
                        out.append(Finding("claims", "readme.install-no-manifest", f"README installs '{sanitize(name, 60)}' but the repository has no {eco} package definition",
                                           "low", 0.4, rf.rel, i, sanitize(line, 200), "production",
                                           "Verify that the package on the registry is published by the author of this repository."))
            for m in _ARCHIVE_URL.finditer(line):
                host = (urlsplit(m.group(0)).hostname or "").lower()
                same_repo = bool(origin) and host == "github.com" and urlsplit(m.group(0)).path.lower().startswith("/" + "/".join(origin.rstrip("/").split("/")[-2:]).removesuffix(".git") + "/")
                if same_repo or (host.endswith(_TRUSTED_HOSTS) and host != "github.com"):
                    continue
                out.append(Finding("claims", "readme.archive-download", "README links to a downloadable archive or executable outside the project's own releases",
                                   "medium", 0.45, rf.rel, i, sanitize(m.group(0), 200), "production",
                                   "Download binaries only from the official release page of the real project."))
                break
            if _PIPE_SHELL.search(line):
                out.append(Finding("claims", "readme.pipe-to-shell", "README tells users to pipe a download into a shell", "low", 0.4, rf.rel, i, sanitize(line, 200), "production",
                                   "Common practice, but the script is whatever the server returns at that moment."))
        out.extend(_keyword_stuffing(rf, text, f))
    return out


def _keyword_stuffing(rf: Any, text: str, f: dict[str, Any]) -> list[Finding]:
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    signal: Optional[tuple[int, str]] = None
    for i, line in enumerate(prose.splitlines(), 1):
        if line.lstrip().startswith("|"):
            continue
        items = [x.strip() for x in re.split(r"[,•·;]", line) if x.strip()]
        if len(items) >= 12 and all(len(x) <= 30 for x in items):
            signal = (i, f"a line with {len(items)} comma-separated keywords")
            break
    if signal is None:
        tokens = re.findall(r"[a-z][a-z-]{3,}", prose.lower())
        own = set().union(*f["deps"]["names"].values()) | {rf.rel.lower()}
        own |= {tok for n in own for tok in re.split(r"[^a-z]+", n) if tok}
        if len(tokens) >= 300:
            word, count = next(((w, c) for w, c in Counter(t for t in tokens if t not in _STOP and t not in own).most_common(1)), ("", 0))
            if count >= 30 and count / len(tokens) >= 0.08:
                signal = (1, f"the word '{sanitize(word, 30)}' makes up {count / len(tokens):.0%} of the text")
    if signal is None:
        return []
    thin = len(f["src"]) <= 2 and len(text) > 4000
    return [Finding("claims", "readme.keyword-stuffing", "README looks stuffed with search keywords", "low", 0.5 if thin else 0.3, rf.rel, signal[0],
                    sanitize(signal[1]), "production",
                    "Combined with very little code this is typical of fake or SEO-bait repositories." if thin else "On its own this is weak evidence.")]


def run(ctx: ScanContext) -> StepResult:
    res = StepResult("claims")
    facts = _facts(ctx)
    # only the root README describes the project; READMEs in subfolders describe parts of it
    readmes = [rf for rf in ctx.files if rf.name_lower.startswith("readme") and rf.rel.count("/") == 0][:5]
    if not readmes:
        res.notes.append("No README found, so there are no claims to verify")
        res.findings.append(Finding("claims", "readme.missing", "No README found", "info", 0.5, None, None, "", "production"))
        res.not_checked.append("Claims in places other than the README (website, docs site, package registry page) are not checked")
        return res
    for cat, rf, line, text, m in _extract(ctx, readmes):
        v = VERIFIERS[cat](text, m, facts)
        res.claims.append(Claim(cat, text, rf.rel, line, v.status, v.confidence, [sanitize(e, 160) for e in v.evidence]))
        if v.status in ("unsupported", "contradicted"):
            detail = (v.detail + (" Evidence: " + "; ".join(sanitize(e, 160) for e in v.evidence) if v.evidence else "")).strip()
            res.findings.append(Finding("claims", f"claim.{cat}.{v.status}", f"Claim {v.status.replace('_', ' ')}: {LABELS[cat]}",
                                        v.severity, v.confidence, rf.rel, line, text, "production", detail))
    res.findings.extend(_readme_checks(ctx, facts, readmes))
    counts = Counter(c.status for c in res.claims)
    res.data = {"claims_by_status": dict(counts), "readmes": [r.rel for r in readmes]}
    res.not_checked.append("Only README files are read for claims; website, docs site and registry descriptions are not")
    res.not_checked.append("A claim marked supported or no_contradiction_found shows only that no counter-evidence was found; it is not an audit")
    res.not_checked.append("Whether a package on npm/PyPI was really published by this repository's author needs registry access")
    return res
