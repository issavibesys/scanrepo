"""Step 3: dependencies. Manifest parsing, supply-chain red flags and known-vulnerability lookup.

Manifests are parsed as data. No package manager is run in a way that executes repository code
(pip-audit is deliberately not used: it installs packages, which runs setup code).
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..context import ScanContext
from ..fsutil import classify_context
from ..models import Finding, StepResult
from .common import LineIndex, sanitize

UNPARSED_MANIFESTS = {"setup.cfg", "pipfile", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "composer.json"}
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_VCS = ("git+", "hg+", "svn+", "bzr+", "http://", "https://")
_SUSPICIOUS_SCRIPT = re.compile(r"\b(?:curl|wget|powershell|certutil|bitsadmin)\b|base64|\beval\b|node\s+-e\b|\bnc\s|(?:ba)?sh\s+-c|https?://", re.I)
_SETUP_RISKY = re.compile(r"\b(?:urllib|urlopen|requests\.|subprocess|os\.system|socket\.|exec\(|eval\(|base64|__import__)")
_LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb")


@dataclass
class Dep:
    eco: str
    name: str
    spec: str
    kind: str  # runtime | dev | build | optional | indirect
    file: str
    line: Optional[int] = None


def _norm(name: str, eco: str) -> str:
    n = name.lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def _one_edit_apart(a: str, b: str) -> bool:
    """True when `a` and `b` differ by one insertion, deletion, substitution or adjacent transposition."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def typosquat_candidate(name: str, eco: str, popular: set[str]) -> Optional[str]:
    """Name of a popular package that `name` suspiciously resembles, or None."""
    n = _norm(name, eco)
    if len(n) < 5 or n in popular or n.startswith("@"):
        return None
    for p in sorted(popular):
        if abs(len(p) - len(n)) > 2:
            continue
        if n.replace("-", "") == p.replace("-", "") or _one_edit_apart(n, p):
            return p
        if difflib.SequenceMatcher(None, n, p).ratio() >= 0.88:
            return p
    return None


def parse_manifests(ctx: ScanContext) -> dict[str, Any]:
    return ctx.memo("manifests", lambda: _parse(ctx))


def _line(li: LineIndex, text: str, needle: str) -> Optional[int]:
    i = text.find(needle)
    return li.line_of(i) if i >= 0 else None


def _parse(ctx: ScanContext) -> dict[str, Any]:
    deps: list[Dep] = []
    names: dict[str, set[str]] = {"npm": set(), "pypi": set(), "cargo": set(), "go": set()}
    findings: list[Finding] = []
    notes: list[str] = []
    parsed: list[str] = []
    unparsed: list[str] = []

    def finding(rule: str, title: str, sev: str, conf: float, rf: Any, line: Optional[int], ev: str, detail: str = "") -> None:
        findings.append(Finding("dependencies", rule, title, sev, conf, rf.rel, line, sanitize(ev, 200), rf.context, detail))

    for rf in ctx.files:
        if rf.context not in ("production", "example") and not rf.name_lower.startswith("requirements"):
            continue
        low = rf.name_lower
        is_req = bool(re.fullmatch(r"requirements([-_.].*)?\.(?:txt|in)", low)) or (rf.rel.lower().startswith("requirements/") and rf.ext in ("txt", "in"))
        if low in UNPARSED_MANIFESTS:
            unparsed.append(rf.rel)
            continue
        if low not in ("package.json", "pyproject.toml", "setup.py", "go.mod", "cargo.toml") and not is_req:
            continue
        text = ctx.read(rf, cache=True)
        if text is None:
            continue
        parsed.append(rf.rel)
        li = LineIndex(text)
        try:
            if low == "package.json":
                _package_json(rf, text, li, deps, names, finding)
            elif low == "pyproject.toml":
                _pyproject(rf, text, li, deps, names)
            elif low == "setup.py":
                _setup_py(rf, text, li, deps, names, finding)
            elif low == "go.mod":
                _go_mod(rf, text, deps, names)
            elif low == "cargo.toml":
                _cargo(rf, text, li, deps, names, finding)
            else:
                _requirements(rf, text, deps, finding)
        except (ValueError, TypeError, AttributeError) as exc:
            notes.append(f"{rf.rel}: could not be parsed ({type(exc).__name__}); its dependencies are not analysed")
    return {"deps": deps, "names": names, "findings": findings, "notes": notes, "parsed": parsed, "unparsed": unparsed}


def _package_json(rf, text, li, deps, names, finding) -> None:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    if isinstance(data.get("name"), str):
        names["npm"].add(data["name"].lower())
    for section, kind in (("dependencies", "runtime"), ("optionalDependencies", "runtime"), ("devDependencies", "dev")):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            spec = str(spec)
            line = _line(li, text, f'"{name}"')
            deps.append(Dep("npm", name, spec, kind, rf.rel, line))
            s = spec.strip().lower()
            non_registry = s.startswith(("git+", "git:", "git@", "http:", "https:", "github:", "gitlab:", "bitbucket:", "file:", "link:")) \
                or re.fullmatch(r"[\w.-]+/[\w.-]+(#.*)?", s) is not None
            if non_registry:
                finding("dep.non-registry-source", "Dependency installed from a git/URL source instead of the registry",
                        "medium" if kind == "runtime" else "low", 0.5 if kind == "runtime" else 0.4, rf, line, f"{name}: {spec}",
                        "The content behind a git branch or URL can change without a version bump.")
            elif kind == "runtime" and s in ("*", "latest", ""):
                finding("dep.unpinned", "Dependency accepts any version", "low", 0.4, rf, line, f"{name}: {spec or '(empty)'}")
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in ("preinstall", "install", "postinstall"):
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            line = _line(li, text, f'"{hook}"')
            if _SUSPICIOUS_SCRIPT.search(cmd):
                finding("dep.install-script-suspicious", f"{hook} script downloads or evaluates code", "high", 0.6, rf, line, f"{hook}: {cmd}",
                        "Install scripts run automatically on every machine that installs this package.")
            else:
                finding("dep.install-script", f"Package declares a {hook} script", "low", 0.3, rf, line, f"{hook}: {cmd}",
                        "Install scripts run automatically when the package is installed.")


def _pep508_name(spec: str) -> Optional[str]:
    m = _REQ_NAME.match(spec.strip())
    return m.group(1) if m else None


def _pyproject(rf, text, li, deps, names) -> None:
    data = tomllib.loads(text)
    proj = data.get("project") or {}
    if isinstance(proj.get("name"), str):
        names["pypi"].add(_norm(proj["name"], "pypi"))
    for spec in proj.get("dependencies") or []:
        n = _pep508_name(str(spec))
        if n:
            deps.append(Dep("pypi", n, str(spec), "runtime", rf.rel, _line(li, text, str(spec)[:30])))
    for specs in (proj.get("optional-dependencies") or {}).values():
        for spec in specs or []:
            n = _pep508_name(str(spec))
            if n:
                deps.append(Dep("pypi", n, str(spec), "optional", rf.rel))
    for spec in (data.get("build-system") or {}).get("requires") or []:
        n = _pep508_name(str(spec))
        if n:
            deps.append(Dep("pypi", n, str(spec), "build", rf.rel))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    if isinstance(poetry.get("name"), str):
        names["pypi"].add(_norm(poetry["name"], "pypi"))
    for n, spec in (poetry.get("dependencies") or {}).items():
        if n.lower() != "python":
            deps.append(Dep("pypi", n, str(spec), "runtime", rf.rel, _line(li, text, n)))


def _setup_py(rf, text, li, deps, names, finding) -> None:
    m = re.search(r"\bname\s*=\s*['\"]([\w.-]+)['\"]", text)
    if m:
        names["pypi"].add(_norm(m.group(1), "pypi"))
    m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
    if m:
        for spec in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            n = _pep508_name(spec)
            if n:
                deps.append(Dep("pypi", n, spec, "runtime", rf.rel))
    risky = _SETUP_RISKY.search(text)
    if risky and rf.rel.count("/") <= 1:
        finding("dep.setup-py-risky", "setup.py contains network or code-execution calls", "medium", 0.4, rf, li.line_of(risky.start()),
                text[li.bounds(risky.start())[0]:li.bounds(risky.start())[1]],
                "setup.py runs on the installing machine when the package is built or installed from source.")


def _requirements(rf, text, deps, finding) -> None:
    total = unpinned = 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = re.split(r"\s+#", raw)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--extra-index-url") or line.startswith("--find-links") or line.startswith("-f "):
            finding("dep.custom-index", "Additional package source configured", "medium", 0.5, rf, i, line,
                    "Extra indexes open the door to dependency-confusion attacks: a same-named public package can win.")
            continue
        if line.startswith("--index-url") or line.startswith("-i "):
            finding("dep.custom-index", "Custom package index configured", "low", 0.4, rf, i, line)
            continue
        if line.startswith("--trusted-host"):
            finding("dep.trusted-host", "TLS verification disabled for a package host", "medium", 0.5, rf, i, line)
            continue
        if line.startswith("-e "):
            line = line[3:].strip()
        elif line.startswith("-"):
            continue
        if line.startswith(_VCS) or " @ " in line:
            finding("dep.non-registry-source", "Requirement installed from a VCS/URL source", "medium", 0.5, rf, i, line,
                    "The content behind a git branch or URL can change without a version bump.")
            continue
        m = _REQ_NAME.match(line)
        if not m:
            continue
        total += 1
        pinned = "==" in m.group(2)
        unpinned += 0 if pinned else 1
        deps.append(Dep("pypi", m.group(1), m.group(2), "runtime", rf.rel, i))
    if total >= 3 and unpinned / total > 0.5:
        finding("dep.unpinned-requirements", f"{unpinned} of {total} requirements are not pinned to an exact version", "low", 0.3, rf, None, rf.rel)


def _go_mod(rf, text, deps, names) -> None:
    m = re.search(r"^module\s+(\S+)", text, re.M)
    if m:
        names["go"].add(m.group(1).lower())
    in_block = False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        body = s[len("require "):] if s.startswith("require ") else (s if in_block else None)
        if body:
            parts = body.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                deps.append(Dep("go", parts[0], parts[1], "indirect" if "// indirect" in body else "runtime", rf.rel, i))


def _cargo(rf, text, li, deps, names, finding) -> None:
    data = tomllib.loads(text)
    pkg = data.get("package") or {}
    if isinstance(pkg.get("name"), str):
        names["cargo"].add(pkg["name"].lower())
    for table, kind in (("dependencies", "runtime"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        for name, spec in (data.get(table) or {}).items():
            line = _line(li, text, name)
            deps.append(Dep("cargo", name, json.dumps(spec) if isinstance(spec, dict) else str(spec), kind, rf.rel, line))
            if isinstance(spec, dict) and "git" in spec:
                finding("dep.non-registry-source", "Cargo dependency taken from a git repository", "medium" if kind == "runtime" else "low", 0.5,
                        rf, line, f"{name}: {spec.get('git')}")


# ---------------------------------------------------------------- known vulnerabilities

_SEV_WORDS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low", "info": "info"}


def _sev_from(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in _SEV_WORDS:
        return _SEV_WORDS[s]
    try:
        score = float(s)
    except ValueError:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else None


def parse_osv(data: dict[str, Any], root: Path) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple] = set()
    for res in data.get("results") or []:
        src = str((res.get("source") or {}).get("path", ""))
        try:
            rel = Path(src).resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            rel = sanitize(src, 120) or None
        context = classify_context(rel) if rel else "production"
        for pkg in res.get("packages") or []:
            p = pkg.get("package") or {}
            name, ver, eco = p.get("name", "?"), p.get("version", "?"), p.get("ecosystem", "")
            group_sev = {i: _sev_from(g.get("max_severity")) for g in pkg.get("groups") or [] for i in g.get("ids") or []}
            for v in pkg.get("vulnerabilities") or []:
                vid = str(v.get("id", "?"))
                key = (name, ver, vid, rel)
                if key in seen:
                    continue
                seen.add(key)
                sev = group_sev.get(vid) or _sev_from((v.get("database_specific") or {}).get("severity")) or "medium"
                summary = sanitize(str(v.get("summary") or v.get("details") or ""), 120)
                out.append(Finding("dependencies", "vuln.osv", f"{sanitize(str(name), 60)}@{sanitize(str(ver), 30)}: {sanitize(vid, 40)} {summary}".strip(),
                                   sev, 0.9, rel, None, sanitize(f"{eco} {name} {ver}", 120), context,
                                   "Known vulnerability for the exact version in the lockfile (OSV database)."))
    return out


def parse_npm_audit(data: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        if not isinstance(v, dict):
            continue
        titles = [x.get("title") for x in v.get("via") or [] if isinstance(x, dict) and x.get("title")]
        sev = _sev_from(v.get("severity")) or "medium"
        fix = v.get("fixAvailable")
        out.append(Finding("dependencies", "vuln.npm-audit", f"{sanitize(str(name), 60)}: {sanitize(str(titles[0]) if titles else 'known vulnerability', 120)}",
                           sev, 0.8, "package-lock.json", None, sanitize(f"range {v.get('range', '?')}", 100), "production",
                           f"Reported by npm audit. Fix available: {'yes' if fix else 'no'}."))
    return out


def _run(cmd: list[str], cwd: Path, timeout: int, env_extra: Optional[dict[str, str]] = None):
    import os
    env = {**os.environ, **(env_extra or {})}
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(cwd), env=env), None
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, f"{Path(cmd[0]).name} failed: {type(exc).__name__}"


def run_osv(ctx: ScanContext, exe: str) -> tuple[Optional[list[Finding]], Optional[str]]:
    last = "no output"
    for cmd in ([exe, "--format", "json", "-r", str(ctx.root)], [exe, "scan", "source", "--format", "json", "-r", str(ctx.root)]):
        proc, err = _run(cmd, ctx.root, ctx.options.external_timeout_s)
        if err:
            last = err
            continue
        try:
            data = json.loads(proc.stdout)
        except ValueError:
            data = None
        if isinstance(data, dict) and "results" in data:
            return parse_osv(data, ctx.root), None
        last = f"osv-scanner returned no usable JSON (exit {proc.returncode})"
        if proc.returncode == 128:
            return [], "osv-scanner found no lockfiles or manifests it supports"
    return None, last


def run_npm_audit(ctx: ScanContext, exe: str) -> tuple[Optional[list[Finding]], Optional[str]]:
    proc, err = _run([exe, "audit", "--package-lock-only", "--ignore-scripts", "--json"], ctx.root,
                     ctx.options.external_timeout_s, {"npm_config_ignore_scripts": "true"})
    if err:
        return None, err
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return None, "npm audit returned no usable JSON"
    if not isinstance(data, dict) or "error" in data:
        return None, "npm audit reported an error (network or registry problem)"
    return parse_npm_audit(data), None


def run(ctx: ScanContext) -> StepResult:
    res = StepResult("dependencies")
    info = parse_manifests(ctx)
    res.findings.extend(info["findings"])
    res.notes.extend(info["notes"])
    deps: list[Dep] = info["deps"]

    # Typosquatting against popular package names
    own = set().union(*info["names"].values()) if info["names"] else set()
    for d in deps:
        popular = ctx.rules.popular.get(d.eco)
        if not popular or d.kind in ("optional", "indirect") or _norm(d.name, d.eco) in own:
            continue
        match = typosquat_candidate(d.name, d.eco, popular)
        if match:
            res.findings.append(Finding(
                "dependencies", "dep.typosquat-suspect", f"Dependency name resembles popular package '{match}'", "medium", 0.4,
                d.file, d.line, sanitize(f"{d.name} {d.spec}", 120), classify_context(d.file),
                "Typosquatted packages imitate popular names. Verify the spelling and the publisher."))

    # Lockfile hygiene
    root_files = {f.rel for f in ctx.files if "/" not in f.rel}
    if "package.json" in root_files and any(d.eco == "npm" and d.kind == "runtime" for d in deps) and not (root_files & set(_LOCKFILES)):
        res.findings.append(Finding("dependencies", "dep.no-lockfile", "package.json has dependencies but no lockfile is committed", "low", 0.4,
                                    "package.json", None, "", "production", "Without a lockfile every install can resolve to different versions."))

    # Known vulnerabilities via external tools, when present
    scanner = None
    if not ctx.options.use_external:
        why = "external tools are disabled (--no-external)"
    else:
        why = "no vulnerability scanner found on PATH (looked for osv-scanner and npm)"
        osv = shutil.which("osv-scanner")
        if osv:
            found, err = run_osv(ctx, osv)
            if found is not None:
                res.findings.extend(found)
                scanner = "osv-scanner"
            else:
                why = err or why
                res.notes.append(f"osv-scanner could not complete: {err}")
        if scanner is None and "package-lock.json" in root_files and shutil.which("npm"):
            found, err = run_npm_audit(ctx, shutil.which("npm"))  # type: ignore[arg-type]
            if found is not None:
                res.findings.extend(found)
                scanner = "npm audit"
            else:
                res.notes.append(f"npm audit could not complete: {err}")
                why = err or why
    if scanner is None:
        res.status = "partial"
        res.not_checked.append(f"Known-vulnerability lookup was skipped: {why}. Dependencies were only checked for supply-chain red flags")
    else:
        res.notes.append(f"Known vulnerabilities were looked up with {scanner}")
    if info["unparsed"]:
        res.not_checked.append("Manifests not parsed by this version: " + ", ".join(info["unparsed"][:8]))
    res.not_checked.append("Package age, maintainer changes and abandonment are not checked (they need package-registry access)")
    res.not_checked.append("Transitive dependencies are only covered when the vulnerability scanner read a lockfile")

    counts: dict[str, int] = {}
    for d in deps:
        counts[d.eco] = counts.get(d.eco, 0) + 1
    res.data = {"dependency_counts": counts, "manifests": info["parsed"], "vulnerability_scanner": scanner}
    return res
