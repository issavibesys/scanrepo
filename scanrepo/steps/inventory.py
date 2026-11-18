"""Step 1: inventory. File structure, languages, manifests, license, CI, git history, provenance."""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from ..context import ScanContext
from ..fsutil import CODE_EXTS, sniff_binary
from ..models import Finding, StepResult
from .common import LineIndex, sanitize

LANG_BY_EXT = {
    "py": "Python", "js": "JavaScript", "mjs": "JavaScript", "cjs": "JavaScript", "jsx": "JavaScript",
    "ts": "TypeScript", "tsx": "TypeScript", "go": "Go", "rs": "Rust", "java": "Java", "kt": "Kotlin",
    "rb": "Ruby", "php": "PHP", "c": "C", "h": "C", "cc": "C++", "cpp": "C++", "hpp": "C++", "cs": "C#",
    "swift": "Swift", "sh": "Shell", "bash": "Shell", "zsh": "Shell", "ps1": "PowerShell", "lua": "Lua",
    "scala": "Scala", "dart": "Dart", "ex": "Elixir", "exs": "Elixir", "pl": "Perl",
}
MANIFEST_NAMES = {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "go.mod", "cargo.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "composer.json",
}
CI_PATTERNS = (
    re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"), re.compile(r"^\.gitlab-ci\.yml$"),
    re.compile(r"^\.circleci/config\.yml$"), re.compile(r"^azure-pipelines\.yml$"),
    re.compile(r"^jenkinsfile$"), re.compile(r"^\.travis\.yml$"), re.compile(r"^bitbucket-pipelines\.yml$"),
)
_REPO_URL = re.compile(r"(?:github\.com|gitlab\.com|bitbucket\.org)[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?\s\"']|$)", re.I)
_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([\w.-]+/[\w./-]+)@([^\s'\"#]+)", re.M)
_INJECTION = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label))"
    r"|comment\.body|review\.body|head_commit\.message)\s*\}\}"
)


def license_family(text: str) -> Optional[str]:
    t = text.lower()
    if "permission is hereby granted, free of charge" in t or re.search(r"\bmit license\b", t):
        return "MIT"
    if "apache license" in t and "version 2.0" in t:
        return "Apache"
    if "gnu lesser general public license" in t:
        return "LGPL"
    if "gnu affero general public license" in t:
        return "AGPL"
    if "gnu general public license" in t:
        return "GPL"
    if "redistribution and use in source and binary forms" in t:
        return "BSD"
    if "mozilla public license" in t:
        return "MPL"
    if "permission to use, copy, modify, and/or distribute this software" in t or re.search(r"\bisc license\b", t):
        return "ISC"
    if "free and unencumbered software" in t:
        return "Unlicense"
    return None


def normalize_family(s: str) -> Optional[str]:
    t = s.lower()
    for fam, pat in (("LGPL", r"\blgpl"), ("AGPL", r"\bagpl"), ("GPL", r"\bgpl"), ("MIT", r"\bmit\b"),
                     ("Apache", r"\bapache"), ("BSD", r"\bbsd"), ("MPL", r"\bmpl"), ("ISC", r"\bisc\b"),
                     ("Unlicense", r"\bunlicense"), ("CC0", r"\bcc0")):
        if re.search(pat, t):
            return fam
    return None


def _repo_slug(text: str) -> Optional[str]:
    m = _REPO_URL.search(text + " ")
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def _manifest_license_and_repos(ctx: ScanContext, manifests: list[str]) -> tuple[Optional[str], list[str]]:
    lic: Optional[str] = None
    repos: list[str] = []
    for rf in ctx.files:
        if rf.rel not in manifests or rf.rel.count("/") > 0:
            continue
        text = ctx.read(rf, cache=True) or ""
        try:
            if rf.name_lower == "package.json":
                data = json.loads(text)
                v = data.get("license")
                if isinstance(v, dict):
                    v = v.get("type")
                lic = lic or (v if isinstance(v, str) else None)
                repo = data.get("repository")
                url = repo if isinstance(repo, str) else (repo or {}).get("url", "") if isinstance(repo, dict) else ""
                slug = _repo_slug(url or "")
                if slug:
                    repos.append(slug)
            elif rf.name_lower == "pyproject.toml":
                proj = tomllib.loads(text).get("project", {})
                v = proj.get("license")
                if isinstance(v, dict):
                    v = v.get("text")
                lic = lic or (v if isinstance(v, str) else None)
                for url in (proj.get("urls") or {}).values():
                    slug = _repo_slug(str(url))
                    if slug:
                        repos.append(slug)
        except (ValueError, AttributeError, TypeError):
            continue
    return lic, repos


def collect(ctx: ScanContext) -> dict[str, Any]:
    return ctx.memo("inventory", lambda: _collect(ctx))


def _collect(ctx: ScanContext) -> dict[str, Any]:
    langs: Counter = Counter()
    lang_bytes: Counter = Counter()
    manifests: list[str] = []
    readmes: list[str] = []
    ci_files: list[str] = []
    license_file: Optional[str] = None
    for rf in ctx.files:
        if rf.ext in LANG_BY_EXT and rf.context != "docs":
            langs[LANG_BY_EXT[rf.ext]] += 1
            lang_bytes[LANG_BY_EXT[rf.ext]] += rf.size
        if rf.name_lower in MANIFEST_NAMES or re.fullmatch(r"requirements([-_.].*)?\.(?:txt|in)", rf.name_lower):
            manifests.append(rf.rel)
        if rf.name_lower.startswith("readme") and rf.rel.count("/") <= 1:
            readmes.append(rf.rel)
        if rf.rel.count("/") == 0 and (rf.name_lower.startswith("licen") or rf.name_lower.startswith("copying")):
            license_file = license_file or rf.rel
        if any(p.match(rf.rel.lower()) for p in CI_PATTERNS):
            ci_files.append(rf.rel)
    lic_text = None
    detected = None
    if license_file:
        lic_rf = next(f for f in ctx.files if f.rel == license_file)
        lic_text = ctx.read(lic_rf, cache=True) or ""
        detected = license_family(lic_text)
    declared, manifest_repos = _manifest_license_and_repos(ctx, manifests)

    git: dict[str, Any] = {"available": False}
    head = ctx.git("rev-parse", "HEAD")
    if head:
        git["available"] = True
        git["commit"] = head.strip()
        git["shallow"] = (ctx.git("rev-parse", "--is-shallow-repository") or "").strip() == "true"
        log = ctx.git("log", "--format=%an%x1f%ae%x1f%aI", "-n", "5000") or ""
        rows = [r.split("\x1f") for r in log.splitlines() if r.count("\x1f") == 2]
        git["commits_seen"] = len(rows)
        git["authors"] = len({(r[0].lower(), r[1].lower()) for r in rows})
        if rows:
            git["last_commit"] = rows[0][2]
            git["first_commit_seen"] = rows[-1][2]
        remote = (ctx.git("remote", "get-url", "origin") or "").strip()
        git["origin"] = ctx.origin_url or remote or None
    return {
        "languages": dict(langs.most_common()), "language_bytes": dict(lang_bytes.most_common()),
        "manifests": manifests, "readmes": readmes, "ci_files": ci_files,
        "license_file": license_file, "license_detected": detected, "license_declared": declared,
        "manifest_repos": manifest_repos, "git": git,
    }


def _ci_findings(ctx: ScanContext, inv: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for rel in inv["ci_files"]:
        rf = next(f for f in ctx.files if f.rel == rel)
        text = ctx.read(rf) or ""
        li = LineIndex(text)

        def add(rule: str, title: str, sev: str, conf: float, pos: int, detail: str = "") -> None:
            ls, le = li.bounds(pos)
            out.append(Finding("inventory", rule, title, sev, conf, rel, li.line_of(pos),
                               sanitize(text[ls:le], 200), "production", detail))

        m = re.search(r"\bpull_request_target\b", text)
        if m:
            head_checkout = "actions/checkout" in text and re.search(
                r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref", text)
            if head_checkout:
                add("ci.pr-target-checkout-head", "Workflow runs untrusted PR code with pull_request_target", "high", 0.65, m.start(),
                    "pull_request_target runs with repository secrets and write access. Checking out the PR head there lets "
                    "a pull request run its own code with those privileges.")
            else:
                add("ci.pull-request-target", "Workflow uses pull_request_target", "medium", 0.4, m.start(),
                    "Runs with secrets in the context of the base repository. Safe only if it never executes PR code.")
        m = re.search(r"^\s*permissions:\s*write-all\b", text, re.M)
        if m:
            add("ci.permissions-write-all", "Workflow grants write-all permissions", "medium", 0.5, m.start())
        m = _INJECTION.search(text)
        if m:
            add("ci.script-injection", "Untrusted event field interpolated into a workflow", "high", 0.55, m.start(),
                "Issue/PR titles, bodies and branch names are attacker-controlled. Inside a run: step they allow command injection.")
        branch_refs, tag_refs, first = 0, 0, None
        for um in _USES.finditer(text):
            name, ref = um.group(1), um.group(2)
            if name.startswith(("actions/", "github/", "./")) or re.fullmatch(r"[0-9a-f]{40}", ref):
                continue
            first = first if first is not None else um.start()
            if ref in ("main", "master", "develop", "HEAD", "latest"):
                branch_refs += 1
            else:
                tag_refs += 1
        if branch_refs:
            add("ci.unpinned-action-branch", f"{branch_refs} third-party action(s) pinned to a branch", "medium", 0.5, first or 0,
                "A branch can change at any time. Pin to a full commit SHA.")
        elif tag_refs:
            add("ci.unpinned-action-tag", f"{tag_refs} third-party action(s) pinned to a mutable tag", "low", 0.4, first or 0,
                "Tags can be moved. Pin to a full commit SHA for supply-chain safety.")
    return out


def run(ctx: ScanContext) -> StepResult:
    res = StepResult("inventory")
    inv = collect(ctx)
    walk = ctx.walk
    findings = res.findings

    # Committed binaries and sensitive file names
    binaries = 0
    for rf in ctx.files:
        if rf.size == 0:
            continue
        label = sniff_binary(rf.path, rf.ext)
        if label and rf.context == "production":
            binaries += 1
            if binaries <= 20:
                exe = label.startswith(("ELF", "Mach-O", "Windows PE"))
                findings.append(Finding("inventory", "inv.binary-committed", f"Binary committed: {label}", "medium" if exe else "low",
                                        0.5 if exe else 0.3, rf.rel, None, sanitize(rf.rel), rf.context,
                                        "Prebuilt binaries cannot be reviewed as source. Check where it came from."))
        for rule in ctx.rules.groups["sensitive_files"]:
            if rule["_re"].search(rf.rel):
                findings.append(Finding("inventory", rule["id"], rule["title"], rule["severity"], rule["confidence"],
                                        rf.rel, None, sanitize(rf.rel), rf.context))
    if binaries > 20:
        res.notes.append(f"{binaries - 20} further committed binaries not listed individually")

    findings.extend(_ci_findings(ctx, inv))

    # License consistency
    fam, declared = inv["license_detected"], inv["license_declared"]
    if declared and inv["license_file"] and fam and normalize_family(declared) not in (None, fam):
        findings.append(Finding("inventory", "inv.license-mismatch", f"Manifest declares {sanitize(declared, 40)} but the license file reads as {fam}",
                                "medium", 0.5, inv["license_file"], None, sanitize(declared), "production"))
    elif declared and not inv["license_file"]:
        findings.append(Finding("inventory", "inv.license-file-missing", "License declared in manifest but no license file in the repository",
                                "low", 0.4, None, None, sanitize(declared), "production"))
    elif not declared and not inv["license_file"]:
        findings.append(Finding("inventory", "inv.no-license", "No license file or license declaration found", "info", 0.5,
                                None, None, "", "production", "Without a license, default copyright applies and the code is not open source."))

    # Provenance: does the git remote match what the manifests say?
    git = inv["git"]
    origin_slug = _repo_slug(git.get("origin") or "")
    if origin_slug and inv["manifest_repos"] and origin_slug not in inv["manifest_repos"]:
        findings.append(Finding("inventory", "inv.repo-owner-mismatch", "Manifest points to a different repository than the git remote",
                                "medium", 0.5, None, None, f"remote={sanitize(origin_slug, 80)} manifest={sanitize(', '.join(inv['manifest_repos']), 100)}",
                                "production", "Normal for forks and mirrors. For a copy of a trending project it is the classic fake-copy pattern; "
                                "check the publisher on the package registry."))
    if git.get("available"):
        if git.get("shallow"):
            res.notes.append("The git history is truncated (shallow clone): commit counts and the first-commit date are lower bounds")
        elif git.get("first_commit_seen"):
            try:
                first = datetime.fromisoformat(git["first_commit_seen"])
                days = (datetime.now(timezone.utc) - first.astimezone(timezone.utc)).days
                git["age_days"] = days
                if days < 30:
                    findings.append(Finding("inventory", "inv.young-repository", f"Very young repository: first commit {max(days, 0)} day(s) ago",
                                            "info", 0.3, None, None, "", "production", "A new repository has no track record. Weigh its claims accordingly."))
            except ValueError:
                pass
    else:
        res.notes.append("No git metadata available: history, authorship and remote checks were skipped")

    # Coverage gaps
    if walk.skipped_dirs:
        res.not_checked.append("Vendored/dependency directories were not scanned: " + ", ".join(sorted(set(walk.skipped_dirs))[:10])
                               + (" …" if len(set(walk.skipped_dirs)) > 10 else ""))
    if walk.skipped_large:
        res.not_checked.append(f"{len(walk.skipped_large)} file(s) over {ctx.options.max_file_kb} KB were skipped")
    if walk.skipped_symlinks:
        res.not_checked.append(f"{walk.skipped_symlinks} symlink(s) were not followed")
    if walk.truncated:
        res.status = "partial"
        res.not_checked.append(f"Stopped after {ctx.options.max_files} files; the repository is larger")

    code_files = sum(1 for f in ctx.files if f.ext in CODE_EXTS)
    res.data = {
        "files": len(ctx.files), "code_files": code_files, "languages": inv["languages"],
        "manifests": inv["manifests"], "readmes": inv["readmes"], "ci_files": inv["ci_files"],
        "license_file": inv["license_file"], "license_detected": inv["license_detected"],
        "license_declared": inv["license_declared"], "git": git,
    }
    return res
