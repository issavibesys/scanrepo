"""Runs the six steps in a fixed order and assembles the report (step 6)."""

from __future__ import annotations

import math
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from . import __version__
from .context import ScanContext, ScanOptions
from .fsutil import TargetError, resolve_target
from .models import SEV_RANK, Report, StepResult
from .rules import load_rules
from .steps import behavior, claims, deps, inventory, static

# The order is fixed: exactly these six steps, step 6 being the report assembled below.
STEPS: list[tuple[str, str, Callable[[ScanContext], StepResult]]] = [
    ("inventory", "1. Inventory", inventory.run),
    ("claims", "2. Claim verification", claims.run),
    ("dependencies", "3. Dependencies", deps.run),
    ("static_analysis", "4. Static analysis", static.run),
    ("behavior", "5. Behaviour check (static)", behavior.run),
]
STEP_NAMES = [s[0] for s in STEPS] + ["report"]


# Findings from structured data are class B. Everything else keeps the default class C (pattern match).
_STRUCTURED = (
    ("vuln.", "vulnerability-db"), ("inv.binary-committed", "magic-bytes"), ("inv.license-mismatch", "license-file"),
    ("inv.repo-owner-mismatch", "git-metadata"), ("inv.young-repository", "git-metadata"),
    ("dep.install-script", "manifest-parser"), ("dep.non-registry-source", "manifest-parser"),
    ("dep.no-lockfile", "manifest-parser"), ("dep.unpinned", "manifest-parser"),
)


def _assign_classes(res: StepResult) -> None:
    for f in res.findings:
        if f.rule_id.startswith("claim."):
            continue  # claim findings are classed by the claim verdict
        for prefix, checker in _STRUCTURED:
            if f.rule_id.startswith(prefix):
                f.evidence_class, f.verified_by = "B", [checker]
                break


def risk_from(findings: list) -> tuple[int, str]:
    """0-100 score with diminishing returns, so one critical finding outweighs many weak ones."""
    per_rule: dict[str, list[float]] = {}
    for f in findings:
        per_rule.setdefault(f.rule_id, []).append(f.score())
    # the first 3 hits of a rule count fully, further hits count a quarter: many hits of one pattern is one signal
    # and no single rule can contribute more than 8 points, however many times it fires
    total = sum(min(sum(sorted(v, reverse=True)[:3]) + 0.25 * sum(sorted(v, reverse=True)[3:]), 8.0) for v in per_rule.values())
    score = round(100 * (1 - math.exp(-total / 25)))
    top = max((SEV_RANK[f.severity] for f in findings if f.context == "production" and f.confidence >= 0.5), default=-1)
    level = "low" if score < 15 else "medium" if score < 40 else "high" if score < 70 else "critical"
    if top >= SEV_RANK["critical"] and level in ("low", "medium"):
        level = "high"
    return score, level


def scan(target: str, options: Optional[ScanOptions] = None,
         progress: Optional[Callable[[str], None]] = None) -> Report:
    options = options or ScanOptions()
    unknown = set(options.skip) - set(STEP_NAMES)
    if unknown:
        raise ValueError(f"unknown step(s) to skip: {', '.join(sorted(unknown))}. Valid: {', '.join(STEP_NAMES[:-1])}")
    rules = load_rules(options.rules_file)
    root, origin, cleanup = resolve_target(target, options.depth)
    try:
        ctx = ScanContext(root, target, options, rules, origin)
        results: list[StepResult] = []
        for name, title, fn in STEPS:
            if name in options.skip:
                results.append(StepResult(name, title, "skipped", notes=["Skipped by request"]))
                continue
            if progress:
                progress(title)
            started = time.monotonic()
            try:
                res = fn(ctx)
            except Exception as exc:  # one failing step must not hide the others
                res = StepResult(name, status="error", notes=[f"Step crashed: {type(exc).__name__}: {exc}"],
                                 not_checked=[f"Step '{name}' did not complete, so its checks are missing from this report"])
            res.title = title
            _assign_classes(res)
            res.duration_s = time.monotonic() - started
            results.append(res)

        findings = [f for r in results for f in r.findings]
        findings.sort(key=lambda f: (-SEV_RANK[f.severity], -f.score(), f.file or "", f.line or 0))
        claim_list = [c for r in results for c in r.claims]
        not_checked: list[str] = []
        for r in results:
            if r.status in ("skipped", "error"):
                not_checked.append(f"Step '{r.name}' was {r.status}: " + "; ".join(r.notes))
            not_checked.extend(r.not_checked)
        if rules.errors:
            not_checked.extend(f"Rule problem: {e}" for e in rules.errors)
        seen: set[str] = set()
        not_checked = [n for n in not_checked if not (n in seen or seen.add(n))]

        score, level = risk_from(findings)
        git = next((r.data.get("git", {}) for r in results if r.name == "inventory"), {})
        inv_data = next((r.data for r in results if r.name == "inventory"), {})
        by_sev = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low", "info")}
        return Report(
            tool_version=__version__, target=target, commit=(git or {}).get("commit"),
            scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            steps=results, findings=findings, claims=claim_list, not_checked=not_checked,
            risk_score=score, risk_level=level,
            stats={"files_scanned": len(ctx.files), "languages": inv_data.get("languages", {}), "findings_by_severity": by_sev,
                   "claims_by_status": {s: sum(1 for c in claim_list if c.status == s)
                                        for s in ("supported", "no_contradiction_found", "unsupported", "contradicted")},
                   "findings_by_class": {c: sum(1 for f in findings if f.evidence_class == c) for c in ("A", "B", "C", "D")}},
        )
    finally:
        cleanup()


__all__ = ["scan", "STEPS", "STEP_NAMES", "ScanOptions", "TargetError", "risk_from"]
