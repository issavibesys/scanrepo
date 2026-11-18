"""Step 4: static analysis. Regex rules for hardcoded secrets and risky code patterns."""

from __future__ import annotations

from collections import Counter

from ..context import ScanContext
from ..models import StepResult
from .common import looks_minified, scan_text, suppressed_notes


def run(ctx: ScanContext) -> StepResult:
    res = StepResult("static_analysis")
    secrets = ctx.rules.groups["secrets"]
    code = ctx.rules.groups["code"]
    counters: Counter = Counter()
    scanned = minified = 0
    for rf in ctx.files:
        if rf.is_lock:
            continue
        if ctx.expired():
            res.status = "partial"
            res.not_checked.append("Time limit reached: the remaining files were not scanned for secrets/code patterns")
            break
        text = ctx.read(rf)
        if text is None:
            continue
        scanned += 1
        scan_text("static_analysis", secrets, rf, text, res.findings, counters, secrets=True)
        if looks_minified(text):
            minified += 1
        else:
            scan_text("static_analysis", code, rf, text, res.findings, counters)
    if minified:
        res.not_checked.append(f"{minified} minified/bundled file(s) were only scanned for secrets, not for code patterns")
    res.not_checked.append(
        "Pattern rules are heuristics, not data-flow analysis: a hit shows where to look, not that the code is exploitable"
    )
    res.not_checked.append("Git history was not scanned, so secrets deleted in later commits are not detected")
    res.notes.extend(suppressed_notes(counters))
    res.data = {"files_scanned": scanned, "rules": len(secrets) + len(code)}
    return res
