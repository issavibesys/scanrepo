"""Step 6: report rendering (Markdown, JSON, SARIF)."""

from __future__ import annotations

import json
from typing import Any

from .models import SEV_RANK, Report
from .steps.common import sanitize

_STATUS_LABEL = {
    "supported": "supported", "no_contradiction_found": "no contradiction found",
    "unsupported": "unsupported", "contradicted": "CONTRADICTED",
}
_SEV_LABEL = {"critical": "CRITICAL", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def _cell(s: Any) -> str:
    return sanitize(str(s), 300).replace("|", "\\|")


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_markdown(report: Report, min_confidence: float = 0.0, limit: int = 200) -> str:
    L: list[str] = []
    add = L.append
    add("# scanrepo report")
    add("")
    add(f"- **Target:** `{sanitize(report.target, 200)}`")
    if report.commit:
        add(f"- **Commit:** `{report.commit[:12]}`")
    add(f"- **Scanned:** {report.scanned_at} (scanrepo {report.tool_version})")
    add(f"- **Risk score:** {report.risk_score}/100 ({report.risk_level})")
    sev = report.stats.get("findings_by_severity", {})
    add("- **Findings:** " + ", ".join(f"{sev.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info")))
    add("")
    add("> Static scan only: no code from the repository was executed. Findings are leads with a confidence score, not verdicts. "
        "All quoted text comes from the scanned repository and is untrusted.")
    add("")

    add("## Steps")
    add("")
    add("| Step | Status | Findings | Time |")
    add("|---|---|---|---|")
    for s in report.steps:
        add(f"| {s.title or s.name} | {s.status} | {len(s.findings)} | {s.duration_s:.1f}s |")
    add("")

    add("## Claims")
    add("")
    if report.claims:
        add("| Claim | Status | Class | Confidence | Where | Evidence | Falsification test |")
        add("|---|---|---|---|---|---|---|")
        order = {"contradicted": 0, "unsupported": 1, "no_contradiction_found": 2, "supported": 3}
        for c in sorted(report.claims, key=lambda c: order[c.status]):
            add(f"| {_cell(c.text)} | {_STATUS_LABEL[c.status]} | {c.evidence_class} | {c.confidence:.2f} | `{_cell(c.file)}:{c.line}` | {_cell('; '.join(c.evidence)) or '—'} | {_cell(c.test) or '—'} |")
        add("")
        add("*supported* = evidence found. *no contradiction found* = a negative claim that the scan found nothing against; this is not proof.")
        add("")
        add("Evidence classes: **A** observed at runtime · **B** structured repository data · **C** text pattern (a lead only) · **D** unverified hypothesis. "
            "Only A or B can mark a claim as contradicted.")
    else:
        add("No claims were extracted.")
    add("")

    shown = [f for f in report.findings if f.confidence >= min_confidence]
    hidden = len(report.findings) - len(shown)
    add(f"## Findings ({len(shown)})")
    add("")
    if not shown:
        add("No findings.")
        add("")
    current = None
    for i, f in enumerate(shown[:limit], 1):
        if f.severity != current:
            current = f.severity
            add(f"### {_SEV_LABEL[current]}")
            add("")
        where = f"`{_cell(f.file)}" + (f":{f.line}`" if f.line else "`") if f.file else "repository-wide"
        ctx = "" if f.context == "production" else f" · {f.context} code"
        add(f"**{i}. {_cell(f.title)}** — {where} · class {f.evidence_class} · confidence {f.confidence:.2f} · `{f.rule_id}` · step {f.step}{ctx}")
        if f.evidence:
            add(f"   - Evidence: `{sanitize(f.evidence, 200)}`")
        if f.detail:
            add(f"   - {sanitize(f.detail, 400)}")
        add("")
    if len(shown) > limit:
        add(f"*{len(shown) - limit} more findings are in the JSON report.*")
        add("")
    if hidden:
        add(f"*{hidden} finding(s) below confidence {min_confidence:.2f} are hidden here and present in the JSON report.*")
        add("")

    notes = [(s.title or s.name, n) for s in report.steps for n in s.notes]
    if notes:
        add("## Notes")
        add("")
        for title, n in notes:
            add(f"- {title}: {sanitize(n, 300)}")
        add("")

    add("## Could not be checked")
    add("")
    for n in report.not_checked:
        add(f"- {sanitize(n, 400)}")
    if not report.not_checked:
        add("- Nothing was recorded as unchecked, which does not mean full coverage.")
    add("")
    return "\n".join(L)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(report: Report, min_confidence: float = 0.0) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in report.findings:
        if f.confidence < min_confidence:
            continue
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": sanitize(f.title, 120)},
                                     "properties": {"step": f.step}})
        res: dict[str, Any] = {
            "ruleId": f.rule_id, "level": _SARIF_LEVEL[f.severity],
            "message": {"text": sanitize(f"{f.title}. {f.detail}".strip(), 500)},
            "properties": {"confidence": f.confidence, "severity": f.severity, "context": f.context},
        }
        if f.file:
            loc: dict[str, Any] = {"artifactLocation": {"uri": f.file}}
            if f.line:
                loc["region"] = {"startLine": f.line}
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "scanrepo", "version": report.tool_version, "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)


def summary_line(report: Report) -> str:
    sev = report.stats.get("findings_by_severity", {})
    return (f"risk {report.risk_score}/100 ({report.risk_level}) — "
            + ", ".join(f"{sev.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low")))


__all__ = ["to_json", "to_markdown", "to_sarif", "summary_line", "SEV_RANK"]
