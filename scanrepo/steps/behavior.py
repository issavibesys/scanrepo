"""Step 5: behaviour check, done statically. The code is never executed.

Looks for outbound endpoints, telemetry, defaults that weaken security, hidden features and obfuscation.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from ..context import ScanContext
from ..models import Finding, StepResult
from .common import LineIndex, sanitize, scan_text, suppressed_notes

_URL = re.compile(r"https?://[^\s\"'<>\\)\]}`]{4,200}")
_HOST_OK = re.compile(r"[a-z0-9.-]+")
_PRIVATE = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.)")


def _matches(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def scan_behavior(ctx: ScanContext) -> dict[str, Any]:
    return ctx.memo("behavior", lambda: _scan(ctx))


def _scan(ctx: ScanContext) -> dict[str, Any]:
    rules = ctx.rules.groups["behavior"]
    ignore = ctx.rules.lists["ignore_domains"]
    ignore_sub = ctx.rules.lists["ignore_url_substrings"]
    tele = ctx.rules.lists["telemetry_domains"]
    prefixes = set(ctx.rules.lists["telemetry_prefixes"])
    findings: list[Finding] = []
    counters: Counter = Counter()
    domains: dict[str, dict[str, Any]] = {}
    tele_seen: dict[str, Finding] = {}
    partial = False
    for rf in ctx.files:
        if rf.is_lock:
            continue
        if ctx.expired():
            partial = True
            break
        text = ctx.read(rf)
        if text is None:
            continue
        scan_text("behavior", rules, rf, text, findings, counters)
        if rf.context not in ("production", "example"):
            continue
        li = LineIndex(text)
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;:!?")
            if any(s in url for s in ignore_sub):
                continue
            try:
                host = (urlsplit(url).hostname or "").lower()
            except ValueError:
                continue
            if "." not in host or not _HOST_OK.fullmatch(host) or _PRIVATE.match(host) or _matches(host, ignore):
                continue
            entry = domains.setdefault(host, {"count": 0, "file": rf.rel, "line": li.line_of(m.start()), "context": rf.context})
            entry["count"] += 1
            is_tele = _matches(host, tele) or host.split(".")[0] in prefixes
            if is_tele and host not in tele_seen:
                known = _matches(host, tele)
                tele_seen[host] = Finding(
                    step="behavior", rule_id="beh.telemetry-endpoint",
                    title=f"Telemetry/analytics endpoint: {sanitize(host, 80)}",
                    severity="low", confidence=0.6 if known else 0.4, file=rf.rel, line=li.line_of(m.start()),
                    evidence=sanitize(url, 160), context=rf.context,
                    detail="The code references this host. Static analysis cannot show what is sent or whether it is opt-in.",
                )
    findings.extend(tele_seen.values())
    return {"findings": findings, "domains": domains, "notes": suppressed_notes(counters), "partial": partial}


def run(ctx: ScanContext) -> StepResult:
    res = StepResult("behavior")
    info = scan_behavior(ctx)
    res.findings = list(info["findings"])
    res.notes = list(info["notes"])
    top = sorted(info["domains"].items(), key=lambda kv: -kv[1]["count"])[:50]
    res.data = {
        "external_hosts": [{"host": h, **v} for h, v in top],
        "external_host_count": len(info["domains"]),
    }
    if info["partial"]:
        res.status = "partial"
        res.not_checked.append("Time limit reached: not every file was checked for behaviour patterns")
    res.not_checked.append("Nothing was executed, so runtime behaviour and the contents of network traffic are unknown")
    res.not_checked.append("Whether a flagged endpoint is actually contacted, and what it receives, cannot be proven statically")
    return res
