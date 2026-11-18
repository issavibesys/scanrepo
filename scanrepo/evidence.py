"""External evidence contract (input to step 2).

Tools write evidence records in one fixed JSON format into a directory outside the scanned repository.
scanrepo validates every record and decides what it may change. Producers are trusted only for what they
declare: scanrepo checks the format, the command allowlist, the commit and the file location, but it does
not verify that a producer really ran its command, and it never runs a producer itself.

Record (one JSON object per line in *.jsonl, or one object or array in *.json):

  {"schema": 1, "producer": "rea", "class": "B",
   "command": "analyze-javascript-application --json", "target_commit": "e7a1046",
   "type": "claim", "claim_category": "no_telemetry", "effect": "contradicts",
   "observation": "package.json declares posthog-node", "file": null, "line": null}

  {"schema": 1, "producer": "semgrep", "class": "B", "command": "semgrep scan --config p/xss",
   "target_commit": "e7a1046", "type": "finding", "rule": "xss-sink", "severity": "medium",
   "confidence": 0.7, "title": "Unsanitised HTML sink", "observation": "innerHTML from request param",
   "file": "src/view.js", "line": 42}
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .fsutil import classify_context
from .models import CONTRADICTION_CLASSES, EVIDENCE_CLASSES, SEVERITIES, Claim, Finding
from .steps.common import sanitize

SCHEMA = 1
MAX_RECORDS = 5000
MAX_FILE_BYTES = 5_000_000
MAX_NOTES = 20
CLAIM_EFFECTS = ("contradicts", "supports")
_RULE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
# Runtime or capture actions are refused in any command, even when the command is otherwise allowlisted.
DENY_TOKENS = frozenset({
    "run", "capture", "observe", "attach", "trace", "debug", "exec", "execute", "launch",
    "browser", "monitor", "proxy", "record", "dynamic",
})
SHELL_CHARS = set(";|&`$<>\n\r")

# Producers and what each may provide. Class B needs a command on the static allowlist.
PRODUCERS: dict[str, dict[str, Any]] = {
    "rea": {"static": [("analyze-javascript-application",), ("inspect_apk_signature",), ("inspect_wasm_artifact",)],
            "classes": ("B", "C", "D")},
    "semgrep": {"static": [("semgrep", "scan")], "classes": ("B", "C", "D")},
    "manual": {"static": [], "classes": ("C", "D")},   # a human reviewer: pattern-level notes or hypotheses
    "agent": {"static": [], "classes": ("D",)},        # an AI agent: hypotheses only, never decisive
}


@dataclass
class Ingest:
    accepted: int = 0
    rejected: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def _stronger(a: str, b: str) -> str:
    return a if EVIDENCE_CLASSES.index(a) <= EVIDENCE_CLASSES.index(b) else b


def _safe_rel(root: Path, rel: Any) -> Optional[str]:
    """A relative path inside the repository that exists as a regular file, or None."""
    if not isinstance(rel, str) or not rel or "\x00" in rel or rel.startswith(("/", "\\")):
        return None
    if re.match(r"^[A-Za-z]:", rel):
        return None
    parts = Path(rel.replace("\\", "/")).parts
    if ".." in parts:
        return None
    p = root / Path(*parts)
    try:
        if p.is_symlink() or not p.is_file():
            return None
        p.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return "/".join(parts)


def _command_problem(producer: str, command: str, cls: str) -> Optional[str]:
    if not command:
        return "class B evidence needs a static command" if cls == "B" else None
    if any(c in SHELL_CHARS for c in command):
        return "command contains shell metacharacters"
    tokens = command.split()
    if any(t.lstrip("-").lower() in DENY_TOKENS for t in tokens):
        return "command names a runtime or capture action; only static commands are accepted"
    allowed = PRODUCERS[producer]["static"]
    if not any(tuple(tokens[: len(a)]) == a for a in allowed):
        return f"command is not on the static allowlist for '{producer}'"
    return None


def _check(raw: Any, root: Path, commit: Optional[str], categories: set[str]) -> tuple[Optional[dict], str]:
    """Validate one record. Returns (normalised record, '') or (None, reason)."""
    if not isinstance(raw, dict):
        return None, "record is not a JSON object"
    if raw.get("schema") != SCHEMA:
        return None, f"schema must be {SCHEMA}"
    producer = raw.get("producer")
    if not isinstance(producer, str) or producer not in PRODUCERS:
        return None, f"unknown producer {sanitize(str(producer), 40)!r}"
    cls = raw.get("class")
    if cls not in EVIDENCE_CLASSES:
        return None, f"class must be one of {', '.join(EVIDENCE_CLASSES)}"
    if cls == "A":
        return None, "class A (runtime observation) is not accepted: no sandbox provenance exists in this version"
    if cls not in PRODUCERS[producer]["classes"]:
        return None, f"producer '{producer}' may not provide class {cls}"
    command = raw.get("command") or ""
    if not isinstance(command, str):
        return None, "command must be a string"
    command = command.strip()
    problem = _command_problem(producer, command, cls)
    if problem:
        return None, problem
    if cls == "B" and not commit:
        return None, "class B needs a git commit to bind the evidence to; this repository has none"
    if commit:
        target = raw.get("target_commit")
        if not isinstance(target, str) or len(target) < 7 or not commit.startswith(target):
            return None, "target_commit does not match the scanned commit (evidence is for a different version)"
    kind = raw.get("type")
    if kind not in ("claim", "finding"):
        return None, "type must be 'claim' or 'finding'"
    obs = raw.get("observation")
    if not isinstance(obs, str) or not obs.strip():
        return None, "observation is required"
    loc_file = raw.get("file")
    if loc_file is not None:
        loc_file = _safe_rel(root, loc_file)
        if loc_file is None:
            return None, "file must be a relative path to an existing file inside the repository"
    line = raw.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        return None, "line must be a positive integer"
    out: dict[str, Any] = {
        "producer": producer, "class": cls, "command": command, "type": kind,
        "observation": sanitize(obs, 300), "file": loc_file, "line": line,
    }
    if kind == "claim":
        cat = raw.get("claim_category")
        if cat not in categories:
            return None, f"unknown claim_category {sanitize(str(cat), 40)!r}"
        effect = raw.get("effect")
        if effect not in CLAIM_EFFECTS:
            return None, "effect must be 'contradicts' or 'supports'"
        out.update(claim_category=cat, effect=effect)
    else:
        rule = raw.get("rule", "finding")
        if not isinstance(rule, str) or not _RULE.match(rule):
            return None, "rule must be lowercase words with hyphens"
        sev = raw.get("severity", "low")
        if sev not in SEVERITIES:
            return None, "severity is invalid"
        conf = raw.get("confidence", 0.5)
        if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not 0 <= conf <= 1:
            return None, "confidence must be between 0 and 1"
        title = raw.get("title")
        if not isinstance(title, str) or not title.strip():
            return None, "title is required for findings"
        out.update(rule=rule, severity=sev, confidence=float(conf), title=sanitize(title, 120))
    return out, ""


def _apply(rec: dict[str, Any], claims: list[Claim], out: Ingest) -> Optional[str]:
    """Apply one valid record. Returns a rejection reason, or None when applied."""
    producer = rec["producer"]
    cls = rec["class"]
    tag = producer + (f" ({rec['command']})" if rec["command"] else "")
    loc = ""
    if rec["file"]:
        loc = f" [{rec['file']}" + (f":{rec['line']}]" if rec["line"] else "]")
    if rec["type"] == "claim":
        cat = rec["claim_category"]
        matches = [c for c in claims if c.category == cat
                   and (rec["file"] is None or c.file == rec["file"])
                   and (rec["line"] is None or c.line == rec["line"])]
        if not matches:
            return f"no claim of category '{cat}' matches this location in the repository"
        text = sanitize(f"{tag}: {rec['observation']}{loc}", 240)
        for c in matches:
            if rec["effect"] == "contradicts":
                if cls in CONTRADICTION_CLASSES:
                    c.status = "contradicted"
                    c.confidence = max(c.confidence, 0.8)
                    c.evidence.append(text)
                    c.evidence_class = _stronger(c.evidence_class, cls)
                    c.verified_by.append(producer)
                    out.findings.append(Finding(
                        "claims", f"ext.{producer}.claim-contradicted",
                        f"Claim contradicted by external evidence ({producer}): {cat}", "medium", 0.8,
                        c.file, c.line, sanitize(rec["observation"], 200), "production",
                        "Producer-declared evidence. Verify the cited observation in the repository.",
                        evidence_class=cls, verified_by=[tag]))
                else:
                    c.evidence.append(text + f" (class {cls}: cannot contradict a claim)")
            elif cls in CONTRADICTION_CLASSES:
                if c.status in ("unsupported", "no_contradiction_found"):
                    c.status = "supported"
                c.evidence.append(text)
                c.evidence_class = _stronger(c.evidence_class, cls)
                c.verified_by.append(producer)
            else:
                c.evidence.append(text + f" (class {cls}: not decisive)")
        return None
    # type == finding
    conf = rec["confidence"]
    sev = rec["severity"]
    if cls == "D":
        sev, conf = "info", min(conf, 0.3)   # hypotheses are never more than a lead
    elif cls == "B":
        conf = min(conf, 0.9)
    file = rec["file"]
    out.findings.append(Finding(
        "claims", f"ext.{producer}.{rec['rule']}", rec["title"], sev, conf, file, rec["line"],
        sanitize(rec["observation"], 200), classify_context(file) if file else "production",
        "Producer-declared evidence (class %s); the scanner did not run the producer." % cls,
        evidence_class=cls, verified_by=[tag]))
    return None


def load_records(ev_dir: Path) -> tuple[list[tuple[str, int, Any]], list[str]]:
    records: list[tuple[str, int, Any]] = []
    errors: list[str] = []
    files = sorted(p for p in ev_dir.iterdir() if p.suffix in (".json", ".jsonl") and p.is_file() and not p.is_symlink())
    if not files:
        errors.append("no .json or .jsonl evidence files found")
    for f in files:
        if f.stat().st_size > MAX_FILE_BYTES:
            errors.append(f"{f.name}: larger than {MAX_FILE_BYTES} bytes, skipped")
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if f.suffix == ".jsonl":
            for n, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    records.append((f.name, n, json.loads(line)))
                except ValueError:
                    errors.append(f"{f.name}:{n}: not valid JSON")
        else:
            try:
                data = json.loads(text)
            except ValueError:
                errors.append(f"{f.name}: not valid JSON")
                continue
            items = data if isinstance(data, list) else [data]
            records.extend((f.name, i, r) for i, r in enumerate(items, 1))
    return records, errors


def apply_evidence(root: Path, ev_dir_arg: str, claims: list[Claim], commit: Optional[str],
                   categories: set[str]) -> Ingest:
    out = Ingest()
    ev_dir = Path(ev_dir_arg).expanduser()
    if not ev_dir.is_dir():
        out.notes.append(f"evidence directory not found: {sanitize(ev_dir_arg, 120)}")
        return out
    try:
        ev_dir.resolve().relative_to(root.resolve())
        out.notes.append("evidence directory is inside the scanned repository and was ignored: "
                         "repository content must not supply its own evidence")
        return out
    except ValueError:
        pass

    records, errors = load_records(ev_dir)
    out.notes.extend(sanitize(e, 200) for e in errors)
    if len(records) > MAX_RECORDS:
        out.notes.append(f"only the first {MAX_RECORDS} of {len(records)} records were read")
        records = records[:MAX_RECORDS]

    by_class = {c: 0 for c in EVIDENCE_CLASSES}
    by_producer: dict[str, int] = {}
    for source, n, raw in records:
        rec, why = _check(raw, root, commit, categories)
        if rec is None:
            out.rejected.append(f"{source}:{n}: {why}")
            continue
        reason = _apply(rec, claims, out)
        if reason:
            out.rejected.append(f"{source}:{n}: {reason}")
            continue
        out.accepted += 1
        by_class[rec["class"]] += 1
        by_producer[rec["producer"]] = by_producer.get(rec["producer"], 0) + 1

    out.summary = {"accepted": out.accepted, "rejected": len(out.rejected), "by_class": by_class,
                   "by_producer": by_producer, "commit_checked": bool(commit)}
    counts = ", ".join(f"{k}: {v}" for k, v in by_class.items() if v) or "none"
    out.notes.append(f"external evidence: {out.accepted} accepted ({counts}), {len(out.rejected)} rejected")
    out.notes.extend(f"rejected {sanitize(r, 240)}" for r in out.rejected[:MAX_NOTES])
    if len(out.rejected) > MAX_NOTES:
        out.notes.append(f"{len(out.rejected) - MAX_NOTES} more rejections not listed")
    if out.accepted:
        out.not_checked.append(
            "External evidence is producer-declared: the scanner checked format, command allowlist, commit and "
            "location, but did not verify that the producer really ran the command")
    if not commit:
        out.notes.append("no git commit known: target_commit could not be checked against the scanned version")
    return out
