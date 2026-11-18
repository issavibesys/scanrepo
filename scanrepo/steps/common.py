"""Helpers shared by the scanning steps: rule application, evidence snippets, masking."""

from __future__ import annotations

import bisect
import math
import re
from collections import Counter
from typing import Any, Optional

from ..fsutil import RepoFile
from ..models import Finding

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize(s: str, limit: int = 240) -> str:
    """One line, no control characters, no backticks. Used for every snippet from the repository."""
    s = _CTRL.sub(" ", s.replace("\t", " "))
    s = re.sub(r"\s+", " ", s).strip().replace("`", "'")
    return s if len(s) <= limit else s[: limit - 1] + "…"


PLACEHOLDER_WORDS = (
    "example", "your", "xxxx", "changeme", "placeholder", "dummy", "sample", "redacted", "fake",
    "12345678", "abcdefgh", "test1234", "insert", "replace", "todo", "<", "${", "{{", "process.env",
    "os.environ", "getenv",
)


def is_placeholder(value: str) -> bool:
    low = value.lower()
    if any(w in low for w in PLACEHOLDER_WORDS):
        return True
    return bool(re.fullmatch(r"(.)\1{7,}", value) or re.fullmatch(r"[x*#.\-]+", low))


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def mask_value(v: str) -> str:
    return v[:4] + "…" + v[-2:] if len(v) > 10 else "***"


class LineIndex:
    def __init__(self, text: str) -> None:
        self.text = text
        self._starts: Optional[list[int]] = None

    def _build(self) -> list[int]:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer("\n", self.text)]
        return self._starts

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self._build(), pos)

    def bounds(self, pos: int) -> tuple[int, int]:
        starts = self._build()
        start = starts[bisect.bisect_right(starts, pos) - 1]
        end = self.text.find("\n", pos)
        return start, (len(self.text) if end == -1 else end)


def make_evidence(li: LineIndex, start: int, end: int, mask: bool = False) -> str:
    ls, le = li.bounds(start)
    line = li.text[ls:le]
    ms, me = start - ls, min(end - ls, le - ls)
    seg = line[ms:me]
    if mask:
        seg = mask_value(seg)
    elif len(seg) > 60:
        seg = seg[:40] + "…" + seg[-10:]
    pre, post = line[:ms], line[me:]
    if len(pre) > 70:
        pre = "…" + pre[-70:]
    if len(post) > 70:
        post = post[:70] + "…"
    return sanitize(pre + seg + post, 200)


def rule_applies(rule: dict[str, Any], rf: RepoFile) -> bool:
    exts = rule["exts"]
    if exts is not None and rf.ext not in exts and rf.name_lower not in exts:
        return False
    return rf.context not in rule["skip_contexts"]


_COMMENT_START = ("//", "#", "*", "/*", "<!--", "--")


def _comment_line(text: str, pos: int) -> bool:
    """True when the match sits on a line that starts as a comment. Comments describe code; they do not run it."""
    start = text.rfind("\n", 0, pos) + 1
    return text[start:pos].lstrip().startswith(_COMMENT_START)


def scan_text(step: str, rules: list[dict[str, Any]], rf: RepoFile, text: str, findings: list[Finding],
              counters: Counter, secrets: bool = False, per_file_cap: int = 3, global_cap: int = 60) -> None:
    """Apply regex rules to one file. Caps keep reports readable; suppressed hits are counted."""
    li = LineIndex(text)
    for rule in rules:
        if not rule_applies(rule, rf):
            continue
        rid = rule["id"]
        in_file = 0
        for m in rule["_re"].finditer(text):
            group = rule.get("group", 0)
            span = m.span(group) if m.lastindex and group and m.group(group) is not None else m.span()
            value = text[span[0]:span[1]]
            if secrets and is_placeholder(value):
                continue
            if not secrets and _comment_line(text, span[0]):
                continue
            min_ent = rule.get("min_entropy")
            if min_ent and entropy(value) < min_ent:
                continue
            if in_file >= per_file_cap or counters[rid] >= global_cap:
                counters[rid + "#suppressed"] += 1
                continue
            in_file += 1
            counters[rid] += 1
            # Test and documentation code often holds fake keys on purpose: keep the hit, cap its severity.
            sev = rule["severity"]
            if rf.context in ("test", "docs") and sev in ("critical", "high"):
                sev = "medium"
            findings.append(Finding(
                step=step, rule_id=rid, title=rule["title"], severity=sev,
                confidence=rule["confidence"], file=rf.rel, line=li.line_of(span[0]),
                evidence=make_evidence(li, span[0], span[1], mask=secrets and rule.get("mask", True)),
                context=rf.context, detail=rule.get("detail", ""),
            ))


def suppressed_notes(counters: Counter) -> list[str]:
    return [
        f"{n} more hit(s) of rule {key[:-11]} were suppressed (per-file/global caps); see the rule id to search yourself"
        for key, n in sorted(counters.items()) if key.endswith("#suppressed")
    ]


def looks_minified(text: str) -> bool:
    return len(text) > 5000 and len(text) / (text.count("\n") + 1) > 1000
