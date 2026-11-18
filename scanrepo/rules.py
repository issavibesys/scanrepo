"""Rule loading. Detection rules are data (JSON), so they can be updated without code changes."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

BUILTIN_RULES = Path(__file__).parent / "data" / "rules.json"

RULE_GROUPS = ("secrets", "code", "behavior", "sensitive_files", "claims")
LIST_GROUPS = ("telemetry_domains", "telemetry_prefixes", "ignore_domains", "ignore_url_substrings")
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class Rules:
    def __init__(self) -> None:
        self.groups: dict[str, list[dict[str, Any]]] = {g: [] for g in RULE_GROUPS}
        self.lists: dict[str, list[str]] = {g: [] for g in LIST_GROUPS}
        self.popular: dict[str, set[str]] = {}
        self.errors: list[str] = []

    def merge(self, data: dict[str, Any], source: str) -> None:
        for group in RULE_GROUPS:
            for raw in data.get(group, []) or []:
                rule = self._validate(raw, group, source)
                if rule is None:
                    continue
                existing = self.groups[group]
                for i, old in enumerate(existing):
                    if old["id"] == rule["id"]:
                        existing[i] = rule  # later sources override by id
                        break
                else:
                    existing.append(rule)
        for name in LIST_GROUPS:
            for item in data.get(name, []) or []:
                if isinstance(item, str) and item.lower() not in self.lists[name]:
                    self.lists[name].append(item.lower())
        for eco, names in (data.get("popular_packages") or {}).items():
            self.popular.setdefault(eco, set()).update(str(n).lower() for n in names)

    def _validate(self, raw: Any, group: str, source: str) -> Optional[dict[str, Any]]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not isinstance(raw.get("pattern"), str):
            self.errors.append(f"{source}: a {group} rule needs string 'id' and 'pattern'")
            return None
        rule = dict(raw)
        try:
            rule["_re"] = re.compile(rule["pattern"])
        except re.error as exc:
            self.errors.append(f"{source}: rule {rule['id']}: invalid pattern ({exc})")
            return None
        if group != "claims":
            sev = rule.get("severity", "low")
            if sev not in VALID_SEVERITIES:
                self.errors.append(f"{source}: rule {rule['id']}: invalid severity {sev!r}")
                return None
            rule["severity"] = sev
            try:
                conf = float(rule.get("confidence", 0.5))
            except (TypeError, ValueError):
                conf = -1.0
            if not 0.0 <= conf <= 1.0:
                self.errors.append(f"{source}: rule {rule['id']}: confidence must be between 0 and 1")
                return None
            rule["confidence"] = conf
        exts = rule.get("exts")
        rule["exts"] = frozenset(str(e).lower().lstrip(".") for e in exts) if exts else None
        rule["skip_contexts"] = frozenset(rule.get("skip_contexts") or ())
        return rule


def load_rules(extra_path: Optional[str] = None) -> Rules:
    rules = Rules()
    rules.merge(json.loads(BUILTIN_RULES.read_text(encoding="utf-8")), "built-in rules")
    if extra_path:
        try:
            data = json.loads(Path(extra_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"cannot read rules file {extra_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"rules file {extra_path} must contain a JSON object")
        rules.merge(data, extra_path)
    return rules
