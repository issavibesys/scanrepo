"""Convert REA's static JavaScript analysis into scanrepo evidence records.

Input: the JSON printed by `npx rea-agents analyze-javascript-application <dir> --json`.
Output: evidence records (see scanrepo/evidence.py) for `scanrepo --evidence DIR`.

The field names used here come from REA's source (src/domain/javascript/electronStaticAnalysisTypes.ts):
  browser_windows[].web_preferences[] = {name, value: {status: "literal"|"dynamic", value, expression}}
  browser_windows[].location.start.line, browser_windows[].window_constructor (optional)
  one record per analysed file: {"file": ..., "javascript": {"electron": {"browser_windows": [...]}}}
The envelope around them is searched for rather than assumed. Run it on real output before relying on it.

Only explicit literal values become class B. Dynamic values become class C leads. Omitted properties are not
reported, because REA itself says omitted webPreferences are not interpreted as Electron defaults.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator, Optional

PRODUCER = "rea"
DEFAULT_COMMAND = "analyze-javascript-application --json"

# web preference -> (value that is insecure, rule id, title, severity, confidence)
RULES: dict[str, tuple[Any, str, str, str, float]] = {
    "nodeIntegration": (True, "electron-node-integration", "BrowserWindow enables nodeIntegration", "medium", 0.7),
    "contextIsolation": (False, "electron-context-isolation-off", "BrowserWindow disables contextIsolation", "medium", 0.6),
    "webSecurity": (False, "electron-web-security-off", "BrowserWindow disables webSecurity", "medium", 0.6),
    "sandbox": (False, "electron-sandbox-off", "BrowserWindow disables the sandbox", "low", 0.5),
    "allowRunningInsecureContent": (True, "electron-insecure-content", "BrowserWindow allows insecure content", "medium", 0.6),
}


def iter_file_entries(node: Any) -> Iterator[dict[str, Any]]:
    """Every object shaped like {"file": ..., "javascript": {...}}, wherever it sits in the envelope."""
    if isinstance(node, dict):
        if "file" in node and isinstance(node.get("javascript"), dict):
            yield node
        for value in node.values():
            yield from iter_file_entries(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_file_entries(item)


def relative_to_root(root: Path, file: str) -> Optional[str]:
    p = Path(file)
    try:
        if p.is_absolute():
            p = p.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return None
    rel = p.as_posix()
    return rel if rel and not rel.startswith("..") and (root / rel).is_file() else None


def convert(doc: Any, root: Path, commit: str, command: str = DEFAULT_COMMAND) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records: list[dict[str, Any]] = []
    stats = {"files": 0, "windows": 0, "preferences_checked": 0, "unresolved_files": 0}
    for entry in iter_file_entries(doc):
        stats["files"] += 1
        electron = (entry["javascript"] or {}).get("electron") or {}
        windows = electron.get("browser_windows") or []
        if not windows:
            continue
        rel = relative_to_root(root, str(entry["file"]))
        if rel is None:
            stats["unresolved_files"] += 1
            continue
        for win in windows:
            if not isinstance(win, dict):
                continue
            stats["windows"] += 1
            location = win.get("location") or {}
            line = (location.get("start") or {}).get("line") if isinstance(location, dict) else None
            line = line if isinstance(line, int) and line >= 1 else None
            ctor = win.get("window_constructor") or "BrowserWindow"
            for pref in win.get("web_preferences") or []:
                if not isinstance(pref, dict):
                    continue
                name = pref.get("name")
                if name not in RULES:
                    continue
                stats["preferences_checked"] += 1
                value = pref.get("value") or {}
                insecure, rule, title, sev, conf = RULES[name]
                base = {"schema": 1, "producer": PRODUCER, "command": command, "target_commit": commit,
                        "type": "finding", "rule": rule, "title": title, "file": rel, "line": line}
                if value.get("status") == "literal" and value.get("value") is insecure:
                    records.append({**base, "class": "B", "severity": sev, "confidence": conf,
                                    "observation": f"{ctor} webPreferences.{name} = {json.dumps(insecure)} (literal)"})
                elif value.get("status") == "dynamic":
                    expr = str(value.get("expression") or "")[:120]
                    records.append({**base, "class": "C", "severity": "low", "confidence": 0.3,
                                    "observation": f"{ctor} webPreferences.{name} is dynamic: {expr}"})
    return records, stats


def find_commit(root: Path) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="rea-to-evidence", description="Convert REA JavaScript analysis output to scanrepo evidence.")
    ap.add_argument("input", help="JSON output of analyze-javascript-application --json")
    ap.add_argument("--root", required=True, help="the repository that was analysed (same tree, same commit)")
    ap.add_argument("--out", required=True, help="output .jsonl file, placed outside the repository")
    ap.add_argument("--commit", help="commit the analysis was run on (default: git HEAD of --root)")
    ap.add_argument("--command", default=DEFAULT_COMMAND, help="the exact static command that produced the input")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"rea-to-evidence: --root is not a directory: {root}", file=sys.stderr)
        return 2
    commit = args.commit or find_commit(root)
    if not commit:
        print("rea-to-evidence: no commit: pass --commit (records must be bound to a commit)", file=sys.stderr)
        return 2
    try:
        doc = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"rea-to-evidence: cannot read input JSON: {exc}", file=sys.stderr)
        return 2

    records, stats = convert(doc, root, commit, args.command)
    if stats["files"] == 0:
        print("rea-to-evidence: no analysed files found in the input. Is it the JSON output of analyze-javascript-application?",
              file=sys.stderr)
        return 2
    out = Path(args.out)
    if out.resolve().is_relative_to(root):
        print("rea-to-evidence: --out must be outside the repository", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    print(f"rea-to-evidence: {len(records)} record(s) written to {out}; files={stats['files']} "
          f"windows={stats['windows']} preferences={stats['preferences_checked']} unresolved_files={stats['unresolved_files']}",
          file=sys.stderr)
    if stats["windows"] == 0:
        print("rea-to-evidence: no BrowserWindow findings in this input (no Electron windows, or the envelope differs)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
