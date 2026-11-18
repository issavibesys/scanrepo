from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from . import fsutil
from .rules import Rules


@dataclass
class ScanOptions:
    skip: frozenset = frozenset()
    rules_file: Optional[str] = None
    use_external: bool = True
    max_files: int = 20000
    max_file_kb: int = 1024
    depth: int = 200
    timeout_s: int = 600
    external_timeout_s: int = 300
    evidence_dir: Optional[str] = None  # directory of external evidence records, outside the repository


class ScanContext:
    """Everything a step needs. Shared computations are memoised so step order stays 1..6."""

    def __init__(self, root: Path, target: str, options: ScanOptions, rules: Rules,
                 origin_url: Optional[str] = None) -> None:
        self.root = root
        self.target = target
        self.options = options
        self.rules = rules
        self.origin_url = origin_url
        self.walk = fsutil.walk_repo(root, options.max_files, options.max_file_kb * 1024)
        self.files = self.walk.files
        self.deadline = time.monotonic() + options.timeout_s
        self._memo: dict[str, Any] = {}
        self._text: dict[str, Optional[str]] = {}

    def expired(self) -> bool:
        return time.monotonic() > self.deadline

    def read(self, rf: fsutil.RepoFile, cache: bool = False) -> Optional[str]:
        if cache and rf.rel in self._text:
            return self._text[rf.rel]
        text = fsutil.read_text(rf.path, self.options.max_file_kb * 1024)
        if cache and len(self._text) < 400:
            self._text[rf.rel] = text
        return text

    def memo(self, key: str, fn: Callable[[], Any]) -> Any:
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]

    def git(self, *args: str, timeout: int = 30) -> Optional[str]:
        """Read-only git queries with fsmonitor and hooks disabled. Returns None on any failure."""
        if not (self.root / ".git").exists() or shutil.which("git") is None:
            return None
        cmd = ["git", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={fsutil.empty_dir()}",
               "-c", "core.pager=cat", "-C", str(self.root), *args]
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        except (subprocess.TimeoutExpired, OSError):
            return None
        return proc.stdout if proc.returncode == 0 else None
