"""Safe file-system access: walking, reading, classifying and fetching the target.

Nothing in here executes code from the scanned repository. Symlinks are never followed.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "third_party", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".gradle", ".idea", ".next", ".nuxt",
    ".cache", "site-packages",
})
LOCK_FILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock", "bun.lockb", "uv.lock",
})
DOC_EXTS = frozenset({"md", "markdown", "rst", "txt", "adoc"})
TEST_DIRS = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures", "__fixtures__", "e2e", "testing",
})
EXAMPLE_DIRS = frozenset({"example", "examples", "sample", "samples", "demo", "demos"})
DOC_DIRS = frozenset({"docs", "doc", "documentation"})
_NOT_DOC_TXT = re.compile(r"^(?:requirements.*\.txt|constraints.*\.txt|cmakelists\.txt)$")
_TEST_NAME = re.compile(r"^(?:test_.*|.*_test\.\w+|.*\.test\.\w+|.*\.spec\.\w+|conftest\.py)$")

CODE_EXTS = frozenset({
    "py", "js", "mjs", "cjs", "jsx", "ts", "tsx", "go", "rs", "java", "kt", "rb", "php", "c", "h", "cc",
    "cpp", "hpp", "cs", "swift", "sh", "bash", "zsh", "ps1", "lua", "scala", "dart", "ex", "exs", "pl",
})

_EMPTY_DIR: Optional[str] = None


def empty_dir() -> str:
    """An empty directory, used as git hooksPath so repository hooks can never run."""
    global _EMPTY_DIR
    if _EMPTY_DIR is None:
        _EMPTY_DIR = tempfile.mkdtemp(prefix="scanrepo-nohooks-")
        atexit.register(shutil.rmtree, _EMPTY_DIR, True)
    return _EMPTY_DIR


@dataclass(frozen=True)
class RepoFile:
    rel: str
    path: Path
    size: int
    context: str

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @property
    def name_lower(self) -> str:
        return self.name.lower()

    @property
    def ext(self) -> str:
        n = self.name_lower
        return n.rsplit(".", 1)[1] if "." in n else ""

    @property
    def is_lock(self) -> bool:
        return self.name_lower in LOCK_FILES


@dataclass
class WalkResult:
    files: list[RepoFile] = field(default_factory=list)
    skipped_dirs: list[str] = field(default_factory=list)
    skipped_large: list[str] = field(default_factory=list)
    skipped_symlinks: int = 0
    truncated: bool = False


def classify_context(rel: str) -> str:
    parts = [p.lower() for p in rel.split("/")]
    name, dirs = parts[-1], parts[:-1]
    if any(d in TEST_DIRS for d in dirs) or _TEST_NAME.match(name):
        return "test"
    ext = name.rsplit(".", 1)[1] if "." in name else ""
    if _NOT_DOC_TXT.match(name):
        ext = ""
    if any(d in DOC_DIRS for d in dirs) or ext in DOC_EXTS:
        return "docs"
    if any(d in EXAMPLE_DIRS for d in dirs):
        return "example"
    return "production"


def walk_repo(root: Path, max_files: int = 20000, max_file_bytes: int = 1_000_000) -> WalkResult:
    result = WalkResult()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                result.skipped_symlinks += 1
            elif d in SKIP_DIRS:
                result.skipped_dirs.append(os.path.relpath(full, root).replace(os.sep, "/"))
            else:
                keep.append(d)
        dirnames[:] = keep
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            if os.path.islink(full):
                result.skipped_symlinks += 1
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if st.st_size > max_file_bytes:
                result.skipped_large.append(rel)
                continue
            if len(result.files) >= max_files:
                result.truncated = True
                return result
            result.files.append(RepoFile(rel, Path(full), st.st_size, classify_context(rel)))
    return result


def read_text(path: Path, limit: int = 1_000_000) -> Optional[str]:
    """Return decoded text, or None for binary or unreadable files."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data[:limit].decode("utf-8", errors="replace")


_MAGIC = (
    (b"\x7fELF", "ELF executable or library"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O binary"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary or Java class"),
    (b"\x00asm", "WebAssembly module"),
)
_BINARY_EXTS = {"jar": "Java archive", "pyc": "Python bytecode", "pyd": "Python extension module",
                "node": "Node native addon", "apk": "Android package", "msi": "Windows installer"}


def sniff_binary(path: Path, ext: str) -> Optional[str]:
    """Identify committed executables from magic bytes. Returns a label or None."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(1024)
    except OSError:
        return None
    for magic, label in _MAGIC:
        if head.startswith(magic):
            return label
    if head.startswith(b"MZ") and b"PE\x00\x00" in head:
        return "Windows PE executable or DLL"
    if ext in _BINARY_EXTS and b"\x00" in head[:512]:
        return _BINARY_EXTS[ext]
    return None


class TargetError(Exception):
    pass


_HTTPS_RE = re.compile(r"^https://[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?/[A-Za-z0-9_.~%/-]+$")
_SHORT_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+$")


def resolve_target(target: str, depth: int = 200) -> tuple[Path, Optional[str], Callable[[], None]]:
    """Return (root, origin_url, cleanup). Accepts a local directory, an https URL or owner/repo."""
    local = Path(target).expanduser()
    if local.is_dir():
        return local.resolve(), None, lambda: None
    if local.exists():
        raise TargetError(f"{target} is not a directory")
    if _HTTPS_RE.match(target):
        url = target
    elif _SHORT_RE.match(target):
        url = f"https://github.com/{target}"
    else:
        raise TargetError(
            f"cannot use target {target!r}: give an existing directory, an https:// repository URL "
            "or owner/repo"
        )
    if shutil.which("git") is None:
        raise TargetError("git is required to scan a remote repository but was not found")
    tmp = Path(tempfile.mkdtemp(prefix="scanrepo-clone-"))
    dest = tmp / "repo"
    cmd = [
        "git", "-c", f"core.hooksPath={empty_dir()}", "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always", "-c", "core.symlinks=false",
        "clone", "--depth", str(max(1, depth)), "--no-tags", "--single-branch",
        "--no-recurse-submodules", "--", url, str(dest),
    ]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
    except (subprocess.TimeoutExpired, OSError) as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise TargetError(f"cloning {url} failed: {exc}") from exc
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
        raise TargetError(f"cloning {url} failed: {tail[0]}")
    return dest, url, lambda: shutil.rmtree(tmp, ignore_errors=True)
