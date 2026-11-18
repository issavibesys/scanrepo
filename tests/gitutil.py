import os
import subprocess

_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def git_init(root):
    """Turn a directory into a one-commit git repository. Returns the full commit id."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, env=_ENV)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, env=_ENV)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=root, check=True, env=_ENV)
    return head_of(root)


def head_of(root):
    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True, env=_ENV)
    return out.stdout.strip()
