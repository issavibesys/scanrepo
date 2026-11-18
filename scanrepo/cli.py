from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .context import ScanOptions
from .engine import STEP_NAMES, TargetError, scan
from .models import SEVERITIES
from .report import summary_line, to_json, to_markdown, to_sarif

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scan-repo",
        description="Static scan of a repository for unsupported claims and vulnerabilities. Never executes the scanned code.",
        epilog="Steps: " + ", ".join(STEP_NAMES) + ". Exit codes: 0 ok, 1 findings at/above --fail-on, 2 error.",
    )
    p.add_argument("target", help="local directory, https:// repository URL, or owner/repo (GitHub)")
    p.add_argument("-f", "--format", choices=("markdown", "json", "sarif"), default="markdown", help="stdout format (default: markdown)")
    p.add_argument("-o", "--output", metavar="DIR", help="write report.md, report.json and report.sarif into DIR")
    p.add_argument("--fail-on", choices=("none",) + SEVERITIES[1:], default="none",
                   help="exit 1 if a production finding at/above this severity has enough confidence (default: none)")
    p.add_argument("--min-confidence", type=float, default=0.0, metavar="0-1",
                   help="hide findings below this confidence in Markdown/SARIF; also the bar for --fail-on (default 0, 0.5 with --fail-on)")
    p.add_argument("--skip", action="append", default=[], metavar="STEP", help="skip a step (repeatable)")
    p.add_argument("--rules", metavar="FILE", help="JSON file with extra or overriding rules")
    p.add_argument("--evidence", metavar="DIR", help="directory of external evidence records (*.json, *.jsonl), outside the repository")
    p.add_argument("--no-external", action="store_true", help="do not call external tools such as osv-scanner or npm")
    p.add_argument("--max-files", type=int, default=20000)
    p.add_argument("--max-file-kb", type=int, default=1024)
    p.add_argument("--depth", type=int, default=200, help="git clone depth for remote targets (default 200)")
    p.add_argument("--timeout", type=int, default=600, help="overall time budget in seconds (default 600)")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr")
    p.add_argument("--version", action="version", version=f"scanrepo {__version__}")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.0 <= args.min_confidence <= 1.0:
        print("scan-repo: --min-confidence must be between 0 and 1", file=sys.stderr)
        return EXIT_ERROR
    gate_conf = args.min_confidence if args.min_confidence > 0 else 0.5
    options = ScanOptions(
        skip=frozenset(args.skip), rules_file=args.rules, use_external=not args.no_external, evidence_dir=args.evidence,
        max_files=args.max_files, max_file_kb=args.max_file_kb, depth=args.depth, timeout_s=args.timeout,
    )
    progress = None if args.quiet else (lambda t: print(f"scan-repo: {t} …", file=sys.stderr))
    try:
        report = scan(args.target, options, progress)
    except (TargetError, ValueError) as exc:
        print(f"scan-repo: {exc}", file=sys.stderr)
        return EXIT_ERROR

    md = to_markdown(report, args.min_confidence)
    if args.output:
        out = Path(args.output)
        try:
            out.mkdir(parents=True, exist_ok=True)
            (out / "report.md").write_text(md, encoding="utf-8")
            (out / "report.json").write_text(to_json(report), encoding="utf-8")
            (out / "report.sarif").write_text(to_sarif(report, args.min_confidence), encoding="utf-8")
        except OSError as exc:
            print(f"scan-repo: cannot write reports to {out}: {exc}", file=sys.stderr)
            return EXIT_ERROR
    text = {"markdown": md, "json": to_json(report), "sarif": to_sarif(report, args.min_confidence)}[args.format]
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    if not args.quiet:
        print(f"scan-repo: {summary_line(report)}", file=sys.stderr)
    return EXIT_FINDINGS if report.exceeds(args.fail_on, gate_conf) else EXIT_OK
