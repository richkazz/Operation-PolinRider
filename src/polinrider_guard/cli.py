from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import git_dates, masquerade, unicode_scan, vscode_tasks
from .models import Finding

SCANNERS = {
    "unicode": unicode_scan.scan_path,
    "masquerade": masquerade.scan_path,
    "vscode": vscode_tasks.scan_path,
}


def scan_all(path: Path, include_git: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for scanner in SCANNERS.values():
        findings.extend(scanner(path))
    if include_git:
        findings.extend(git_dates.scan_repo(path))
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run all PolinRider Guard repository checks.")
    parser.add_argument("path", nargs="?", default=".", help="Repository root to scan.")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings.")
    parser.add_argument("--no-git", action="store_true", help="Skip git history checks.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    findings = scan_all(root, include_git=not args.no_git)
    if args.json:
        print(json.dumps([finding.to_dict(root) for finding in findings], indent=2, sort_keys=True))
    else:
        if not findings:
            print("No findings.")
        for finding in findings:
            location = finding.path or root
            print(f"[{finding.severity}] {finding.rule_id}: {location}: {finding.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
