from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding


def is_git_repo(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def parse_epoch(value: str) -> datetime:
    return datetime.fromtimestamp(int(value), tz=timezone.utc)


def scan_repo(path: Path, threshold_hours: int = 24) -> list[Finding]:
    if not git_is_available():
        return [
            Finding(
                "git.executable_missing",
                "medium",
                (
                    "git executable not found; install git or rerun with --no-git "
                    "to skip history checks"
                ),
                path=path,
            )
        ]
    if not is_git_repo(path):
        return []
    fmt = "%H%x00%an%x00%at%x00%ct%x00%s"
    result = subprocess.run(
        ["git", "-C", str(path), "log", "--all", f"--pretty=format:{fmt}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return [Finding("git.log_failed", "medium", result.stderr.strip(), path=path)]
    findings: list[Finding] = []
    threshold_seconds = threshold_hours * 3600
    for line in result.stdout.splitlines():
        parts = line.split("\x00", 4)
        if len(parts) != 5:
            continue
        commit, author, author_time, committer_time, subject = parts
        try:
            author_dt = parse_epoch(author_time)
            committer_dt = parse_epoch(committer_time)
        except ValueError:
            continue
        skew_seconds = abs((committer_dt - author_dt).total_seconds())
        if skew_seconds > threshold_seconds:
            findings.append(
                Finding(
                    "git.author_committer_date_skew",
                    "medium",
                    (
                        f"Commit {commit[:12]} has author/committer date skew "
                        f"greater than {threshold_hours}h"
                    ),
                    path=path,
                    evidence=commit,
                    metadata={
                        "author": author,
                        "subject": subject,
                        "author_date": author_dt.isoformat(),
                        "committer_date": committer_dt.isoformat(),
                        "skew_hours": round(skew_seconds / 3600, 2),
                    },
                )
            )
    return findings


def git_is_available() -> bool:
    try:
        result = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find suspicious author/committer date gaps in git history."
    )
    parser.add_argument("path", nargs="?", default=".", help="Git repository path.")
    parser.add_argument("--threshold-hours", type=int, default=24, help="Date skew threshold.")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    findings = scan_repo(root, threshold_hours=args.threshold_hours)
    if args.json:
        print(json.dumps([finding.to_dict(root) for finding in findings], indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(f"{finding.path}: {finding.message} ({finding.metadata})")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
