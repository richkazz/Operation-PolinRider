from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from . import git_dates, masquerade, unicode_scan, vscode_tasks, yara_scanner
from .models import Finding

SCANNERS = {
    "unicode": unicode_scan.scan_path,
    "masquerade": masquerade.scan_path,
    "vscode": vscode_tasks.scan_path,
    "yara": yara_scanner.scan_path,
}
SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}
SUMMARY_FINDING_LIMIT = 25


def scan_all(path: Path, include_git: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for scanner in SCANNERS.values():
        findings.extend(scanner(path))
    if include_git:
        findings.extend(git_dates.scan_repo(path))
    return findings


def highest_severity(findings: list[Finding]) -> str:
    if not findings:
        return "none"
    return max(findings, key=lambda finding: SEVERITY_RANK.get(finding.severity, 0)).severity


def markdown_escape(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def finding_location(finding: Finding, root: Path | None = None) -> str:
    if finding.path is None:
        location = str(root) if root else "."
    else:
        try:
            location = str(finding.path.relative_to(root)) if root else str(finding.path)
        except ValueError:
            location = str(finding.path)
    if finding.line is not None:
        location = f"{location}:{finding.line}"
        if finding.column is not None:
            location = f"{location}:{finding.column}"
    return location


def remediation_for_rule(rule_id: str) -> str:
    if rule_id.startswith("unicode."):
        return (
            "Remove unexpected invisible characters or document why the exact codepoint "
            "is required. For markdown emoji, prefer plain emoji characters without "
            "variation selectors."
        )
    if rule_id.startswith("masquerade."):
        return (
            "Quarantine the file, replace it with a verified binary asset from a trusted source, "
            "and do not execute binary-extension files with script interpreters."
        )
    if rule_id.startswith("ioc.") or rule_id.startswith("yara."):
        return (
            "Treat the repository as potentially compromised: stop local execution, "
            "preserve the evidence, rotate exposed credentials, and review the file "
            "against incident-response guidance."
        )
    if rule_id.startswith("vscode."):
        return (
            "Remove folder-open auto-run behavior, make task output visible, and ensure "
            "tasks do not invoke Node.js, Python, or shell interpreters against "
            "disguised binary assets."
        )
    if rule_id.startswith("git."):
        return (
            "Review commit provenance and author/committer dates; rerun with full "
            "history or use --no-git only when history checks are intentionally "
            "out of scope."
        )
    return "Review the finding, remove untrusted content, and rerun PolinRider Guard."


def remediation_steps(findings: list[Finding]) -> list[str]:
    steps: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        advice = remediation_for_rule(finding.rule_id)
        if advice in seen:
            continue
        seen.add(advice)
        steps.append(advice)
    return steps


def build_github_summary(findings: list[Finding], root: Path) -> str:
    if not findings:
        return "## PolinRider Guard\n\nNo findings were detected.\n"

    counts = Counter(finding.severity for finding in findings)
    counts_text = ", ".join(
        f"{severity}: {counts[severity]}"
        for severity in ("critical", "high", "medium", "low")
        if counts[severity]
    )
    lines = [
        "## PolinRider Guard findings",
        "",
        f"PolinRider Guard found **{len(findings)}** issue(s). Highest severity: "
        f"**{highest_severity(findings)}**.",
    ]
    if counts_text:
        lines.append(f"Severity counts: {counts_text}.")
    lines.extend(
        [
            "",
            "### Findings",
            "",
            "| Severity | Rule | Location | Message |",
            "| --- | --- | --- | --- |",
        ]
    )
    for finding in findings[:SUMMARY_FINDING_LIMIT]:
        lines.append(
            "| "
            f"{markdown_escape(finding.severity)} | "
            f"`{markdown_escape(finding.rule_id)}` | "
            f"`{markdown_escape(finding_location(finding, root))}` | "
            f"{markdown_escape(finding.message)} |"
        )
    if len(findings) > SUMMARY_FINDING_LIMIT:
        lines.append(
            f"\nShowing the first {SUMMARY_FINDING_LIMIT} findings. Review the job log "
            "or JSON output for the full list."
        )
    lines.extend(
        [
            "",
            "### Suggested actions",
            "",
            "1. Do not run install scripts, IDE tasks, or binary-looking files from "
            "this checkout until findings are reviewed.",
        ]
    )
    for index, step in enumerate(remediation_steps(findings), start=2):
        lines.append(f"{index}. {step}")
    next_step = len(remediation_steps(findings)) + 2
    lines.append(
        f"{next_step}. Rerun the workflow after remediation to confirm the "
        "repository is clean."
    )
    lines.append("")
    return "\n".join(lines)


def write_github_metadata(findings: list[Finding], root: Path) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(f"findings-count={len(findings)}\n")
            handle.write(f"highest-severity={highest_severity(findings)}\n")
            handle.write(f"has-findings={str(bool(findings)).lower()}\n")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    summary_enabled = os.environ.get("POLINRIDER_GITHUB_STEP_SUMMARY", "true").lower()
    if summary_path and summary_enabled not in {"0", "false", "no", "off"}:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(build_github_summary(findings, root))
            handle.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run all PolinRider Guard repository checks.")
    parser.add_argument("path", nargs="?", default=".", help="Repository root to scan.")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings.")
    parser.add_argument("--no-git", action="store_true", help="Skip git history checks.")
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # Filter out empty strings passed by GitHub Actions conditional logic
    argv = [arg for arg in argv if arg]

    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    findings = scan_all(root, include_git=not args.no_git)
    write_github_metadata(findings, root)
    if args.json:
        print(json.dumps([finding.to_dict(root) for finding in findings], indent=2, sort_keys=True))
    else:
        if not findings:
            print("No findings.")
        for finding in findings:
            location = finding.path or root
            print(f"[{finding.severity}] {finding.rule_id}: {location}: {finding.message}")
        if findings:
            print("\nSuggested actions:")
            for step in remediation_steps(findings):
                print(f"- {step}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
