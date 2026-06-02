from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from .models import Finding

SUSPICIOUS_COMMAND = re.compile(
    r"\b(node|python|python3|bash|sh|pwsh|powershell)\b"
    r".*\.(woff2?|ttf|otf|png|jpg|jpeg|gif|ico|wasm)\b",
    re.I,
)


def task_text(task: dict[str, Any]) -> str:
    parts = [str(task.get("command", ""))]
    args = task.get("args", [])
    if isinstance(args, list):
        parts.extend(str(arg) for arg in args)
    else:
        parts.append(str(args))
    return " ".join(parts)


def scan_tasks_file(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [Finding("vscode.tasks_json_unreadable", "medium", str(exc), path=path)]
    tasks = data.get("tasks", [])
    findings: list[Finding] = []
    if not isinstance(tasks, list):
        return findings
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        run_options_raw = task.get("runOptions", {})
        run_options = run_options_raw if isinstance(run_options_raw, dict) else {}
        presentation_raw = task.get("presentation", {})
        presentation = presentation_raw if isinstance(presentation_raw, dict) else {}
        label = str(task.get("label", f"task #{index}"))
        text = task_text(task)
        is_hidden_folder_open = (
            run_options.get("runOn") == "folderOpen"
            and (presentation.get("reveal") in {"never", "silent"} or task.get("hide") is True)
        )
        if is_hidden_folder_open:
            findings.append(
                Finding(
                    "vscode.hidden_folder_open_task",
                    "high",
                    f"VS Code task '{label}' auto-runs on folder open and hides output",
                    path=path,
                    evidence=label,
                    metadata={"task_index": index},
                )
            )
        if SUSPICIOUS_COMMAND.search(text):
            findings.append(
                Finding(
                    "vscode.task_executes_disguised_payload",
                    "critical",
                    (
                        f"VS Code task '{label}' executes an interpreter "
                        "against a disguised binary asset"
                    ),
                    path=path,
                    evidence=text,
                    metadata={"task_index": index},
                )
            )
    return findings


def scan_path(root: Path) -> list[Finding]:
    root = root.resolve()
    if root.is_file():
        return scan_tasks_file(root)
    return scan_tasks_file(root / ".vscode" / "tasks.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan .vscode/tasks.json for unsafe auto-run payloads."
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository root or tasks.json path.")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    findings = scan_path(root)
    if args.json:
        base = root if root.is_dir() else root.parent
        print(
            json.dumps(
                [finding.to_dict(base) for finding in findings],
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for finding in findings:
            print(f"{finding.path}: {finding.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
