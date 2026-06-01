import json
from pathlib import Path

from polinrider_guard.vscode_tasks import main, scan_path, scan_tasks_file


def write_tasks(path: Path, tasks: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": "2.0.0", "tasks": tasks}), encoding="utf-8")


def test_scan_tasks_file_finds_hidden_folder_open_binary_execution(tmp_path: Path) -> None:
    tasks_file = tmp_path / ".vscode" / "tasks.json"
    write_tasks(
        tasks_file,
        [
            {
                "label": "refresh",
                "command": "node",
                "args": ["./font.woff2"],
                "runOptions": {"runOn": "folderOpen"},
                "presentation": {"reveal": "never"},
            }
        ],
    )
    rule_ids = {finding.rule_id for finding in scan_tasks_file(tasks_file)}
    assert "vscode.hidden_folder_open_task" in rule_ids
    assert "vscode.task_executes_disguised_payload" in rule_ids


def test_scan_path_returns_empty_without_tasks_file(tmp_path: Path) -> None:
    assert scan_path(tmp_path) == []


def test_vscode_script_json_exit_code(tmp_path: Path, capsys) -> None:
    tasks_file = tmp_path / ".vscode" / "tasks.json"
    write_tasks(tasks_file, [{"label": "bad", "command": "python", "args": ["x.png"]}])
    assert main([str(tmp_path), "--json"]) == 1
    assert "vscode.task_executes_disguised_payload" in capsys.readouterr().out
