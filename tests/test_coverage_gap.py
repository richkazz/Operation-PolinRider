import json
import stat
import subprocess
from pathlib import Path

from polinrider_guard.cli import main as cli_main
from polinrider_guard.git_dates import main as git_main
from polinrider_guard.git_dates import scan_repo
from polinrider_guard.masquerade import main as masquerade_main
from polinrider_guard.masquerade import scan_file as scan_masquerade_file
from polinrider_guard.models import Finding
from polinrider_guard.unicode_scan import main as unicode_main
from polinrider_guard.unicode_scan import scan_file
from polinrider_guard.vscode_tasks import main as vscode_main
from polinrider_guard.vscode_tasks import scan_tasks_file
from polinrider_guard.walk import iter_files


def test_unicode_scan_new_extensions(tmp_path: Path):
    extensions = [".php", ".kt", ".swift", ".sql", ".bat", ".ps1"]
    for ext in extensions:
        p = tmp_path / f"test{ext}"
        p.write_text("v = 1\u200b", encoding="utf-8")
        findings = scan_file(p)
        assert len(findings) == 1
        assert findings[0].rule_id == "unicode.invisible_or_private_use"


def test_unicode_scan_unreadable_file(tmp_path: Path):
    p = tmp_path / "unreadable.py"
    p.write_text("v = 1", encoding="utf-8")
    p.chmod(0)
    try:
        findings = scan_file(p)
        assert len(findings) == 1
        assert findings[0].rule_id == "file.read_error"
    finally:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_unicode_scan_decode_error(tmp_path: Path):
    p = tmp_path / "bad_decode.py"
    p.write_bytes(b"\xff\xfe\xfd")
    findings = scan_file(p)
    assert len(findings) == 0


def test_masquerade_new_markers(tmp_path: Path):
    markers = [b"exec(", b"subprocess.", b"os.system"]
    for marker in markers:
        p = tmp_path / f"test_{marker.decode().strip('.')}.woff2"
        p.write_bytes(marker + b" extra data")
        findings = scan_masquerade_file(p)
        assert any(f.rule_id == "masquerade.binary_extension_contains_script" for f in findings)


def test_masquerade_unreadable_file(tmp_path: Path):
    p = tmp_path / "unreadable.woff2"
    p.write_bytes(b"something")
    p.chmod(0)
    try:
        findings = scan_masquerade_file(p)
        assert len(findings) == 1
        assert findings[0].rule_id == "file.read_error"
    finally:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_vscode_tasks_invalid_json(tmp_path: Path):
    p = tmp_path / ".vscode" / "tasks.json"
    p.parent.mkdir()
    p.write_text("{invalid json", encoding="utf-8")
    findings = scan_tasks_file(p)
    assert len(findings) == 1
    assert findings[0].rule_id == "vscode.tasks_json_unreadable"


def test_vscode_tasks_not_a_list(tmp_path: Path):
    p = tmp_path / ".vscode" / "tasks.json"
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps({"tasks": "not a list"}), encoding="utf-8")
    findings = scan_tasks_file(p)
    assert len(findings) == 0


def test_vscode_tasks_task_not_a_dict(tmp_path: Path):
    p = tmp_path / ".vscode" / "tasks.json"
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps({"tasks": ["not a dict"]}), encoding="utf-8")
    findings = scan_tasks_file(p)
    assert len(findings) == 0


def test_vscode_tasks_presentation_not_a_dict(tmp_path: Path):
    p = tmp_path / ".vscode" / "tasks.json"
    p.parent.mkdir(exist_ok=True)
    payload = {
        "tasks": [
            {"label": "t", "presentation": "not a dict", "runOptions": {"runOn": "folderOpen"}}
        ]
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    # presentation.get("reveal") will be called on an empty dict if presentation is not a dict
    findings = scan_tasks_file(p)
    # It should still find hidden folder open if reveal is not set to silent/never?
    # Wait, reveal defaults to None, which is not in {"never", "silent"}.
    assert len(findings) == 0


def test_models_to_dict_no_root():
    f = Finding("id", "sev", "msg")
    d = f.to_dict()
    assert d["path"] is None


def test_models_to_dict_with_path_no_root(tmp_path: Path):
    p = tmp_path / "test.txt"
    f = Finding("id", "sev", "msg", path=p)
    d = f.to_dict()
    assert d["path"] == str(p)


def test_models_to_dict_path_not_relative_to_root():
    p = Path("/other/path/test.txt")
    root = Path("/app")
    f = Finding("id", "sev", "msg", path=p)
    d = f.to_dict(root=root)
    assert d["path"] == str(p)


def test_walk_iter_files_single_file(tmp_path: Path):
    p = tmp_path / "file.txt"
    p.write_text("hi")
    paths = list(iter_files(p))
    assert len(paths) == 1
    assert paths[0] == p.resolve()


def test_cli_no_findings(tmp_path: Path, capsys):
    assert cli_main([str(tmp_path), "--no-git"]) == 0
    assert "No findings." in capsys.readouterr().out


def test_unicode_main_no_json(tmp_path: Path, capsys):
    p = tmp_path / "test.py"
    p.write_text("\u200b", encoding="utf-8")
    unicode_main([str(tmp_path)])
    assert "test.py:1:1: Suspicious" in capsys.readouterr().out


def test_masquerade_main_no_json(tmp_path: Path, capsys):
    p = tmp_path / "test.woff2"
    p.write_text("eval('hi')", encoding="utf-8")
    masquerade_main([str(tmp_path)])
    assert "test.woff2: .woff2 file looks like script" in capsys.readouterr().out


def test_vscode_main_no_json(tmp_path: Path, capsys):
    p = tmp_path / ".vscode" / "tasks.json"
    p.parent.mkdir()
    payload = {"tasks": [{"label": "t", "command": "node", "args": ["x.png"]}]}
    p.write_text(json.dumps(payload), encoding="utf-8")
    vscode_main([str(tmp_path)])
    assert "tasks.json: VS Code task 't' executes" in capsys.readouterr().out


def test_git_main_no_json(tmp_path: Path, capsys):
    # This might be tricky if it's not a git repo, but let's test the 0 findings case
    git_main([str(tmp_path)])
    assert capsys.readouterr().out == ""


def test_git_main_json(tmp_path: Path, capsys):
    git_main([str(tmp_path), "--json"])
    assert capsys.readouterr().out == "[]\n"


def test_vscode_main_json(tmp_path: Path, capsys):
    vscode_main([str(tmp_path), "--json"])
    assert capsys.readouterr().out == "[]\n"


def test_unicode_main_json(tmp_path: Path, capsys):
    unicode_main([str(tmp_path), "--json"])
    assert capsys.readouterr().out == "[]\n"


def test_masquerade_main_json(tmp_path: Path, capsys):
    masquerade_main([str(tmp_path), "--json"])
    assert capsys.readouterr().out == "[]\n"


def test_cli_main_json(tmp_path: Path, capsys):
    cli_main([str(tmp_path), "--no-git", "--json"])
    assert capsys.readouterr().out == "[]\n"


def test_vscode_scan_path_file(tmp_path: Path):
    p = tmp_path / "tasks.json"
    p.write_text(json.dumps({"tasks": []}), encoding="utf-8")
    findings = scan_tasks_file(p)
    assert findings == []


def test_git_dates_unparseable_epoch(tmp_path: Path, monkeypatch):
    class MockResult:
        returncode = 0
        stdout = "commit\x00author\x00invalid\x00invalid\x00subject\n"
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: MockResult())
    monkeypatch.setattr("polinrider_guard.git_dates.git_is_available", lambda: True)
    monkeypatch.setattr("polinrider_guard.git_dates.is_git_repo", lambda p: True)
    findings = scan_repo(tmp_path)
    assert findings == []


def test_git_dates_log_failed(tmp_path: Path, monkeypatch):
    class MockResult:
        returncode = 1
        stdout = ""
        stderr = "error"
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: MockResult())
    monkeypatch.setattr("polinrider_guard.git_dates.git_is_available", lambda: True)
    monkeypatch.setattr("polinrider_guard.git_dates.is_git_repo", lambda p: True)
    findings = scan_repo(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "git.log_failed"
