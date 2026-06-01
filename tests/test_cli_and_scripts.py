import runpy
import subprocess
import sys
from pathlib import Path

from polinrider_guard.cli import main, scan_all

SCRIPT_NAMES = [
    "polinrider-guard.py",
    "scan-unicode.py",
    "scan-git-dates.py",
    "scan-masquerade.py",
    "scan-vscode-tasks.py",
]


def test_aggregate_cli_finds_multiple_rule_types(tmp_path: Path, capsys) -> None:
    (tmp_path / "bad.js").write_text("x\u200d\n", encoding="utf-8")
    (tmp_path / "font.woff2").write_text("require('fs'); function x(){}", encoding="utf-8")
    findings = scan_all(tmp_path, include_git=False)
    assert {finding.rule_id for finding in findings} >= {
        "unicode.invisible_or_private_use",
        "masquerade.binary_extension_contains_script",
    }
    assert main([str(tmp_path), "--no-git"]) == 1
    assert "unicode.invisible_or_private_use" in capsys.readouterr().out


def test_all_script_wrappers_support_help() -> None:
    for script_name in SCRIPT_NAMES:
        result = subprocess.run(
            [sys.executable, str(Path("scripts") / script_name), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, script_name
        assert "usage:" in result.stdout.lower(), script_name


def test_script_wrappers_only_import_main(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["scan-unicode.py", "--help"])
    for script_name in SCRIPT_NAMES:
        try:
            runpy.run_path(str(Path("scripts") / script_name), run_name="not_main")
        except SystemExit as exc:  # pragma: no cover - documents unexpected behavior
            raise AssertionError(f"{script_name} executed at import time") from exc
