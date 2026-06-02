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


def test_aggregate_cli_writes_github_outputs_and_summary(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "bad.js").write_text("x\u200d\n", encoding="utf-8")
    output_file = tmp_path / "github-output.txt"
    summary_file = tmp_path / "github-summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    assert main([str(tmp_path), "--no-git", "--json"]) == 1

    output = output_file.read_text(encoding="utf-8")
    assert "findings-count=1" in output
    assert "highest-severity=high" in output
    assert "has-findings=true" in output

    summary = summary_file.read_text(encoding="utf-8")
    assert "PolinRider Guard found **1** issue" in summary
    assert "unicode.invisible_or_private_use" in summary
    assert "Suggested actions" in summary
    assert "Rerun the workflow after remediation" in summary


def test_aggregate_cli_can_disable_github_summary(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "bad.js").write_text("x\u200d\n", encoding="utf-8")
    output_file = tmp_path / "github-output.txt"
    summary_file = tmp_path / "github-summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    monkeypatch.setenv("POLINRIDER_GITHUB_STEP_SUMMARY", "false")

    assert main([str(tmp_path), "--no-git"]) == 1

    assert "has-findings=true" in output_file.read_text(encoding="utf-8")
    assert not summary_file.exists()
