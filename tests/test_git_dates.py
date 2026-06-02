import os
import shutil
import subprocess
from pathlib import Path

import pytest

from polinrider_guard.git_dates import is_git_repo, main, scan_repo


def run_git(repo: Path, *args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for this test")
def test_scan_repo_finds_author_committer_skew(tmp_path: Path) -> None:
    run_git(tmp_path, "init")
    run_git(tmp_path, "config", "user.name", "Test User")
    run_git(tmp_path, "config", "user.email", "test@example.invalid")
    (tmp_path / "file.txt").write_text("hello", encoding="utf-8")
    run_git(tmp_path, "add", "file.txt")
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-01-05T00:00:00+00:00",
        }
    )
    run_git(tmp_path, "commit", "-m", "backdated", env=env)
    findings = scan_repo(tmp_path, threshold_hours=24)
    assert len(findings) == 1
    assert findings[0].metadata["skew_hours"] == 96.0


def test_non_git_repo_has_no_findings(tmp_path: Path) -> None:
    assert not is_git_repo(tmp_path)
    assert scan_repo(tmp_path) == []


def test_git_checks_do_not_traceback_when_git_is_missing(monkeypatch, tmp_path: Path) -> None:
    def missing_git(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", missing_git)

    assert is_git_repo(tmp_path) is False
    findings = scan_repo(tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "git.executable_missing"
    assert "--no-git" in findings[0].message


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for this test")
def test_git_dates_script_exit_code(tmp_path: Path) -> None:
    run_git(tmp_path, "init")
    assert main([str(tmp_path)]) == 0
