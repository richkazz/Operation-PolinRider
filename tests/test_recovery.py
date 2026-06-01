import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure we can import from scripts if needed, or just run them as subprocesses
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
SURGICAL_CLEAN = SCRIPTS_DIR / "surgical-clean.py"

def run_git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, check=True)

@pytest.fixture
def test_repo():
    """Creates a temporary git repository with legitimate and malicious commits."""
    temp_dir = tempfile.mkdtemp()
    repo_dir = Path(temp_dir) / "test-repo"
    repo_dir.mkdir()

    run_git(["init"], repo_dir)
    run_git(["config", "user.email", "test@example.com"], repo_dir)
    run_git(["config", "user.name", "Test User"], repo_dir)

    # 1. Legitimate commit
    file1 = repo_dir / "app.js"
    file1.write_text("console.log('legit line 1');\nconsole.log('legit line 2');\n")
    run_git(["add", "app.js"], repo_dir)
    run_git(["commit", "-m", "Initial legitimate commit"], repo_dir)

    # 2. Malicious injection (appended to existing file)
    with open(file1, "a") as f:
        f.write("global['_V']='8-st-demo'; // malicious injection\n")
    run_git(["add", "app.js"], repo_dir)
    run_git(["commit", "-m", "Unsuspecting update (malicious)"], repo_dir)

    # 3. Another malicious injection (invisible unicode)
    file2 = repo_dir / "utils.js"
    # Adding a zero-width space \u200b
    file2.write_bytes(b"const secret = 'safe';\xe2\x80\x8b\n")
    run_git(["add", "utils.js"], repo_dir)
    run_git(["commit", "-m", "Add utils (malicious unicode)"], repo_dir)

    # 4. Legitimate work on top
    with open(file1, "a") as f:
        f.write("console.log('legit line 3');\n")
    run_git(["add", "app.js"], repo_dir)
    run_git(["commit", "-m", "More legitimate work"], repo_dir)

    yield repo_dir

    shutil.rmtree(temp_dir)

def test_surgical_clean(test_repo):
    # Verify presence of malicious content initially
    app_js_content = (test_repo / "app.js").read_text()
    assert "global['_V']='8-st-demo'" in app_js_content
    assert "legit line 3" in app_js_content

    utils_js_content = (test_repo / "utils.js").read_bytes()
    assert b"\xe2\x80\x8b" in utils_js_content

    # Run surgical-clean.py
    # Note: surgical-clean.py requires git-filter-repo to be installed
    try:
        import git_filter_repo  # noqa: F401
    except ImportError:
        pytest.skip("git-filter-repo not installed, skipping surgical clean test")

    result = subprocess.run(
        [sys.executable, str(SURGICAL_CLEAN), "--verbose"],
        cwd=test_repo,
        capture_output=True,
        text=True
    )

    assert result.returncode == 1 # 1 because it cleaned something

    # Verify content after cleaning
    app_js_content_cleaned = (test_repo / "app.js").read_text()
    assert "global['_V']='8-st-demo'" not in app_js_content_cleaned
    assert "legit line 1" in app_js_content_cleaned
    assert "legit line 2" in app_js_content_cleaned
    assert "legit line 3" in app_js_content_cleaned

    utils_js_content_cleaned = (test_repo / "utils.js").read_bytes()
    assert b"\xe2\x80\x8b" not in utils_js_content_cleaned
    assert b"const secret = 'safe';" in utils_js_content_cleaned

    # Verify history is preserved (still should have 4 commits, though hashes changed)
    log_result = run_git(["log", "--oneline"], test_repo)
    commits = log_result.stdout.strip().split("\n")
    assert len(commits) == 4

if __name__ == "__main__":
    pass
