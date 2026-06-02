from pathlib import Path

WORKFLOW = Path(".github/workflows/polinrider-guard.yml")
PROTECTION_DOC = Path("docs/GITHUB_PROTECTION.md")
ACTION = Path("action.yml")
DOCKERFILE = Path("Dockerfile")


def test_github_workflow_exists_and_runs_required_checks() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "pull_request:" in text
    assert "push:" in text
    assert "permissions:\n  contents: read" in text
    assert "persist-credentials: false" in text
    assert "python -m pytest" in text
    assert "python -m ruff check ." in text
    assert "polinrider-guard src --no-git --json" in text
    assert "polinrider-guard examples/clean-project --no-git --json" in text
    assert "polinrider-guard examples/vulnerable-samples --no-git --json" in text
    assert "id: scan-repository" in text
    assert "POLINRIDER_GITHUB_STEP_SUMMARY: 'false'" in text


def test_branch_protection_documentation_names_required_checks() -> None:
    text = PROTECTION_DOC.read_text(encoding="utf-8")

    assert "Require status checks to pass before merging" in text
    assert "Tests and lint (Python 3.10)" in text
    assert "Tests and lint (Python 3.12)" in text
    assert "Repository protection scan" in text
    assert "Do not allow bypassing" in text


def test_docker_action_handles_git_scans_and_hyphenated_no_git_input() -> None:
    action = ACTION.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "inputs['no-git'] == 'true'" in action
    assert "findings-count:" in action
    assert "highest-severity:" in action
    assert "has-findings:" in action
    assert "apt-get install --no-install-recommends -y git" in dockerfile
