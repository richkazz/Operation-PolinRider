# GitHub protection setup

The repository includes a GitHub Actions workflow at
`.github/workflows/polinrider-guard.yml`. The workflow is intended to be used as a required status
check for pull requests.

## What the workflow protects

The workflow runs in two stages:

1. **Tests and lint** installs the project with development dependencies, runs the full pytest suite,
   and runs ruff lint checks on supported Python versions.
2. **Repository protection scan** installs the scanner package and runs `polinrider-guard` against the
   repository's source, scripts, docs, and clean example. It also verifies that the intentionally
   vulnerable example still fails, which protects against accidentally weakening detector behavior.

The workflow uses read-only repository permissions and disables checkout credential persistence so pull
request checks do not receive unnecessary write credentials.

## Recommended branch protection rule

In GitHub, configure a branch protection rule for the default branch:

1. Open **Settings → Branches → Add branch protection rule**.
2. Set the branch pattern to `main` or your default branch name.
3. Enable **Require a pull request before merging**.
4. Enable **Require status checks to pass before merging**.
5. Select these required checks:
   - `Tests and lint (Python 3.10)`
   - `Tests and lint (Python 3.12)`
   - `Repository protection scan`
6. Enable **Require branches to be up to date before merging** if your project requires linear review
   against the latest default branch.
7. Enable **Do not allow bypassing the above settings** for maintainers if this repository is used as a
   security gate.

For repositories with GitHub rulesets available, create an equivalent ruleset that requires the same
status checks on the default branch and on protected release branches.
