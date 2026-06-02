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

When a scan fails, `polinrider-guard` writes a GitHub Actions job summary that includes severity counts,
the first findings with rule IDs and paths, and remediation suggestions. The action also writes
`findings-count`, `highest-severity`, and `has-findings` outputs to `$GITHUB_OUTPUT` for repositories
that want to add notification or issue-creation steps after a guarded scan.

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

## What to do when the scan fails

1. Treat critical or high findings as a stop-the-line event: do not run package install scripts, editor
   tasks, or binary-looking files from the checkout until the finding is understood.
2. Review the job summary and JSON log for the `rule_id`, `path`, and message. Use the rule family to
   decide the first action:
   - `unicode.*`: remove unexpected invisible characters, or document intentional codepoints and narrow
     the scan scope only after review.
   - `masquerade.*`, `ioc.*`, or `yara.*`: quarantine or replace the suspicious asset, preserve evidence,
     and rotate credentials if the checkout may have executed locally or in CI.
   - `vscode.*`: remove folder-open auto-run behavior, make task output visible, and avoid invoking
     interpreters against `.woff2`, image, or other binary-extension files.
   - `git.*`: rerun with full history and review commit provenance before deciding whether `--no-git` is
     appropriate for that workflow.
3. Commit the remediation or adjust the workflow path to scan only the intended clean project area. Do
   not suppress findings from intentionally vulnerable fixtures unless the scan step is explicitly a
   negative-control test.
4. Rerun the workflow and require a clean `Repository protection scan` before merging.
