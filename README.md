# Operation PolinRider

Operation PolinRider is a complete defensive engineering project for checking repositories before
opening, installing, or trusting them. It packages the operation as runnable code, examples, tests,
and documentation rather than prose-only guidance.

The project focuses on structural behaviors associated with PolinRider, GlassWorm, BeaverTail,
Trojan Source, and adjacent developer supply-chain incidents:

- invisible Unicode/private-use characters in source files;
- script payloads hidden behind binary-looking extensions such as `.woff2`, images, or `.wasm`;
- VS Code folder-open tasks that execute hidden or disguised payloads;
- suspicious git author-date versus committer-date gaps that may indicate history rewriting.

> **Verification note:** campaign names, repository counts, infrastructure, and attribution can change
> quickly. Treat this repository as tested defensive tooling, not as a primary threat-intelligence feed.
> See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the assumptions this project deliberately
> encodes as stable, testable engineering checks.

## What this project provides

Operation PolinRider is intended to be useful as a repository you can clone, run, extend, and test:

- reusable Python package under `src/polinrider_guard/`;
- command-line entry points for each scanner;
- thin scripts under `scripts/` for direct execution without installation;
- pytest coverage for every scanner and every script wrapper;
- runnable clean and vulnerable examples under `examples/`;
- a documented threat model that separates stable detection logic from fast-changing campaign claims;
- a GitHub Actions workflow that can be required as a branch protection check.

## Public references to review

Use current primary or specialist sources before making incident decisions. Useful starting points:

- [MITRE ATT&CK: GlassWorm, S9010](https://attack.mitre.org/software/S9010/)
- [Wiz threat entry: PolinRider campaign](https://threats.wiz.io/all-incidents/polinrider-campaign-dprk-linked-supply-chain-attack-infects-github-repositories)
- [Wiz threat entry: PolinRider supply-chain attack](https://threats.wiz.io/all-incidents/polinrider-supply-chain-attack)
- [Malpedia: BeaverTail](https://malpedia.caad.fkie.fraunhofer.de/details/js.beavertail)

## Requirements

- Python 3.10 or newer
- `git` only for the git-history scanner and its tests
- `pytest` for the test suite

The scanners use the Python standard library at runtime. There are no runtime package dependencies.

## Quick start

```bash
python -m pip install -e .
polinrider-guard examples/clean-project
polinrider-guard examples/vulnerable-samples --no-git
```

Expected behavior:

- `examples/clean-project` exits `0` and prints `No findings.`
- `examples/vulnerable-samples` exits `1` and reports sample findings.

## Recommended repository intake workflow

Use this workflow before opening an unfamiliar repository in an IDE or running project scripts:

1. Clone or unpack the project into a temporary directory.
2. Run `polinrider-guard PATH --json` and save the output if you need an audit trail.
3. Review any findings before opening the folder in VS Code or another editor that may auto-run tasks.
4. If findings are expected test fixtures, document the exception and keep them isolated.
5. If findings are unexpected, do not run package-manager install scripts, build hooks, or IDE tasks until
   the repository has been reviewed by someone responsible for security.

A clean scan is not proof that a repository is safe. It only means these specific structural checks did
not produce findings.

## CLI commands

| Command | Purpose |
| --- | --- |
| `polinrider-guard PATH` | Run all scanners against a repository or directory. |
| `polinrider-scan-unicode PATH` | Find invisible Unicode, bidi controls, variation selectors, and private-use characters in source-like files. |
| `polinrider-scan-masquerade PATH` | Find script-like content hidden behind binary extensions. |
| `polinrider-scan-vscode PATH` | Inspect `.vscode/tasks.json` for risky folder-open execution patterns. |
| `polinrider-scan-git-dates PATH` | Find commits with large author/committer date skew across all refs. |

Each command supports `--json` for automation. Commands exit `1` when they produce findings and `0`
when no findings are present.

The same checks can be run through the direct wrapper scripts:

```bash
python scripts/polinrider-guard.py --help
python scripts/scan-unicode.py --help
python scripts/scan-masquerade.py --help
python scripts/scan-vscode-tasks.py --help
python scripts/scan-git-dates.py --help
```

## What each scanner checks

### Invisible Unicode scanner

The Unicode scanner examines source-like files for zero-width characters, bidirectional controls,
variation selectors, and private-use characters. These characters can be legitimate in some projects,
but they are unusual in most source code and should be reviewed when they appear unexpectedly.

### Binary-extension masquerade scanner

The masquerade scanner checks binary-looking file extensions for readable script markers, invalid magic
bytes, and known endpoint strings. It is designed around the principle that file extensions are labels,
not security boundaries.

### VS Code task scanner

The VS Code scanner reads `.vscode/tasks.json` and looks for folder-open tasks that hide output or invoke
an interpreter against a disguised binary asset. This catches a risky behavior pattern rather than a
single hard-coded filename.

### Git date-skew scanner

The git scanner compares author dates and committer dates across all refs. Large unexplained gaps are an
investigation signal because they can appear when history is rewritten or commits are backdated. This is
not a standalone proof of compromise.

## Examples

### Clean project

```bash
polinrider-guard examples/clean-project --no-git
```

### Intentionally vulnerable sample

```bash
polinrider-guard examples/vulnerable-samples --no-git
```

The vulnerable sample contains:

- a zero-width character in `app.js`;
- JavaScript-like content in `assets.woff2`;
- a `.vscode/tasks.json` folder-open task that runs `node ./assets.woff2` while hiding output.

These examples are inert and exist only to keep the scanners demonstrable and testable.


## GitHub Actions protection

This repository includes `.github/workflows/polinrider-guard.yml` so the operation can protect pull
requests, not just local machines. The workflow runs tests, linting, repository scans against source and
documentation paths, and a negative-control scan that confirms the intentionally vulnerable example still
produces findings.

To make the check enforceable, configure branch protection or a ruleset that requires the workflow status
checks before merging. See [`docs/GITHUB_PROTECTION.md`](docs/GITHUB_PROTECTION.md) for the recommended
required checks and protection settings.

## Development

```bash
python -m pip install -e .
python -m pytest
```

Optional linting if `ruff` is available:

```bash
python -m ruff check .
```

## Repository structure

```text
src/polinrider_guard/       Python package and scanner implementations
scripts/                    Direct cross-platform script wrappers
tests/                      Unit and CLI-wrapper tests
examples/clean-project/     No-finding demo project
examples/vulnerable-samples/Intentional finding demo project
docs/THREAT_MODEL.md        Stable assumptions and verification boundaries
```

## Scanner design principles

1. **Prefer structural signals over brittle strings.** Exact indicators change; suspicious behavior
   such as hidden Unicode or binary-extension masquerading remains testable.
2. **Fail safely for automation.** Commands exit `1` when findings are present and `0` when no
   findings are present.
3. **Be cross-platform.** Runtime scanners are Python, not shell-specific, so they work on Linux,
   macOS, and Windows.
4. **Keep findings reviewable.** JSON output uses a common finding schema with rule IDs, severity,
   paths, evidence, and metadata.

## Security limitations

This toolkit is a first-pass detector. It does not replace endpoint telemetry, sandbox execution,
malware reverse engineering, package-registry intelligence, or incident-response procedures. A clean
scan does not prove a repository is safe; it only means these specific checks did not find evidence.

If you suspect compromise, revoke credentials from a clean device, preserve forensic copies before
cleanup, and follow your organization’s incident-response process.

## License

MIT. Defensive and educational use is encouraged.
