# Operation PolinRider

Operation PolinRider turns the original long-form incident-response article into a small,
testable, cross-platform defensive toolkit. The goal is not to prove every public campaign claim
inside this repository; the goal is to give developers and security teams practical checks they can
run before opening, installing, or trusting an unfamiliar project.

The project focuses on structural behaviors reported across PolinRider, GlassWorm, BeaverTail,
Trojan Source, and adjacent developer supply-chain incidents:

- invisible Unicode/private-use characters in source files;
- script payloads hidden behind binary-looking extensions such as `.woff2` or images;
- VS Code folder-open tasks that execute hidden payloads;
- suspicious git author-date versus committer-date gaps that may indicate history rewriting.

> **Verification note:** campaign names, repository counts, infrastructure, and attribution can change
> quickly. Treat this repository as tested defensive tooling, not as a primary threat-intelligence feed.
> See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what the project deliberately encodes as
> stable engineering assumptions.

## Why this exists

The original article was useful as a narrative guide, but narrative code is hard to test, hard to run
on every operating system, and easy to copy incorrectly. This repository is structured as a GitHub
project instead:

- reusable Python package under `src/polinrider_guard/`;
- command-line entry points for each scanner;
- thin scripts under `scripts/` for direct execution;
- pytest coverage for every scanner and every script wrapper;
- runnable clean and vulnerable examples under `examples/`.

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

## CLI commands

| Command | Purpose |
| --- | --- |
| `polinrider-guard PATH` | Run all scanners against a repository or directory. |
| `polinrider-scan-unicode PATH` | Find invisible Unicode, bidi controls, variation selectors, and private-use characters in source-like files. |
| `polinrider-scan-masquerade PATH` | Find script-like content hidden behind binary extensions. |
| `polinrider-scan-vscode PATH` | Inspect `.vscode/tasks.json` for risky folder-open execution patterns. |
| `polinrider-scan-git-dates PATH` | Find commits with large author/committer date skew across all refs. |

Each command supports `--json` for automation.

The same checks can be run through the direct wrapper scripts:

```bash
python scripts/polinrider-guard.py --help
python scripts/scan-unicode.py --help
python scripts/scan-masquerade.py --help
python scripts/scan-vscode-tasks.py --help
python scripts/scan-git-dates.py --help
```

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
