# Threat model and verification notes

This repository is a defensive engineering project, not a primary threat-intelligence source.
The scanners are intentionally framed as structural checks that are useful for PolinRider,
GlassWorm, Trojan Source, and similar developer supply-chain attacks.

## What is verified enough to encode as tests

- Invisible Unicode and private-use code points can hide payloads from visual review.
- Git author dates and committer dates can diverge; a large unexplained divergence is an
  investigation signal, not proof of compromise.
- A file extension is not a content guarantee. A `.woff2`, image, or `.wasm` file containing
  readable JavaScript should be treated as suspicious until reviewed.
- VS Code `tasks.json` can define tasks that run when a folder opens. Hidden auto-run tasks
  invoking interpreters against disguised assets are high-risk.

## What must remain configurable

Campaign names, exact repository counts, attribution, and active indicators change quickly.
The project avoids hard-coding a claim as truth when a structural detector is safer and easier
to test. Known endpoint strings are retained only as optional indicator matches.
