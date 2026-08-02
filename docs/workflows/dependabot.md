# dependabot

## Purpose

Keeps dependencies and pinned action SHAs current.

## Triggers

Weekly on Monday, per ecosystem. Configured in `.github/dependabot.yml`; this is
configuration rather than a workflow.

## What it covers

| Ecosystem | Directory | Commit prefix |
|---|---|---|
| github-actions | `/` | `ci` |
| gomod | `/` | `build` |
| npm | `/web` | `build` |
| docker | `/` | `build` |

GitHub Actions updates matter more here than usual: because actions are pinned
to commit SHAs, pinning without automated updates would mean never receiving
upstream fixes.

## Cryptographic dependencies are excluded from grouping

Routine updates are grouped into a single pull request to reduce noise. Certain
dependencies are deliberately excluded so they arrive individually:

- `golang.org/x/crypto`
- `filippo.io/*`
- `hash-wasm`

A grouped bump buries an individual change inside a larger diff. Every
cryptographic dependency change must be reviewed on its own, with the diff
actually read. This is the policy deferred during the workflow discussion:
**automate the noise, never automate the cryptography.**

## What a failure means

A Dependabot pull request failing CI means the update is not safe to merge as-is.
Read the upstream changelog before assuming the test is wrong.
