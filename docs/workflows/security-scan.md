# security-scan

## Purpose

Detects dependencies with known vulnerabilities.

## Triggers

Pull requests, daily at 05:00 UTC, and on demand.

## What it does

- **`govulncheck`** — the Go vulnerability database, reporting only
  vulnerabilities actually reachable from this code.
- **`npm-audit`** — npm advisories at `--audit-level=high`.

## What a failure means

**Usually the world changed, not your code.** A new advisory can turn a green
pipeline red without anything being committed, which is exactly why this also
runs on a schedule.

`govulncheck` findings are high signal because reachability analysis filters out
vulnerabilities in code paths this project never executes. Treat a finding as
real until shown otherwise.

The fix is normally a dependency bump. Where no fixed version exists, assess
whether the vulnerable path is reachable in Sendan and record the reasoning in
the issue.
