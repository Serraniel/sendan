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

### When the finding is in the standard library

`govulncheck` reports the toolchain's own packages, and the fix is a newer Go
rather than a newer dependency. `GO_VERSION` in every workflow names an exact
patch release for this reason: a version spec of `1.25` is satisfied by whatever
patch the runner already has cached, so a fixed toolchain that exists is not
necessarily the one that gets used — the scan kept failing against `1.25.12`
while `1.25.13` was available.

The cost of pinning is that it goes stale silently. The daily run is what
catches that, and bumping the pin is the response.
