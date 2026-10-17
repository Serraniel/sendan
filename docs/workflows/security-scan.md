# security-scan

## Purpose

Detects dependencies with known vulnerabilities.

## Triggers

Pull requests, daily at 05:00 UTC, and on demand.

## What it does

- **`govulncheck`** — the Go vulnerability database, reporting only
  vulnerabilities actually reachable from this code.
- **`npm-audit`** — npm advisories at high severity and above.

It asks a different question depending on why it ran.

**On a pull request:** does this change add a finding that the branch it
targets does not already have? Both sides are scanned and compared by
`scripts/security-delta.py`. A finding present on both is reported and does not
fail the change; a finding only on the proposed side does.

**On a schedule, or anywhere else:** is there a finding at all? There is
nothing to compare against, so every reachable finding fails the job — and the
`report` job then opens an issue, or comments on the open one.

## Why it is split that way

A single question conflated two facts: that a change introduces a
vulnerability, and that the branch it targets already had one. Only the first
is the change's doing, and only the first is something its author can act on.

The cost of conflating them was measured. On 15 October 2026 the scheduled scan
went red on main for ten reachable advisories in `net/http`. Nobody saw it for
two days, and in the meantime every open dependency bump inherited the failure.
Four of them were read as broken when none had changed anything. A check that is
red for reasons its reader cannot address teaches people to scroll past red,
which is worse than the advisory it was reporting.

The issue the `report` job opens is what keeps this honest. Without it,
"already on the base branch" would be a politer way of saying nobody is
looking.

## What a failure means

**On a pull request, it means this change added it.** The comparison has
already subtracted whatever the base branch carries, so a failure here names
something that was not there before: a dependency bumped into a vulnerable
version, or a code path newly reaching one.

**On the scheduled run, usually the world changed rather than the code.** A new
advisory can turn a green pipeline red without anything being committed, which
is exactly why this also runs on a schedule.

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

## The comparison itself

`scripts/security-delta.py` reads two scans and exits non-zero only on what the
second adds. It does not run the scanners: producing the scans needs two
checkouts and a toolchain, comparing them needs neither, and keeping those
apart is what makes it testable on a laptop.

Two behaviours are worth knowing:

- **Module-level `govulncheck` findings do not fail anything.** They are
  vulnerabilities in a module that is required but never called. `govulncheck`
  does not fail on them either; counting them here would make this stricter
  than the tool it is reading.
- **An unreadable baseline fails closed.** If the base scan is missing or
  malformed it is treated as clean, which makes every finding on the proposed
  side new. The alternative — assuming the base had everything — would let a
  real regression through whenever the baseline breaks.

`scripts/security-delta.test.py` covers both directions, because a comparison
that only ever passes is indistinguishable from a working one on a branch that
fixes everything. It runs in `verify.sh` and in the test workflow.
