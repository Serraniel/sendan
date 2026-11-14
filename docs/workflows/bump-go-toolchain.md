# bump-go-toolchain

## Purpose

Proposes the newest patch of the pinned Go release line, so that standard
library security fixes arrive as a pull request rather than as a red scheduled
scan somebody happens to read.

## Triggers

Daily at 06:00 UTC, and on demand. That is an hour after
[security-scan](security-scan.md), so a scan that goes red for a standard
library finding has its remedy proposed the same morning.

## What it does

`scripts/bump-go-toolchain.sh`:

1. Reads the `toolchain` directive from `go.mod`.
2. Asks `go.dev/dl` for the newest **stable patch of that same minor**.
3. Stops if they match, or if a pull request for that version is already open.
4. Resolves the manifest-list digest for `golang:<version>-alpine`, and reads
   `GOLANG_VERSION` out of the image config that digest points at. A digest
   whose image does not carry the version being adopted is refused.
5. Rewrites the nine pinned places, and refuses to commit if anything else
   changed.
6. Runs `scripts/check-toolchains.sh`.
7. Pushes `go-toolchain/<version>` and opens a pull request titled
   `Build with Go <version>`, with the commit prefixed `fix(deps):`.

`--dry-run` stops after step 6 and leaves the change in the working tree.

Running it twice proposes nothing the second time.

## What it will not do

**It does not move the minor.** A new release line changes the standard library
underneath a reproducible build, so adopting one stays a decision somebody
makes. This only ever moves the patch inside the line `go.mod` already names.

**It does not merge.** The toolchain gate verifies the change on the branch like
any other, which is the arrangement worth keeping: the check that asserts the
nine pins agree is what signs off on moving them. Read the upstream release
notes before merging — a patch release is usually security fixes, but it is
still a compiler change under a reproducible build.

## Why this is needed at all

The Go toolchain is pinned exactly, in nine places, held equal by
`scripts/check-toolchains.sh`. That is deliberate: the released binary's bytes
depend on the exact compiler, and #183 came from two Gos in one project.

Dependabot does not fill the gap. Its `gomod` ecosystem updates `require`
entries and has no opinion about the `toolchain` directive, so a standard
library advisory produced no pull request:

| Advisory | Days on `main` | Found by |
|---|---|---|
| GO-2026-6809 (#319) | 4 | a human reading a red scan |
| GO-2026-6859 (#350) | 3 | a human reading a red scan |

The scheduled scan detects the condition but names no remedy, and a pull
request cannot catch it either — the security delta reports a finding already
present on the base branch rather than failing on it, which is deliberate and
is why those issues exist. See #330 for the options that were weighed.

## Why the commit is `fix(deps):`

A toolchain patch moves code that users run. `build:` would be hidden from the
changelog and would produce no release, so the fix would land on `main` and
never reach anybody running the published image —
[release-please](release-please.md) explains how the prefixes map.

## Permissions

`contents: write` to push the branch, `pull-requests: write` to open the pull
request. There is no `setup-go` step: this reads `go.mod` as text and compares
strings in files, and installing the toolchain it is proposing would be
circular.
