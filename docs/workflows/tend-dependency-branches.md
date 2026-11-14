# tend-dependency-branches

## Purpose

Keeps the generated third-party notices current on open dependency branches,
and makes a bump that changes what ships produce a release.

Two sets of notices: `web/static/third-party-notices.txt` for the npm packages
compiled into the web client, and `notices/sendan.txt` and
`notices/sendan-cli.txt` for the Go modules linked into the two released
binaries.

## Triggers

Every six hours, and on demand. `workflow_dispatch` takes an optional pull
request number to tend a single branch.

## What it does

For each open Dependabot pull request:

1. Skips it outright if the branch touches neither dependency tree —
   `web/package.json` / `web/package-lock.json`, nor `go.mod` / `go.sum`.
2. Where the npm tree moved: installs with `npm ci --ignore-scripts` and runs
   `scripts/third-party-notices.mjs`.
3. Where the Go tree moved: `go mod download` and `go run ./tools/go-notices`.
4. Commits and pushes the result if anything differs, as
   `fix(deps): regenerate the notices for what ships`.

Running it twice changes nothing the second time.

There is no `--ignore-scripts` equivalent on the Go side and none is needed:
Go has no lifecycle scripts, and `go list` does not run the code it reports on,
so the only thing executed is this repository's own generator.

### Which Go bumps produce a release

This is the part the Go side adds. Most of the module graph is not shipped —
344 modules in the graph, 34 linked into a released binary — so most Go bumps
move `go.mod` and nothing a user runs.

| The bump moves | Notices change | Prefix |
|---|---|---|
| a module linked into a binary, e.g. `tus/tusd` or `golang.org/x/crypto` | yes | `fix(deps):`, releases |
| a test-only or tool-only module, e.g. `mattn/go-isatty` | no | stays `build:`, releases nothing |

Before the Go notices existed, every Go bump looked like the second row.

## Why the notices cannot come from Dependabot

Dependabot runs the package manager and nothing else. The notices are
generated from the installed tree, and `check-notices.sh` fails when the
committed copy does not match it — correctly, because the notices are what MIT
requires to travel with the bundle, and a stale file names versions that were
not shipped.

So every npm bump that moves a shipped package arrived red on a check nobody
could have satisfied, and a person checked out the branch to regenerate one
line. That happened twice by hand before this existed. See #292.

## Why the commit is a `fix`

`scripts/third-party-notices.mjs` lists exactly the packages compiled into what
a browser receives, and decides that set explicitly — npm's dev/production
split does not answer the question, since Svelte is a devDependency whose
runtime ships. A change to this file therefore means the shipped client
changed.

Dependabot labels its own commits `build:`, which release-please correctly
treats as not user facing. On its own that means a bump which moves shipped
code produces **no release**: the change lands on `main` and never reaches
anybody running the published image. That nearly mattered — a dependency bump
was most of the fix for the `net/http` advisories in October 2026.

Changing Dependabot's prefix would not work. `commit-message.prefix` sets the
pull request title as well, and a Conventional Commit title is counted twice in
the changelog; `release-please.md` explains why. A separate commit, added here,
carries the releasable type without touching the title.

## Why it installs with `--ignore-scripts`

This job holds a token that can push. A normal install executes each
dependency's lifecycle scripts, which is a stranger's code running beside a
write credential, on a branch whose whole purpose is to raise a version number.

The generator only reads licence files out of `node_modules`, so nothing needs
to be executed. Verified by producing the same output both ways.

## What it will not do

It commits one path. If the generator touches anything else the job fails and
pushes nothing, rather than committing whatever appeared.

## What is not covered

Go dependencies. Every module linked into the released binaries ships, but
there is no generated file that records them, so nothing here can tell a bump
that changes the binary from one that only changes a test. A Go bump therefore
still produces no release. See the issue linked from #292 for the two ways to
close that, one of which would also give the binaries the licence notices they
arguably already owe.
