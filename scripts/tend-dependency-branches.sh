#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Brings the generated third-party notices up to date on open dependency
# branches, and marks the ones that changed what ships.
#
# # Why this exists
#
# check-notices.sh regenerates web/static/third-party-notices.txt and fails if
# the committed copy differs. That check is right: the notices are what MIT
# requires to travel with the bundle, and a stale file names versions that were
# not shipped. But Dependabot runs the package manager and nothing else, so
# every npm bump that moves a shipped package arrives red on a check nobody
# could have satisfied - and somebody then checks out the branch, installs,
# regenerates and pushes one line. That happened twice by hand before this
# existed. See #292.
#
# # The second thing it does
#
# The files list exactly the third-party code compiled into what users run.
# scripts/third-party-notices.mjs decides that set for the web client, because
# npm's dev/production split does not answer the question - Svelte is a
# devDependency and ships. tools/go-notices decides it for the two released
# binaries, by asking the Go toolchain what each one links.
#
# So a change to one of these files means what ships changed, and that is worth
# a release. Dependabot labels its own commits `build:`, which release-please
# correctly ignores, so a bump that moves shipped code produces no release at
# all: the fix lands on main and never reaches anybody running the published
# image. Nearly happened with the net/http advisories, where a dependency bump
# was most of the fix.
#
# On the Go side this is also the only thing that can tell the two kinds of
# bump apart. A module that only a test or a tool imports moves go.mod and
# nothing else; a module linked into a binary moves a notices file too. Before
# these files existed, every Go bump looked the same and every one released
# nothing. See #313.
#
# The commit added here carries `fix(deps):` instead, which does produce one.
# Changing Dependabot's own prefix would not work: it sets the pull request
# title too, and a Conventional Commit title is counted twice in the changelog
# - docs/workflows/release-please.md says why.
#
# # Why it installs with --ignore-scripts
#
# This runs with a token that can push. Installing a dependency normally
# executes that dependency's lifecycle scripts, which is a stranger's code
# running next to a write credential on a branch that exists to raise a version
# number. The generator only reads licence files out of node_modules, so
# nothing has to be executed for it to work - verified by producing the same
# output both ways.
set -euo pipefail

cd "$(dirname "$0")/.."

only="${1:-}"
web_notices=web/static/third-party-notices.txt
go_notices=(notices/sendan.txt notices/sendan-cli.txt)

if ! command -v gh >/dev/null; then
  echo "gh is not available; this needs it to find the open branches."
  exit 1
fi

if [ -n "$only" ]; then
  prs=$(gh pr view "$only" --json number,headRefName,author \
    --jq 'select(.author.login == "app/dependabot") | "\(.number) \(.headRefName)"')
  [ -n "$prs" ] || { echo "#$only is not an open Dependabot pull request."; exit 1; }
else
  prs=$(gh pr list --author "app/dependabot" --state open \
    --json number,headRefName --jq '.[] | "\(.number) \(.headRefName)"')
fi

if [ -z "$prs" ]; then
  echo "no open dependency branches."
  exit 0
fi

touched=0
while read -r number branch; do
  [ -n "$branch" ] || continue
  printf '\n#%s %s\n' "$number" "$branch"

  git fetch --quiet origin "$branch"
  git checkout --quiet -B "$branch" "origin/$branch"

  # Which tree moved decides which generator runs. A branch that touches
  # neither has nothing to regenerate.
  web_moved=0
  go_moved=0
  git diff --quiet "origin/main...HEAD" -- web/package-lock.json web/package.json || web_moved=1
  git diff --quiet "origin/main...HEAD" -- go.mod go.sum || go_moved=1

  if [ "$web_moved" -eq 0 ] && [ "$go_moved" -eq 0 ]; then
    echo "  no change to either dependency tree; nothing to do."
    continue
  fi

  expected=()
  if [ "$web_moved" -eq 1 ]; then
    (cd web && npm ci --ignore-scripts >/dev/null 2>&1)
    node scripts/third-party-notices.mjs >/dev/null
    expected+=("$web_notices")
  fi
  if [ "$go_moved" -eq 1 ]; then
    # Go has no equivalent of a lifecycle script, and `go list` does not run
    # the code it reports on, so there is no --ignore-scripts to reach for
    # here: the only thing executed is this repository's own generator.
    go mod download
    go run ./tools/go-notices >/dev/null
    expected+=("${go_notices[@]}")
  fi

  # Loud rather than clever: the generators are expected to touch those paths
  # and no others, and a job holding a push credential should not quietly
  # commit something else.
  unexpected=$(git status --porcelain -- . ':!web/node_modules' | awk '{print $2}' \
    | grep -vxF "$(printf '%s\n' "${expected[@]}")" || true)
  if [ -n "$unexpected" ]; then
    echo "  a generator changed paths this does not expect, so nothing was committed:"
    printf '    %s\n' $unexpected
    git checkout --quiet -- "${expected[@]}" || true
    exit 1
  fi

  if git diff --quiet -- "${expected[@]}"; then
    echo "  the notices already match the dependency trees."
    continue
  fi

  printf '  what ships moved:\n'
  git --no-pager diff --no-color -- "${expected[@]}" | grep -E '^[+-][a-zA-Z@]' | sed 's/^/    /' | head -40

  git add "${expected[@]}"
  git -c user.name="github-actions[bot]" \
      -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
      commit --quiet -F - <<'MSG'
fix(deps): regenerate the notices for what ships

The notices name the third-party code compiled into what users run: the web
client a browser receives, and the modules linked into the released binaries.
A bump that moves one of those moves a line here, and Dependabot runs the
package manager and nothing else, which is why this arrives separately.

It is a fix rather than a build change because what ships is what moved, and a
release is how that reaches anybody running the published image or binary.

A bump that moves only a test-only or tool-only dependency changes nothing
here and stays a build change. Telling those two apart is the point.

Signed-off-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>
MSG

  git push --quiet origin "HEAD:$branch"
  echo "  pushed."
  touched=$((touched + 1))
done <<< "$prs"

printf '\n%s branch(es) updated.\n' "$touched"
