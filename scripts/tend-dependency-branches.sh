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
# The file lists exactly the packages that are compiled into what a browser
# receives; scripts/third-party-notices.mjs decides that set explicitly,
# because npm's dev/production split does not answer the question - Svelte is a
# devDependency and ships.
#
# So a change to this file means the shipped client changed, and that is worth
# a release. Dependabot labels its own commits `build:`, which release-please
# correctly ignores, so a bump that moves shipped code produces no release at
# all: the fix lands on main and never reaches anybody running the published
# image. Nearly happened with the net/http advisories, where a dependency bump
# was most of the fix.
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
notices=web/static/third-party-notices.txt

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

  # Nothing to regenerate where the dependency tree did not move.
  if git diff --quiet "origin/main...HEAD" -- web/package-lock.json web/package.json; then
    echo "  no change to the web dependency tree; nothing to do."
    continue
  fi

  (cd web && npm ci --ignore-scripts >/dev/null 2>&1)
  node scripts/third-party-notices.mjs >/dev/null

  # Loud rather than clever: the generator is expected to touch one path, and a
  # job holding a push credential should not quietly commit something else.
  unexpected=$(git status --porcelain -- . ':!web/node_modules' | awk -v n="$notices" '$2 != n {print $2}')
  if [ -n "$unexpected" ]; then
    echo "  the generator changed paths this does not expect, so nothing was committed:"
    printf '    %s\n' $unexpected
    git checkout --quiet -- . || true
    exit 1
  fi

  if git diff --quiet -- "$notices"; then
    echo "  the notices already match the dependency tree."
    continue
  fi

  printf '  shipped packages moved:\n'
  git --no-pager diff --no-color -- "$notices" | grep -E '^[+-][a-z@]' | sed 's/^/    /'

  git add "$notices"
  git -c user.name="github-actions[bot]" \
      -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
      commit --quiet -F - <<'MSG'
fix(deps): regenerate the notices for the shipped packages

The notices name the third-party code compiled into what a browser receives,
so a bump that moves one of those packages moves a line here. Dependabot runs
the package manager and nothing else, which is why this arrives separately.

It is a fix rather than a build change because the shipped client is what
moved, and a release is how that reaches anybody running the published image.

Signed-off-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>
MSG

  git push --quiet origin "HEAD:$branch"
  echo "  pushed."
  touched=$((touched + 1))
done <<< "$prs"

printf '\n%s branch(es) updated.\n' "$touched"
