#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that the committed notices for the Go binaries match what they link.
#
# Same reasoning as check-notices.sh, which does this for the npm packages in
# the web client: the notices are generated, so the risk is not that they are
# wrong when written - it is that they stay as written while a dependency is
# upgraded, added or removed underneath them. A stale notice file is worse than
# none, because it names versions that were not shipped and omits code that
# was. See #313.
set -euo pipefail

cd "$(dirname "$0")/.."

files=(notices/sendan.txt notices/sendan-cli.txt)

before=$(mktemp -d)
trap 'rm -rf "$before"' EXIT
for file in "${files[@]}"; do
  [ -f "$file" ] && cp "$file" "$before/$(basename "$file")"
done

go run ./tools/go-notices >/dev/null

stale=0
for file in "${files[@]}"; do
  if ! cmp -s "$before/$(basename "$file")" "$file" 2>/dev/null; then
    printf '%s is out of date.\n' "$file"
    stale=1
  fi
done

if [ "$stale" -ne 0 ]; then
  printf '\ntools/go-notices has rewritten it - commit the result.\n'
  git --no-pager diff --stat -- notices || true
  exit 1
fi

# The generator reads the module set without the embedui build tag, because the
# tag embeds internal/webui/dist, which is generated and git-ignored - with the
# tag the generator would not run on a fresh checkout. That is only sound while
# the tag adds no module of its own, so where the assets are present, check it.
if [ -d internal/webui/dist ]; then
  tagged=$(go list -deps -tags embedui -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/sendan \
    | grep -v '^$' | sort -u)
  plain=$(go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./cmd/sendan \
    | grep -v '^$' | sort -u)
  if [ "$tagged" != "$plain" ]; then
    printf 'the embedui build tag changes which modules the server links:\n'
    diff <(printf '%s\n' "$plain") <(printf '%s\n' "$tagged") || true
    printf '\nthe notices are generated without that tag, so they would now be\n'
    printf 'incomplete - tools/go-notices has to learn about it.\n'
    exit 1
  fi
  echo "go notices: current, and the embedui tag adds no module."
else
  echo "go notices: current. (internal/webui/dist absent, so the embedui tag was not compared.)"
fi
