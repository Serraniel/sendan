#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs every gate continuous integration runs, and reports by exit status.
#
# It exists because reading the tail of a command's output is not the same as
# checking whether it succeeded. A lint failure was pushed after `npm run lint |
# tail -1` printed the reassuring last line of a report whose exit code was 1.
# Piping discards the status; this does not.
set -uo pipefail

cd "$(dirname "$0")/.."

# Tools installed by `go install` land here and are not always on PATH.
PATH="$PATH:$(go env GOPATH)/bin"
export PATH

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
failed=0

check() {
  local name="$1"
  shift
  printf '%-34s' "$name"
  if (cd "${dir:-.}" && "$@") >"$log" 2>&1; then
    echo "ok"
  else
    echo "FAILED"
    sed 's/^/    /' "$log" | tail -25
    failed=1
  fi
}

dir=. check "go build"            go build ./...
dir=. check "go vet"              go vet ./...
dir=. check "golangci-lint"       golangci-lint run ./...
dir=. check "go test"             go test -count=1 ./...
dir=web check "biome"             npm run --silent lint
dir=web check "svelte-check"      npm run --silent check
dir=web check "vitest"            npm run --silent test:coverage
dir=web check "vite build"        npm run --silent build
dir=. check "asset audit"         ./scripts/audit-assets.sh

echo
if [ "$failed" -ne 0 ]; then
  echo "verify: something continuous integration checks would fail on."
  exit 1
fi
echo "verify: every gate continuous integration runs passes."
