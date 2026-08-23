#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that continuous integration installs the toolchain go.mod names.
#
# The scripts pin GOTOOLCHAIN to go.mod's toolchain directive, so a workflow
# that installs a different version is a second standard library in the same
# project - which is how #183 arrived: the checks ran against one Go locally and
# another in CI, and the difference surfaced as a crash that looked like a
# finding about this code.
set -euo pipefail

cd "$(dirname "$0")/.."

want=$(awk '/^toolchain /{sub(/^go/, "", $2); print $2; exit}' go.mod)
if [ -z "$want" ]; then
  echo "go.mod names no toolchain; the scripts have nothing to pin to."
  exit 1
fi

failed=0
for file in .github/workflows/*.yml; do
  while read -r version; do
    [ "$version" = "$want" ] && continue
    printf '%s installs Go %s; go.mod names %s\n' "$file" "$version" "$want"
    failed=1
  done < <(awk -F'"' '/^ *GO_VERSION: /{print $2}' "$file")
done

exit "$failed"
