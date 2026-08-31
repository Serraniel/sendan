#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that everything which builds this project uses the Go go.mod names.
#
# The scripts pin GOTOOLCHAIN to go.mod's toolchain directive, so anything that
# installs a different version is a second standard library in the same project
# - which is how #183 arrived: the checks ran against one Go locally and another
# in continuous integration, and the difference surfaced as a crash that looked
# like a finding about this code.
#
# The container image counts too, and for a second reason. Releases promise a
# byte-identical rebuild, and somebody reproducing one has "Go and this
# repository" to work from - so which Go built the released binary is part of
# what they need. An image on a different version makes that promise unkeepable
# quietly: everything still builds, and the bytes no longer match.
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

# The build stage of the container image, which produces the released binary.
while read -r version; do
  [ "$version" = "$want" ] && continue
  printf 'Dockerfile builds with Go %s; go.mod names %s\n' "$version" "$want"
  failed=1
done < <(sed -n 's/^FROM .*golang:\([0-9][0-9.]*\)-.*/\1/p' Dockerfile)

exit "$failed"
