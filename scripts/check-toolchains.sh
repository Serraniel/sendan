#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that everything which builds this project uses the same toolchains.
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
#
# Node is here for that second reason alone, and it is not hypothetical. The
# release builds the client twice - once on a runner to produce the signed asset
# manifest, once inside the Dockerfile to produce the image - and a bundler on
# two different majors emits two different sets of content-hashed filenames. In
# v0.2.0 that shipped: `sendan verify` reported the project's own image as not
# serving the published client, because it was not. See #260.
set -euo pipefail

cd "$(dirname "$0")/.."

failed=0

fail() {
  printf '%s\n' "$1"
  failed=1
}

# ---- Go -------------------------------------------------------------------

go_want=$(awk '/^toolchain /{sub(/^go/, "", $2); print $2; exit}' go.mod)
if [ -z "$go_want" ]; then
  echo "go.mod names no toolchain; the scripts have nothing to pin to."
  exit 1
fi

for file in .github/workflows/*.yml; do
  while read -r version; do
    [ "$version" = "$go_want" ] && continue
    fail "$(printf '%s installs Go %s; go.mod names %s' "$file" "$version" "$go_want")"
  done < <(awk -F'"' '/^ *GO_VERSION: /{print $2}' "$file")
done

# The build stage of the container image, which produces the released binary.
while read -r version; do
  [ "$version" = "$go_want" ] && continue
  fail "$(printf 'Dockerfile builds with Go %s; go.mod names %s' "$version" "$go_want")"
done < <(sed -n 's/^FROM .*golang:\([0-9][0-9.]*\)-.*/\1/p' Dockerfile)

# ---- Node -----------------------------------------------------------------
#
# There is no go.mod here to be the authority, so the workflows are: they build
# the client whose hashes the release publishes. Compared by major, because that
# is what the workflows name and what decides the bundler's output; a patch
# difference within a major has never moved a filename.

node_want=""
for file in .github/workflows/*.yml; do
  while read -r version; do
    major=${version%%.*}
    if [ -z "$node_want" ]; then
      node_want=$major
      continue
    fi
    [ "$major" = "$node_want" ] && continue
    fail "$(printf '%s installs Node %s; another workflow names %s' "$file" "$major" "$node_want")"
  done < <(awk -F'"' '/^ *NODE_VERSION: /{print $2}' "$file")
done

if [ -z "$node_want" ]; then
  echo "no workflow names a NODE_VERSION; there is nothing to compare the image to."
  exit 1
fi

while read -r version; do
  major=${version%%.*}
  [ "$major" = "$node_want" ] && continue
  fail "$(printf 'Dockerfile builds the client with Node %s; the workflows name %s' "$major" "$node_want")"
done < <(sed -n 's/^FROM .*node:\([0-9][0-9.]*\)-.*/\1/p' Dockerfile)

if [ "$failed" -ne 0 ]; then
  echo
  echo "The manifest and the image must come from one toolchain, or an instance"
  echo "running the published image fails the verification this project ships."
  exit 1
fi

printf 'toolchains: Go %s and Node %s everywhere.\n' "$go_want" "$node_want"
