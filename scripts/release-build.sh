#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Builds the command line client for every supported target, deterministically,
# and writes SHA256SUMS beside the binaries.
#
# This is the script continuous integration runs to produce a release **and**
# the script a user runs to reproduce one. That is deliberate and is the whole
# point: a reproduction procedure nobody can follow is not a procedure. If this
# needed a release tool installed, verifying a binary would mean trusting that
# tool as well, and the thing being verified is the project's trust anchor.
#
# What makes the output deterministic:
#
#   CGO_ENABLED=0      no host C toolchain, so no host in the output - and a
#                      static binary, which is what "no runtime dependency"
#                      means in practice
#   -trimpath          no absolute paths from the machine that built it
#   -buildvcs=false    no version control stamping, which differs between a
#                      clone and a tarball. It is also why the version has to
#                      be injected below rather than discovered
#   -ldflags -buildid= the build identifier is derived from the toolchain's own
#                      action graph and is not stable across environments
#   -s -w              no symbol or DWARF tables, which is smaller and removes
#                      another thing that can differ
#
# The Go version matters. Two toolchains do not produce the same bytes, so a
# reproduction has to use the one the release used; go.mod pins the language
# version and the release notes state the toolchain.
set -euo pipefail

cd "$(dirname "$0")/.."

out="${1:-dist}"

# Injected rather than discovered, because -buildvcs=false leaves nothing to
# discover. A reproduction must pass the same values; the release notes carry
# them, and they are what `sendan version` prints.
version="${SENDAN_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
commit="${SENDAN_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

# Not used by the Go toolchain, which embeds no timestamps in a binary. Exported
# because anything else in a release pipeline that does honour it should agree.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

# linux, macOS and Windows, on both architectures anybody runs.
targets=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

rm -rf "$out"
mkdir -p "$out"

echo "building sendan $version ($commit)"
echo "  toolchain: $(go version)"
echo

for target in "${targets[@]}"; do
  os="${target%%/*}"
  arch="${target##*/}"

  name="sendan-${os}-${arch}"
  [ "$os" = "windows" ] && name="${name}.exe"

  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags "-buildid= -s -w -X main.version=${version} -X main.commit=${commit}" \
      -o "$out/$name" \
      ./cmd/sendan-cli

  echo "  $name"
done

echo
# One file, sorted, so two runs produce identical text and a diff between them
# means something. The format is what sha256sum -c reads.
(cd "$out" && sha256sum sendan-* | sort -k2 > SHA256SUMS)

cat "$out/SHA256SUMS"
echo
echo "release-build: ${#targets[@]} binaries in $out/, checksums in $out/SHA256SUMS"
