#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Writes the digest manifest for the built client.
#
# The manifest is what makes it possible to check that an instance serves the
# published client rather than a modified one: the bundle is the trust boundary,
# and verifying an instance reduces to verifying what it served. See
# docs/design.md §7.1, and tools/asset-manifest for why no endpoint can answer
# this instead.
#
# Written outside internal/webui/dist on purpose. Everything in that directory
# is embedded and served, and an instance serving its own manifest would be
# attesting to itself.
set -euo pipefail

cd "$(dirname "$0")/.."

out="${1:-internal/webui/manifest.json}"

if [ ! -d internal/webui/dist ]; then
  echo "asset-manifest: internal/webui/dist does not exist; build the client first"
  exit 1
fi

go run ./tools/asset-manifest -dir internal/webui/dist -out "$out" \
  ${SENDAN_VERSION:+-version "$SENDAN_VERSION"} \
  ${SENDAN_COMMIT:+-commit "$SENDAN_COMMIT"}

# Then check the result covers the build, by walking it again from here.
#
# The generator enumerates the directory, so it covers everything by
# construction - which is exactly why the check is done by something else. A
# filter added later, or a build step that writes somewhere unexpected, would
# leave an asset an attacker may replace freely, and the generator would report
# success either way.
missing=0
while IFS= read -r file; do
  path="/${file#internal/webui/dist/}"
  if ! grep -qF "\"$path\":" "$out"; then
    echo "  not covered: $path"
    missing=1
  fi
done < <(find internal/webui/dist -type f)

if [ "$missing" -ne 0 ]; then
  echo
  echo "asset-manifest: the manifest does not cover the whole build."
  echo "An asset nobody digested is one nobody can detect being replaced."
  exit 1
fi

covered=$(grep -c 'sha256-' "$out")
served=$(find internal/webui/dist -type f | wc -l)
if [ "$covered" -ne "$served" ]; then
  # More digests than files means the manifest describes something no longer
  # in the build, which a verifier would demand and an honest instance would
  # not serve.
  echo "asset-manifest: $covered digests for $served files"
  exit 1
fi

echo "asset-manifest: every one of the $served files in the build is covered."
