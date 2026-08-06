#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that the built web client loads nothing from a third party.
#
# A single external origin in the output breaks the guarantee the strict
# Content-Security-Policy exists to make, and reintroduces a third party into a
# page that performs end-to-end encryption. The policy is the enforcement; this
# is the check that says so at build time rather than in a browser console.
#
# It looks for references that cause a load, not for the text of a URL. An
# earlier version grepped every script for https:// and failed on the
# documentation links inside Svelte's own error messages - strings that are
# thrown, never fetched. A check that fires on those would be turned off within
# a week, and then it would be catching nothing at all.
set -euo pipefail

cd "$(dirname "$0")/.."

out="${1:-internal/webui/dist}"

if [ ! -d "$out" ]; then
  echo "audit: $out does not exist; the web client was not built"
  exit 1
fi
if [ -z "$(find "$out" -name '*.js' -print -quit)" ]; then
  echo "audit: $out contains no scripts; there would be nothing to audit"
  exit 1
fi

found=0

# Anything the document loads while parsing: scripts, stylesheets, images,
# fonts, frames. A relative or root-relative reference is served from this
# origin and is fine; an absolute one is not.
while IFS= read -r hit; do
  echo "  markup loads an external resource: $hit"
  found=1
done < <(grep -rInoP '(?:src|href)\s*=\s*["'"'"']https?://(?!localhost|127\.0\.0\.1)[^"'"'"']*' \
  "$out" --include='*.html' || true)

# Stylesheets pull fonts and images the same way.
while IFS= read -r hit; do
  echo "  stylesheet loads an external resource: $hit"
  found=1
done < <(grep -rInoP 'url\(\s*["'"'"']?https?://(?!localhost|127\.0\.0\.1)[^)]*' \
  "$out" --include='*.css' || true)

# A module fetched from another origin at run time. Static and dynamic import
# both, since either would execute third-party code inside the page holding the
# file key.
while IFS= read -r hit; do
  echo "  script imports from an external origin: $hit"
  found=1
done < <(grep -rInoP '(?:\bfrom\s*|\bimport\s*\(\s*)["'"'"']https?://(?!localhost|127\.0\.0\.1)[^"'"'"']*' \
  "$out" --include='*.js' || true)

if [ "$found" -ne 0 ]; then
  echo
  echo "audit: the built client would load something from a third party."
  echo "This breaks the Content-Security-Policy guarantee: see docs/design.md §8.2."
  exit 1
fi

echo "audit: the built client loads nothing from a third party."
