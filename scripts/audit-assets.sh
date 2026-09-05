#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that the built web client can run under the policy it is served with.
#
# Two things are checked, both of which the Content-Security-Policy enforces at
# run time and neither of which any test that does not execute the page can see.
#
# First, that nothing is loaded from a third party. A single external origin in
# the output breaks the guarantee the policy exists to make, and reintroduces a
# third party into a page that performs end-to-end encryption.
#
# Second, that nothing depends on an inline style. style-src 'self' carries no
# 'unsafe-inline', and style-src-attr falls back to style-src, so a style
# attribute is refused - silently, since a blocked style is not a broken page.
# The development server sends no policy, so this fails only on a real instance,
# and only as something rendering wrongly rather than as an error. A progress
# bar whose width is set inline is exactly this: correct everywhere it is
# looked at, and empty everywhere it matters.
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

external=$found

# A style attribute in the shell. Svelte extracts component <style> blocks into
# a stylesheet, which is served from this origin and is fine; an attribute is
# not, whether it was written by hand or produced by a style: directive.
while IFS= read -r hit; do
  echo "  markup carries an inline style, which the policy refuses: $hit"
  found=1
done < <(grep -rInoP '<[^>]+\sstyle\s*=\s*["'"'"']' "$out" --include='*.html' || true)

# The same thing at run time. setAttribute("style", …) and cssText are refused
# for the same reason; assigning an individual property such as style.width is
# not, so it is deliberately not matched here.
while IFS= read -r hit; do
  echo "  script sets an inline style, which the policy refuses: $hit"
  found=1
done < <(grep -rInoP '(?:setAttribute\(\s*["'"'"']style["'"'"']|\.style\.cssText\s*=)' \
  "$out" --include='*.js' || true)

# And in the bundles' template text, which is where a framework keeps its own
# markup. This is the gap that let SvelteKit's route announcer reach a browser:
# the check above reads *.html, and the announcer is a string inside a *.js.
#
# These are not failures by themselves - the server hashes what it finds, so
# the policy is correct whatever the framework emits. What matters is that the
# set stays known: a new one is a question about whether it should exist,
# answered by somebody rather than by the build.
styles=$(grep -rhoP '(?<=style=")[^"]*' "$out" --include='*.js' | sort -u || true)
count=$(printf '%s' "$styles" | grep -c . || true)
if [ "$count" -gt 1 ]; then
  echo "  the bundles carry $count distinct inline style attributes, expected 1:"
  printf '%s\n' "$styles" | sed 's/^/    /'
  echo "  each is hashed into the policy; review whether it belongs there."
  found=1
fi

if [ "$found" -ne 0 ]; then
  echo
  if [ "$external" -ne 0 ]; then
    echo "audit: the built client would load something from a third party."
  else
    echo "audit: the built client would be rendered wrongly by its own policy."
  fi
  echo "See docs/design.md §8.2 for the policy this checks against."
  exit 1
fi

if [ "$count" -eq 0 ]; then
  echo "audit: the built client loads nothing external and needs no inline style."
else
  echo "audit: the built client loads nothing external; its $count inline style" \
       "attribute is hashed into the policy."
fi
