#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that the committed third-party notices match the dependency tree.
#
# The notices are generated, so the risk is not that they are wrong when
# written - it is that they stay as written while a dependency is upgraded,
# added or removed underneath them. A stale notice file is worse than none: it
# names versions that were not shipped and omits code that was.
set -euo pipefail

cd "$(dirname "$0")/.."

file=web/static/third-party-notices.txt
before=$(cat "$file" 2>/dev/null || true)

node scripts/third-party-notices.mjs >/dev/null

if [ "$before" != "$(cat "$file")" ]; then
  printf 'the notices are out of date; scripts/third-party-notices.mjs has\n'
  printf 'rewritten %s - commit it.\n' "$file"
  git --no-pager diff --stat -- "$file" || true
  exit 1
fi
