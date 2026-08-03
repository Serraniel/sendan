#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Enforces the per-package coverage floors in .coverage-floors.
#
# A floor is a ratchet rather than a target: it sits just below the coverage
# actually achieved, so a change that reduces coverage fails rather than being
# noticed later. When coverage rises, raise the floor in the same pull request.
set -euo pipefail

cd "$(dirname "$0")/.."

floors=.coverage-floors
[ -f "$floors" ] || { echo "coverage: $floors is missing"; exit 1; }

# The store and blob floors assume both alternative backends run, which needs
# the service containers. Without them those packages cover only half their
# code, and a contributor would see a failure that is not their fault.
if [ -z "${SENDAN_TEST_POSTGRES:-}" ] || [ -z "${SENDAN_TEST_S3:-}" ]; then
  printf 'note: SENDAN_TEST_POSTGRES or SENDAN_TEST_S3 is unset.\n'
  printf '      The floors assume both are available, as they are in CI.\n'
  printf '      internal/store and internal/blob will fall short without them.\n\n'
fi

failed=0
missing=0
summary=""

while read -r pkg want; do
  case "$pkg" in ''|'#'*) continue ;; esac

  if [ ! -d "$pkg" ]; then
    printf '  %-22s package does not exist; remove it from %s\n' "$pkg" "$floors"
    missing=1
    continue
  fi

  out=$(go test -cover -count=1 "./$pkg/" 2>&1) || {
    printf '  %-22s TESTS FAILED\n%s\n' "$pkg" "$out"
    failed=1
    continue
  }

  got=$(printf '%s' "$out" | grep -oE 'coverage: [0-9.]+%' | grep -oE '[0-9.]+' | head -1)
  if [ -z "$got" ]; then
    printf '  %-22s no coverage reported\n' "$pkg"
    failed=1
    continue
  fi

  if awk -v g="$got" -v w="$want" 'BEGIN { exit !(g + 0 < w + 0) }'; then
    printf '  %-22s %6s%%  BELOW FLOOR of %s%%\n' "$pkg" "$got" "$want"
    failed=1
  else
    printf '  %-22s %6s%%  (floor %s%%)\n' "$pkg" "$got" "$want"
  fi

  # Coverage well above its floor means the floor is stale. Say so, so the
  # ratchet is actually turned rather than drifting into decoration.
  if awk -v g="$got" -v w="$want" 'BEGIN { exit !(g + 0 > w + 5) }'; then
    summary="${summary}  ${pkg} is ${got}% against a floor of ${want}%; consider raising it\n"
  fi
done < "$floors"

# A package with no floor is a package nobody is holding to anything.
for dir in internal/*/; do
  pkg="${dir%/}"
  case "$pkg" in */storetest|*/blobtest) continue ;; esac
  ls "$pkg"/*.go >/dev/null 2>&1 || continue
  if ! grep -qE "^${pkg}[[:space:]]" "$floors"; then
    printf '  %-22s has no floor in %s\n' "$pkg" "$floors"
    missing=1
  fi
done

if [ -n "$summary" ]; then
  printf '\nFloors that could be raised:\n'
  # %b, never "$summary" directly: the text contains per-cent signs, which
  # printf would read as format specifiers.
  printf '%b' "$summary"
fi

if [ "$missing" -ne 0 ]; then
  printf '\ncoverage: %s does not match the packages that exist\n' "$floors"
  exit 1
fi
if [ "$failed" -ne 0 ]; then
  printf '\ncoverage: at least one package is below its floor\n'
  exit 1
fi
printf '\ncoverage: every package meets its floor\n'
