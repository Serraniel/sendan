#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Proposes the newest patch of the pinned Go release line.
#
# # Why this exists
#
# The Go toolchain is pinned in nine places and `check-toolchains.sh` holds them
# equal. That pin is load-bearing: the released binary's bytes depend on the
# exact compiler, and #183 came from two Gos in one project. Nothing here wants
# to loosen it.
#
# What was missing is anything that *moves* it. Dependabot's gomod ecosystem
# updates `require` entries and does not propose `toolchain` directive patches,
# so a standard library advisory produced no pull request at all. Twice:
# GO-2026-6809 sat on main for four days (#319), and GO-2026-6859 for three
# (#350). Both were found by a human reading a red scheduled scan, which is a
# discovery mechanism, not a remedy. See #330.
#
# # What it will and will not do
#
# It moves the patch inside the pinned minor and nothing else. A minor is a
# deliberate choice - a new release line changes the standard library under a
# reproducible build - so this never proposes one, and a Go minor still arrives
# the way it does today, by somebody deciding to adopt it.
#
# It opens a pull request. It does not merge one. The toolchain gate then
# verifies the change on the branch like any other, which is the point: the
# thing that asserts the nine places agree is the thing that signs off on
# moving them.
#
# # Why the digest is checked against the image's own config
#
# The Dockerfile pins `golang:<version>-alpine` by digest, so this has to
# resolve a new one, and a digest is exactly the kind of value that is easy to
# copy from the wrong place. Rather than trust the tag, it reads GOLANG_VERSION
# out of the image config the digest points at and refuses to write a digest
# whose image does not carry the version being adopted.
set -euo pipefail

cd "$(dirname "$0")/.."

dry_run=0
case "${1:-}" in
  --dry-run) dry_run=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }

# Nothing is rewritten on a tree that already has modifications. This edits
# nine tracked files and has to be able to tell its own change from everything
# else; it also used to recover by discarding the rewrite, and "discard what is
# not mine" is not a thing a script can do safely on somebody's working tree.
if ! git diff --quiet; then
  say "the working tree has uncommitted changes to tracked files:"
  git diff --name-only | sed 's/^/  /'
  say ""
  say "commit, stash or discard them first - this needs to be able to tell its"
  say "own rewrite from everything else."
  exit 1
fi

# ---- what is pinned now ---------------------------------------------------

current=$(sed -n 's/^toolchain go\([0-9][0-9.]*\)$/\1/p' go.mod)
if [ -z "$current" ]; then
  say "go.mod names no toolchain directive; there is nothing to move."
  exit 1
fi

line=${current%.*}          # 1.27.3 -> 1.27
say "pinned: Go $current (release line $line)"

# ---- the newest patch of that line ----------------------------------------
#
# go.dev/dl is the authority on what exists. Only stable releases, only this
# minor, and compared numerically so that 1.27.10 sorts above 1.27.9.

latest=$(curl -fsS 'https://go.dev/dl/?mode=json&include=all' | python3 -I -c '
import json, sys

line = sys.argv[1]
best = None
for release in json.load(sys.stdin):
    if not release.get("stable"):
        continue
    version = release["version"].removeprefix("go")
    parts = version.split(".")
    if len(parts) != 3 or f"{parts[0]}.{parts[1]}" != line:
        continue
    try:
        patch = int(parts[2])
    except ValueError:
        continue
    if best is None or patch > best[0]:
        best = (patch, version)
print(best[1] if best else "")
' "$line")

if [ -z "$latest" ]; then
  say "go.dev/dl lists no stable release on the $line line; refusing to guess."
  exit 1
fi

say "newest on that line: Go $latest"

if [ "$latest" = "$current" ]; then
  say "already on the newest patch of the line; nothing to propose."
  exit 0
fi

branch="go-toolchain/$latest"

# ---- do not re-propose what is already proposed ---------------------------

if command -v gh >/dev/null && [ "$dry_run" -eq 0 ]; then
  if gh pr list --state open --head "$branch" --json number \
      --jq 'length' 2>/dev/null | grep -qv '^0$'; then
    say "a pull request for Go $latest is already open; nothing to do."
    exit 0
  fi
fi

# ---- resolve the image digest, and check it serves that Go ----------------

digest_for() {
  local tag="$1" token
  token=$(curl -fsS \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/golang:pull" \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')

  # The manifest *list* digest, because the Dockerfile builds for more than one
  # architecture and a per-architecture digest would pin away the others.
  curl -fsS -o /dev/null -D - \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    "https://registry-1.docker.io/v2/library/golang/manifests/$tag" \
    | awk 'tolower($1)=="docker-content-digest:"{print $2}' | tr -d '\r'
}

go_version_in() {
  local reference="$1" token
  token=$(curl -fsS \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/golang:pull" \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')

  # index -> a linux/amd64 manifest -> its config blob, whose Env carries
  # GOLANG_VERSION. One architecture is enough: the question is which Go the
  # tag resolved to, not whether the arches differ.
  local manifest
  manifest=$(curl -fsS \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    "https://registry-1.docker.io/v2/library/golang/manifests/$reference" \
    | python3 -I -c '
import json, sys
index = json.load(sys.stdin)
for entry in index.get("manifests", []):
    platform = entry.get("platform", {})
    if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
        print(entry["digest"])
        break
')
  [ -n "$manifest" ] || return 1

  local config
  config=$(curl -fsS \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "https://registry-1.docker.io/v2/library/golang/manifests/$manifest" \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["config"]["digest"])')
  [ -n "$config" ] || return 1

  curl -fsS -L \
    -H "Authorization: Bearer $token" \
    "https://registry-1.docker.io/v2/library/golang/blobs/$config" \
    | python3 -I -c '
import json, sys
config = json.load(sys.stdin)
for variable in config.get("config", {}).get("Env", []):
    if variable.startswith("GOLANG_VERSION="):
        print(variable.split("=", 1)[1])
        break
'
}

tag="$latest-alpine"
digest=$(digest_for "$tag")
case "$digest" in
  sha256:*) ;;
  *) say "could not resolve a digest for golang:$tag; nothing was changed."; exit 1 ;;
esac

served=$(go_version_in "$digest" || true)
if [ "$served" != "$latest" ]; then
  say "golang:$tag at $digest reports GOLANG_VERSION=${served:-<unknown>}, not $latest."
  say "refusing to write a digest whose image does not carry the version being adopted."
  exit 1
fi
say "image: golang:$tag at $digest, serving Go $served"

# ---- rewrite the nine places ----------------------------------------------

sed -i "s/^toolchain go$current\$/toolchain go$latest/" go.mod
sed -i "s/GO_VERSION: \"$current\"/GO_VERSION: \"$latest\"/" .github/workflows/*.yml
sed -i -E "s#golang:${current//./\\.}-alpine@sha256:[0-9a-f]{64}#golang:$tag@$digest#" Dockerfile

# Loud rather than clever, for the same reason tend-dependency-branches.sh is:
# this runs with a credential that can push, and a rewrite that touched
# something unexpected should stop rather than be committed.
#
# `git diff --name-only` rather than `git status --porcelain`: the question is
# what the rewrite changed, and status also lists untracked files, which this
# did not create. The workflow names carry digits - e2e-test.yml - so the
# pattern has to admit them.
unexpected=$(git diff --name-only \
  | grep -vE '^(go\.mod|Dockerfile|\.github/workflows/[a-z0-9-]+\.yml)$' || true)
if [ -n "$unexpected" ]; then
  say "the rewrite touched paths this does not expect, so nothing was committed:"
  printf '  %s\n' $unexpected
  # Only the paths this wrote. The tree was clean on entry, so this restores it
  # without reaching for `git checkout -- .`, which would discard anything else
  # that happened to be there.
  git checkout -- go.mod Dockerfile .github/workflows || true
  exit 1
fi

if git diff --quiet; then
  say "every pin already reads $latest, but go.mod said $current; nothing to commit."
  exit 1
fi

say ""
say "changed:"
git --no-pager diff --no-color --stat | sed 's/^/  /'

# ---- the gate verifies the change -----------------------------------------

say ""
./scripts/check-toolchains.sh

if [ "$dry_run" -eq 1 ]; then
  say ""
  say "--dry-run, so the working tree holds the change and nothing was pushed."
  exit 0
fi

# ---- propose it -----------------------------------------------------------

git checkout --quiet -B "$branch"
git add go.mod Dockerfile .github/workflows
git -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -F - <<MSG
fix(deps): build with Go $latest

Go $latest is the newest patch of the $line line this project pins. The patch
is where standard library security fixes arrive, and nothing else proposes
them: Dependabot's gomod ecosystem updates require entries, not the toolchain
directive, so these bumps had been arriving only after a scheduled scan went
red. See #330.

The release line is unchanged. This moves the patch inside $line and nothing
else, so the standard library a reproducible build depends on moves by exactly
the amount upstream calls a patch.

The Dockerfile digest was resolved for golang:$tag and checked against that
image's own GOLANG_VERSION before being written.

Signed-off-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>
MSG

git push --quiet --force-with-lease origin "HEAD:$branch"

gh pr create \
  --head "$branch" \
  --title "Build with Go $latest" \
  --body "$(cat <<BODY
Go **$latest** is the newest patch of the \`$line\` line this project pins, and \`go.mod\` named $current.

Raised by \`scripts/bump-go-toolchain.sh\`, because nothing else proposes these. Dependabot's \`gomod\` ecosystem updates \`require\` entries, not the \`toolchain\` directive, so a standard library advisory produced no pull request — GO-2026-6809 sat on \`main\` for four days (#319) and GO-2026-6859 for three (#350), both found by a human reading a red scheduled scan. See #330.

**The release line does not move.** Only the patch inside \`$line\`, so the standard library a reproducible build rests on moves by exactly what upstream calls a patch.

The \`Dockerfile\` digest was resolved for \`golang:$tag\` and then checked against that image's own \`GOLANG_VERSION\`, so the digest and the version it claims to serve agree.

\`check-toolchains.sh\` ran before this was pushed and will run again here, which is the intended arrangement: the check that asserts the nine pins agree is what signs off on moving them.

**Read the release notes before merging.** A patch release is usually security fixes, but this is still a compiler change under a reproducible build.
BODY
)" || say "the branch is pushed; opening the pull request failed."

say ""
say "proposed Go $latest on $branch."
