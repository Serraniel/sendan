#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Pins the Go toolchain to the one named in go.mod, for the script that sources
# this.
#
# The `toolchain` directive is a minimum rather than a pin: a machine whose Go
# has moved ahead of it keeps using the newer one. That is usually harmless and
# occasionally not - a linter built against an older standard library crashes
# while parsing a newer one, and the crash arrives looking like a finding about
# this code rather than about the toolchain.
#
# Setting GOTOOLCHAIN to an exact version is what actually pins it. Reading that
# version from go.mod keeps one source of truth: the alternative is the same
# number written into every script, drifting one at a time.
#
# A GOTOOLCHAIN already set is left alone. Continuous integration sets it to
# `local` after installing an exact version, and overriding that would make the
# job fetch a second copy of a toolchain it already has - so the workflows and
# go.mod are held to the same version by a check instead.
#
# Nothing is downloaded on a machine that already has the version. On one that
# does not, Go fetches it, which is the intended behaviour rather than a cost:
# checks that run against a different standard library are not the same checks.

if [ -z "${GOTOOLCHAIN:-}" ]; then
  # Read from the working directory: every caller changes to the repository
  # root before sourcing this, which is also why it is sourced by a path
  # relative to that root rather than to $0.
  _toolchain=$(awk '/^toolchain /{print $2; exit}' go.mod)
  if [ -n "$_toolchain" ]; then
    export GOTOOLCHAIN="$_toolchain"
  fi
  unset _toolchain
fi
