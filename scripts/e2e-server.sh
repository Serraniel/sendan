#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Starts an instance for the browser tests to drive.
#
# It builds the client and embeds it, rather than serving the development
# server, because that is what the tests are for: the Content-Security-Policy,
# the single-page fallback and the service worker's scope are properties of the
# binary and of nothing else. A development server sends no policy at all, so a
# suite run against one would pass on a client no instance could serve.
set -euo pipefail

cd "$(dirname "$0")/.."

port="${SENDAN_E2E_PORT:-18091}"
data="$(mktemp -d)"
trap 'rm -rf "$data"' EXIT

(cd web && npm run --silent build)
go build -tags embedui -o "$data/sendan" ./cmd/sendan

# Deliberately permissive where a limit would only get in the way, and
# deliberately tight where a test needs it. The rate limit is off because a
# browser suite makes bursts no real user would.
#
# The default lifetime is fifteen seconds so an expiry test can watch an upload
# expire rather than waiting a day. The maximum stays generous: a lifetime
# longer than the maximum is *refused*, not clamped, so a short maximum would
# make every upload that picks an hour from the form fail - which is a
# different test failing for a reason that is not the thing under test.
export SENDAN_LISTEN=":${port}"
export SENDAN_BASE_URL="http://localhost:${port}"
export SENDAN_DATABASE="sqlite:${data}/sendan.db"
export SENDAN_STORAGE="file:${data}/blobs"
export SENDAN_RATE_LIMIT=0
export SENDAN_DEFAULT_TTL=15s
export SENDAN_MAX_TTL=720h
export SENDAN_LOG_LEVEL="${SENDAN_E2E_LOG_LEVEL:-warn}"

exec "$data/sendan"
