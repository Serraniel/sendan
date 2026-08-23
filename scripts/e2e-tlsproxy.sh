#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Terminates TLS in front of the test instance, so a browser can speak HTTP/2.
#
# The streaming upload path needs request streaming, request streaming needs
# HTTP/2, and a browser only has HTTP/2 over TLS. The Sendan binary serves plain
# HTTP and expects a proxy in front, so without this the streaming path is
# unreachable from a browser and would go untested.
set -euo pipefail

cd "$(dirname "$0")/.."

# Runs against the toolchain go.mod names, not whatever is installed. Sourced
# by a path relative to the repository root, because the cd above has already
# moved there and $0 no longer resolves from here.
# shellcheck source=scripts/go-toolchain.sh
. ./scripts/go-toolchain.sh

data="$(mktemp -d)"
trap 'rm -rf "$data"' EXIT

go build -o "$data/tlsproxy" ./tools/e2e-tlsproxy

exec "$data/tlsproxy" \
  -listen ":${SENDAN_E2E_TLS_PORT:-18191}" \
  -upstream "http://localhost:${SENDAN_E2E_PORT:-18091}"
