# syntax=docker/dockerfile:1
#
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Serraniel and the Sendan contributors
#
# One static binary on an empty image. See docs/deployment.md.
#
# Base images are pinned by digest for the same reason the workflows pin actions
# by commit: a tag is a name somebody else can repoint, and "we built it from
# node:22-alpine" then describes nothing in particular.
#
# The builder stages run on the machine doing the building and cross-compile to
# the target. Emulating an arm64 toolchain under QEMU to produce a binary that
# CGO_ENABLED=0 lets us cross-compile directly would cost many minutes per build
# and change nothing about the output.

# ---- the web client -------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS web

WORKDIR /src/web

# Dependencies before sources, so editing a component does not reinstall them.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./

# The changelog the client serves, and the step that places it. Copied into the
# stage that builds the client rather than committed into it, because
# release-please rewrites the changelog and a committed copy would be stale
# inside its own release pull request.
COPY CHANGELOG.md /src/CHANGELOG.md
COPY scripts/copy-changelog.mjs /src/scripts/copy-changelog.mjs
# svelte.config.js writes to ../internal/webui/dist, which is where the Go build
# below expects to find it - one definition of that path, in the app's config.
RUN npm run build

# ---- the binary -----------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=web /src/internal/webui/dist ./internal/webui/dist

ARG TARGETOS
ARG TARGETARCH

# Stamped in rather than derived: -buildvcs=false is required for a
# reproducible build and removes exactly the version control information that
# would otherwise fill these in. An image that cannot say which release it is
# cannot be checked against one - `sendan verify` reads this back through
# /api/source to decide which published manifest to compare against.
ARG VERSION=dev
ARG COMMIT=unknown

# The same flags as scripts/release-build.sh, so an image and a released binary
# of the same version are the same program.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags embedui \
      -trimpath -buildvcs=false \
      -ldflags "-buildid= -s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/sendan ./cmd/sendan

# Certificate authorities, for reaching Postgres or an object store over TLS.
# An empty image has none, and the failure without them is an x509 error at the
# first connection rather than anything that names the cause.
RUN apk add --no-cache ca-certificates

# The data directory, created here because an empty image has no shell to
# create it in. Owned by the user the container runs as, so a default
# deployment can write to its volume without being told to fix permissions.
RUN mkdir -p /var/lib/sendan && chown 65532:65532 /var/lib/sendan

# ---- the image ------------------------------------------------------------
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /var/lib/sendan /var/lib/sendan
COPY --from=build /out/sendan /sendan

# Numeric, because there is no /etc/passwd here to resolve a name against. 65532
# is the convention distroless established for a non-root service account.
USER 65532:65532

# Absolute, because the defaults are relative to the working directory and a
# relative path in a container is a path that moves when the working directory
# does. Both live under the one volume, so `docker run -v` is the whole of
# persistence.
ENV SENDAN_DATABASE=sqlite:/var/lib/sendan/sendan.db \
    SENDAN_STORAGE=file:/var/lib/sendan/blobs \
    SENDAN_LISTEN=:8080

VOLUME ["/var/lib/sendan"]
EXPOSE 8080

# No shell, so this is exec form of necessity as well as of preference: signals
# reach the process directly and an interrupted container stops rather than
# waiting to be killed.
ENTRYPOINT ["/sendan"]
