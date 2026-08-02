# release

## Purpose

Produces the permanent, signed, versioned artefacts users install.

## Triggers

Tags matching `v*` — created by merging the release pull request from
[release-please](release-please.md).

## What it does

| Job | Output |
|---|---|
| `verify-reproducible` | builds the CLI twice and requires the two to be byte-identical |
| `binaries` | GoReleaser cross-platform binaries, checksums, Sigstore signatures, GitHub Release |
| `container` | multi-architecture image to GHCR with SBOM, build provenance, and a cosign signature |

### Image tags

```
post-1.0    :1.4.2   :1.4   :1   :latest   :sha-abc1234
pre-1.0     :0.1.0   :0.1         :latest   :sha-abc1234
```

The bare major tag is suppressed below `v1`. Under SemVer a `0.x` minor bump may
break compatibility, so a moving `:0` tag would silently break operators.
`:latest` follows the newest stable release and never a pre-release.

## What a failure means

**No release was published.** Nothing is partially released; fix the cause and
re-tag.

`verify-reproducible` failing is the serious one. It means two builds of
identical source produced different binaries, so users cannot verify that a
published binary corresponds to this source. Since the CLI is the project's trust
anchor — the answer to a malicious instance serving modified client code — an
unreproducible build undermines a security guarantee the project makes publicly.
Do not bypass this job.

## Known gap

Sigstore signing is ECDSA-based and therefore exposed to Shor's algorithm. A
post-quantum signature, SPHINCS+ preferred for resting only on hash functions,
is tracked in issue #60 and is not yet implemented.
