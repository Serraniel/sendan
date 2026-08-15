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
| `cli-binaries` | the CLI for every target, `SHA256SUMS`, the client asset manifest, and a Sigstore signature over each of the latter two |
| `container` | multi-architecture image to GHCR with SBOM, build provenance, and a cosign signature |

### There is no release tool

Binaries and checksums come from `scripts/release-build.sh`, and release notes
from release-please. A release tool was considered and rejected
([#48](https://github.com/Serraniel/sendan/issues/48)): it would be a second
build path for artefacts the first one already produces, and two build paths
that must agree byte-for-byte is a guarantee nobody can keep.

What that buys is the reproduction procedure in
[`SECURITY.md`](../../SECURITY.md). Somebody checking a published binary needs
Go and this repository, and nothing else — every tool they would otherwise have
to install at the right version is one more thing standing between them and the
answer.

### One signature is not made here

`sendan verify` requires the client asset manifest to be signed by **two release
keys**, and both are held offline. This workflow cannot sign with it, by
design: a key this job could reach is a key that leaks when this job does, and
the manifest exists to be checkable by someone who does not trust the release
pipeline.

So a freshly tagged release is **not yet verifiable**. `sendan verify` reports
it as unsigned — a distinct answer from a pass, and from a failure. The job
summary prints the commands; the safe order is:

```sh
# 1. Reproduce what CI built, and confirm it matches. Signing CI's output
#    without this step signs whatever CI produced.
git checkout v0.5.0
(cd web && npm ci && npm run build)
./scripts/asset-manifest.sh /tmp/manifest.json

gh release download v0.5.0 -p manifest.json
diff -u /tmp/manifest.json manifest.json

# 2. Sign with both keys, and publish both signatures.
minisign -Sm manifest.json -t 'sendan v0.5.0 client asset manifest'
go run ./tools/pq-sign sign release.pqkey manifest.json

gh release upload v0.5.0 manifest.json.minisig manifest.json.slhdsa
```

The trusted comment is covered by the signature; the untrusted comment on the
first line is not, and nothing should be read from it.

Generating the keys, once:

```sh
minisign -G                              # Ed25519 -> releaseKey
go run ./tools/pq-sign generate release  # SLH-DSA -> releasePQKey
```

The public halves go in `releaseKey` and `releasePQKey` in
`cmd/sendan-cli/verify.go`, and in `docs/cli.md`. The private halves never leave
the machine that made them, and should not live in the same place as each
other: a release must satisfy both, and one attacker holding both keys is the
situation having two exists to avoid.

Changing either constant changes what every future binary will accept, so it is
a source change that goes through review like any other.

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

## Why three signatures

| Signature | Made by | Checked by | Rests on |
|---|---|---|---|
| Sigstore bundle | this workflow | `cosign verify-blob`, and the transparency log | ECDSA, and being unable to run this workflow |
| minisign | a maintainer, offline | `sendan verify`, and `minisign -Vm` | Ed25519, and a key CI never holds |
| SLH-DSA | a maintainer, offline | `sendan verify`, and `tools/pq-sign verify` | hash functions only |

They fail differently on purpose. The Sigstore one is publicly logged but
producible by anyone who can run this workflow. The minisign one survives that
but not an adversary who eventually has a quantum computer and a recorded
release. The SLH-DSA one covers exactly that case, and rests on a scheme with
much less deployment behind it, which is why it is not the only one.

A forgery has to defeat all three.
