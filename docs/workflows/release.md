# release

## Purpose

Produces the permanent, signed, versioned artefacts users install.

## Triggers

Called by [release-please](release-please.md) when it creates a release, and on
demand with a tag, for a release that has to be rebuilt.

It is deliberately **not** triggered by the tag. A tag pushed with
`GITHUB_TOKEN` starts no workflow — GitHub refuses that so a workflow cannot
start itself — and release-please pushes with exactly that token. Left as
`on: push: tags`, this never ran for a real release: `v0.1.0` was tagged and
produced no binaries, no image and no signatures, with nothing failing to say
so.

Chaining avoids a personal access token, which would be a long-lived credential
held for one job and a second thing to rotate.

Because it is called rather than triggered, the workflow's own ref is the
caller's branch. Every checkout and every step that needs the version takes the
tag from the input instead.

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

### Signing is automatic, and what that costs

`sendan verify` requires the client asset manifest to be signed by **two release
keys**, and this workflow signs with both, from repository secrets.

That is a decision with a price attached. Releases are tagged automatically by
release-please, so a signature waiting on a person is a release that sits
unverifiable until somebody is free — and in practice, until somebody remembers.
The alternative was a manual step per release, which is a step that gets skipped.

**A key this job can reach is a key an attacker who reaches this job can use.**
None of these signatures survives a compromise of this repository. `SECURITY.md`
states that plainly rather than implying otherwise, and sets out what is bought
instead: the Sigstore signature is recorded in a public transparency log against
the run that made it, and the build is reproducible from source, so a malicious
release is discoverable by anyone, permanently.

Releases are still signed in a useful order: the manifest is produced, signed,
and only then attached, so nothing is published in a state where the signature
and the file could disagree.

The trusted comment is covered by the signature; the untrusted comment on the
first line is not, and nothing should be read from it.

Generating the keys, once:

```sh
minisign -G -W -p release.pub -s release.key   # Ed25519 -> releaseKey
go run ./tools/pq-sign generate release        # SLH-DSA -> releasePQKey
```

The public halves go in `releaseKey` and `releasePQKey` in
`cmd/sendan-cli/verify.go`, and in `docs/cli.md`.

The private halves become repository secrets:

| Secret | Contents |
|---|---|
| `SENDAN_MINISIGN_KEY` | the whole of `release.key` |
| `SENDAN_PQ_KEY` | the whole of `release.pqkey` |

`-W` on the minisign key means it carries no passphrase. That is deliberate: a
passphrase stored beside the key it unlocks, in the same secret store, protects
nothing, and a passphrase *not* stored there is a prompt — the manual step this
design exists to remove.

Keep a copy of both private keys somewhere outside GitHub. Losing them does not
break existing releases, but it means every future one is signed by a key no
published client trusts, which is a source change and a new release to fix.

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
| minisign | this workflow | `sendan verify`, and `minisign -Vm` | Ed25519, and a key a lean verifier can check |
| SLH-DSA | this workflow | `sendan verify`, and `tools/pq-sign verify` | hash functions only |

All three are made by this workflow, so all three fall to a compromise of it.
They still differ in what else they resist, which is why there are three:

- Sigstore is publicly logged, so producing one leaves a permanent record.
- minisign is checkable by `minisign -Vm` and by a client small enough to audit,
  which reading a Sigstore bundle would not be.
- SLH-DSA is the only one an adversary with a quantum computer and an archived
  release cannot forge years from now.

## The changelog the instance serves

`CHANGELOG.md` is copied into the client at build time by
`scripts/copy-changelog.mjs`, and the footer links to it.

Copied rather than committed into `web/static`: release-please rewrites the
changelog inside its own release pull request, so a committed copy would be
stale exactly there — and a check that caught it would fail on a bot pull
request that cannot run the script to fix itself.

Served by the instance rather than linked to a forge, for the same reason the
source link carries a neutral mark: `SENDAN_SOURCE_URL` is the operator's to
set and need not be a GitHub URL, so a link built from it would guess at a
layout most instances do not have. This way the changelog a visitor reads
belongs to the code answering them.

A tree with no changelog gets a short note instead, so the link resolves rather
than 404s — a missing page reads as a broken instance rather than an unreleased
one.
