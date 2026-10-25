# Compliance

Sendan is **outside the scope of the EU Cyber Resilience Act**, and this
document exists anyway.

An organisation subject to the CRA needs evidence about the software it uses,
whether or not that software's author owes anyone a declaration. Most of what
the Regulation asks a manufacturer to produce is worth producing regardless, so
this page states plainly what Sendan has, what it does not, and which parts of
the obligation land on **you** rather than on this project.

> [!NOTE]
> This is an engineering document, not legal advice. Article and Annex wording
> is paraphrased; the authority is
> [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
> as published in the Official Journal. Where this page and the Regulation
> disagree, the Regulation is right and this page is a bug.

## Why Sendan is out of scope

The chain is short and it rests on monetisation, not on licence or quality.

| Provision | What it says |
|---|---|
| Art. 2(1) | the Regulation applies to products "made available on the market" |
| Art. 3(22) | making available on the market means supply "in the course of a commercial activity, whether in return for payment or free of charge" |
| Art. 3(48) | free and open-source software is software whose source is openly shared under a licence granting all rights to access, use, modify and redistribute |
| Recital 18 | "the provision of products with digital elements qualifying as free and open-source software that are **not monetised by their manufacturers** should not be considered to be a commercial activity" |

Sendan is AGPL-3.0-or-later, so Art. 3(48) is satisfied. It is not monetised:
there is no paid edition, no paid support, no hosted service sold, and no
feature behind payment. Recital 18 adds two points that are often assumed to
cut the other way and do not — how development was financed is not the test,
and "the mere presence of regular releases should not in itself lead to the
conclusion that a product with digital elements is supplied in the course of a
commercial activity."

Sendan's maintainer is also **not an open-source software steward** under
Art. 3(14), which requires a *legal* person supporting products "intended for
commercial activities." So Art. 24 does not apply either.

## Who the manufacturer is — read this part

This is the question organisations get wrong, and getting it wrong produces a
false sense of compliance. Upstream being out of scope does not move the
obligation; it means **nobody has discharged it yet**.

| What you are doing | Your position |
|---|---|
| Running an instance for your own organisation's internal use | You are an operator, not a manufacturer. The CRA does not reach you for this; other regimes (NIS2, GDPR as controller) may |
| Running an instance as a service for other people, commercially | You are **making it available on the market**. Under Art. 3(13) and 3(22) you are the manufacturer, with the full Annex I and Annex II duties |
| Redistributing Sendan, modified or not, as part of a commercial offering | Same — **you** are the manufacturer of what you ship |
| Taking Sendan as a component into a commercial product | Same, and Recital 18's component rule means the duty is yours because Sendan is not monetised by its author |

In every one of those commercial cases the manufacturer is you. This project
cannot be your manufacturer, cannot sign your declaration of conformity, and
cannot carry your support period. What it can do is hand you the evidence
below so that less of the work is yours.

## What Sendan gives you

Everything here exists today and is independently checkable — nothing in this
table is a promise about future work.

| Artefact | Where | Supports |
|---|---|---|
| SBOM, SPDX-JSON, per architecture | BuildKit attestation on the image | Annex I Pt II(1) |
| SLSA build provenance | attestation on the image | supply-chain evidence, Art. 13(12) technical documentation |
| Signed asset manifest, three schemes | release assets | integrity of the client actually served |
| `SHA256SUMS` plus a Sigstore bundle | release assets | Annex I Pt II(7) |
| Reproducible build, verified twice per release | `scripts/release-build.sh`, `REPRODUCING.md` | the strongest available answer to "is this binary this source" |
| Coordinated vulnerability disclosure policy | [`SECURITY.md`](../SECURITY.md) | Annex I Pt II(5), Art. 24(1) |
| Single point of contact | [`SECURITY.md`](../SECURITY.md) | Annex I Pt II(6), Art. 13(17) |
| Published threat model, with the limits stated | [`SECURITY.md`](../SECURITY.md) | risk assessment input, Art. 13(2) |
| Design rationale and normative wire format | [`design.md`](design.md), [`spec/wire-format-v1.md`](spec/wire-format-v1.md) | review without reading the implementation first |
| Version and commit reported by a running instance | `/api/source` | asset inventory, and what `sendan verify` checks against |

Note that **Recital 77 does not require a manufacturer to publish its SBOM** —
it is technical documentation shown to authorities on request. Sendan publishes
one anyway, because an SBOM you cannot obtain is not evidence you can use.

### Getting the SBOM and the provenance

```sh
VERSION=0.3.3      # image tags follow the releases and carry no `v`

docker buildx imagetools inspect "ghcr.io/serraniel/sendan:$VERSION" \
  --format '{{ json .SBOM }}'

docker buildx imagetools inspect "ghcr.io/serraniel/sendan:$VERSION" \
  --format '{{ json .Provenance }}'
```

These are BuildKit attestations on the image index, not `cosign attest`
signatures, so `cosign verify-attestation` will not read them. The image
signature itself is separate and is checked as
[`deployment.md`](deployment.md) describes.

## Annex I, requirement by requirement

Honest about the gaps. A table of ticks would be useless to you.

### Part I — properties of the product

| | Requirement | State |
|---|---|---|
| 1 | cybersecurity appropriate to the risks | the threat model is published, including what it does **not** defend against |
| 2(a) | no known exploitable vulnerabilities at release | `govulncheck`, `npm audit`, CodeQL and a security-delta gate run per pull request and on a schedule |
| 2(b) | secure-by-default configuration | end-to-end encryption is unconditional and has no off switch; third-party compatibility endpoints are **off** by default; unlimited retention is **off**; a deadline or download limit is **required** by default; rate limiting is on; `SENDAN_TRUSTED_PROXIES` defaults to `0` |
| 2(c) | security updates, automatically where relevant | ⚠️ **partial by design.** Updates arrive as a new image or binary; there is no in-product auto-update. A server that silently replaces its own code is a worse property than one that does not, given the client is the trust anchor |
| 2(d) | protection from unauthorised access | ⚠️ **read carefully.** There are no accounts. The link *is* the credential and an owner token authorises deletion; the instance stores only a hash of that token. **Uploading is open to anyone who can reach the instance** — bounded by rate limits and size and retention caps, not by authentication. If you need an authenticated uploader, put it in the reverse proxy |
| 2(e) | confidentiality of stored and transmitted data | content, filename, media type and size are encrypted client-side; the server holds ciphertext and an opaque padded envelope; the decryption key never reaches it |
| 2(f) | integrity of data, commands and configuration | AEAD over every record, so modification is detected on decryption; configuration is validated at startup and the process refuses to start if it is wrong |
| 2(g) | data minimisation | no accounts, no analytics, no web fonts, no outbound requests from the client; the metadata endpoint omits the size deliberately |
| 2(h) | availability, resilience to denial of service | rate limiting and burst caps, size and retention bounds, a reaper that bounds storage growth |
| 2(i) | no negative impact on other devices or networks | the instance initiates no outbound traffic beyond its configured database and object store |
| 2(j) | limited attack surface | one static binary on an empty image — no distribution, no package manager, no shell; the client links no network dependency |
| 2(k) | exploitation mitigation | `CGO_ENABLED=0`, a strict Content Security Policy, non-root numeric UID, read-only root filesystem in the shipped compose file |
| 2(l) | recording of security-relevant activity | ⚠️ **deliberately reduced.** Structured logs cover requests and lifecycle events but carry **no file identifiers**, because an identifier in a log defeats the deletion guarantee. If your own obligations need per-object audit trails, that tension is yours to resolve and you should know about it before you deploy |
| 2(m) | secure and permanent erasure | expiry and revocation hard-delete: no orphaned blobs, no tombstone rows, no retained identifiers. Browser-held state is a single clearable store the interface describes before writing to it |

### Part II — vulnerability handling

| | Requirement | State |
|---|---|---|
| 1 | identify and document vulnerabilities and components, with a machine-readable SBOM of at least top-level dependencies | ⚠️ **the one real gap.** The image carries an SPDX-JSON SBOM; the **released binaries do not**. Tracked in [#313](https://github.com/Serraniel/sendan/issues/313), which will also produce the licence notices the linked Go modules require |
| 2 | remediate without delay; separate security from functionality updates where feasible | fixes go into the next release from the current line. ⚠️ On a 0.x line with no backports, a security fix can arrive alongside other change — see the support statement in [`SECURITY.md`](../SECURITY.md) |
| 3 | regular, effective security testing and review | 498 Go tests, cross-language cryptographic test vectors holding the Go and TypeScript implementations to each other, fuzzing, coverage floors, CodeQL, end-to-end flows, and a third-party client interoperability test per pull request |
| 4 | publicly disclose fixed vulnerabilities after an update | GitHub Security Advisories, plus the changelog each release carries |
| 5 | coordinated vulnerability disclosure policy | [`SECURITY.md`](../SECURITY.md): private reporting, 7-day acknowledgement, 90 days treated as reasonable and uncontested, reporter credited by default |
| 6 | facilitate reporting, including on third-party components; publish a contact | GitHub private reporting and email, with a PGP fingerprint |
| 7 | secure distribution of updates | signed releases, signed checksums, a signed asset manifest, a signed image, and a reproducible build so distribution is not the only thing you have to trust |
| 8 | disseminate updates without delay and free of charge, with advisory messages | releases are public and free; advisories carry the description, affected versions and remediation |

### What is absent, and why

| | |
|---|---|
| EU declaration of conformity, CE marking | not applicable — these attach to a product placed on the market. If you place it on the market, they are yours to produce |
| Independent security audit | **has not happened and has not been commissioned.** This is the single largest limit on what Sendan is ready for, and it is stated in the README and `SECURITY.md` rather than buried here |
| Declared support period with an end date | none — see [`SECURITY.md`](../SECURITY.md). An honest absence rather than a number that would not be kept |
| SBOM for the released binaries | [#313](https://github.com/Serraniel/sendan/issues/313) |

## What we will do if you ask

Within the limits of a single maintainer working outside working hours:

- **Answer compliance questions** about anything on this page, through a GitHub
  issue or the address in `SECURITY.md`.
- **Cooperate on a vulnerability** you find or receive, under the disclosure
  policy — including one in a third-party component.
- **Not invent assurances.** If something is asked for that does not exist, the
  answer will be that it does not exist, which is more useful to you than a
  qualified yes.
