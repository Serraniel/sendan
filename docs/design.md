# Sendan — Design

> [!NOTE]
> This document describes software that has not yet been implemented. It records
> decisions and their reasoning so that they need not be re-argued, and so that
> the cryptographic scheme can be reviewed before it is built.

## 1. Stack

**One Go binary, one container.** The server, the embedded web client, and the
command line client are produced from a single Go module.

| Component | Choice | Reasoning |
|---|---|---|
| Server | Go | Streaming multi-gigabyte transfers at constant memory is well served by Go's `io` and `net/http`. A static binary permits a `scratch`-based image with negligible CVE surface. |
| Web client | SvelteKit, `adapter-static`, TypeScript | All cryptography is client-side, so server-side rendering offers nothing. Small bundle, compatible with a strict CSP. Compiled to static assets and embedded via `embed.FS`. |
| CLI | Go | Shares the cryptographic package with the server's vector tests. Cross-compiles to linux, macOS, and Windows on amd64 and arm64 with no runtime dependency. |
| Metadata | SQLite (WAL) default, PostgreSQL optional | Rows are small. PostgreSQL is available behind an interface but is not required. |
| Blobs | Local filesystem default, S3-compatible optional | |
| Cache | None | An additional service would carry operational cost without purpose. |

### 1.1 Repository layout

| Path | Contents |
|---|---|
| `cmd/sendan` | Server entrypoint |
| `internal/crypto` | The Go half of the cryptographic scheme (spec §4–§7) |
| `internal/store` | Upload metadata: SQLite and PostgreSQL, plus a conformance suite |
| `internal/blob` | Upload ciphertext: filesystem and S3, plus crypto-shredding and a conformance suite |
| `internal/upload` | Lifecycle: expiry policy, revocation, reaping |
| `internal/config` | Environment configuration and validation |
| `internal/logging` | Structured logging with identifier redaction |
| `internal/ratelimit` | Structural abuse controls |
| `web/src/crypto` | The TypeScript half of the cryptographic scheme |
| `testdata/vectors` | Shared cross-language test vectors |
| `scripts` | Checks continuous integration runs and contributors can run directly, currently the coverage gate |

Each backend pair is held to a single conformance suite — `store/storetest` and
`blob/blobtest` — so a second backend is not a second set of assumptions.

There are exactly **two** cryptographic implementations, Go and TypeScript,
cross-validated against shared JSON test vectors in continuous integration. A
third language would mean a third implementation to keep synchronised.

`SENDAN_SERVE_UI=false` disables the embedded static handler, producing a
backend-only instance from the same binary rather than a second deployable.

## 2. Cryptographic design

> [!NOTE]
> This section gives the reasoning. The normative definition — labels, sizes,
> padding rules, and record framing — is
> [`docs/spec/wire-format-v1.md`](spec/wire-format-v1.md). Where the two
> disagree, the specification governs.

### 2.1 Scheme

Upload:

1. Generate a random 256-bit **file key (FK)**.
2. Encrypt the content with **AES-256-GCM** in
   [RFC 8188](https://www.rfc-editor.org/rfc/rfc8188) encrypted-content-encoding
   records, with a 64 KiB record size.
3. Encrypt filename, media type, and size separately under a metadata key into
   an opaque envelope.
4. Generate a random **256-bit link secret**, carried in the URL fragment:
   `https://host/d/<id>#<secret>`. The length is a quantum-resistance decision;
   see §2.4.
5. Derive a key-encryption key and wrap the file key:

   ```
   without password:  KEK = HKDF-SHA256(linkSecret, info="sendan/kek/v1")
   with password:     KEK = HKDF-SHA256(linkSecret ‖ Argon2id(password, salt),
                                        info="sendan/kek/v1")
   ```

   The server stores only the wrapped file key.

6. Derive an authentication key from the same schedule, allowing the server to
   reject an incorrect password before streaming ciphertext.

### 2.2 Choice of AES-256-GCM

WebCrypto supports AES-GCM natively with hardware acceleration, so the browser
requires no WebAssembly cipher. XChaCha20-Poly1305 would be marginally preferable
on design grounds but has no WebCrypto support, and shipping a WebAssembly cipher
to every visitor is a worse trade than using a well-implemented native primitive.

AES is defined by FIPS 197 with 128-, 192-, and 256-bit keys and a fixed 128-bit
block. There is no larger variant; 256 bits is the maximum available.

### 2.3 Password contribution to the wrapping key

A password may be folded into the key-encryption key rather than merely into a
server-verified token. This is a deliberate departure from designs that enforce
passwords as server-side policy, where an operator or a database disclosure
defeats the protection entirely.

Under this scheme a link without its password decrypts nothing, and the property
holds cryptographically rather than by policy. Wrapping also means that changing
a password re-wraps 32 bytes rather than re-encrypting the content.

Argon2id runs in the browser via `hash-wasm`. PBKDF2 is a degraded fallback, not
the default, and the interface reports which was used.

### 2.4 Quantum resistance

Sendan is symmetric-only, which determines the entire analysis.

**Shor's algorithm** breaks asymmetric cryptography — RSA, ECDH, ECDSA. Sendan
contains none. The key is never negotiated over the wire; it travels out of band
in the URL fragment. "Harvest now, decrypt later" therefore has no recorded key
agreement to attack.

**Grover's algorithm** is the only quantum attack applicable to symmetric
primitives, and it provides a quadratic speedup: an *n*-bit secret retains
approximately *n*/2 bits of security. It parallelises poorly, so this is a
conservative bound rather than a practical one.

> [!NOTE]
> There is no such thing as a "post-quantum symmetric algorithm". Post-quantum
> cryptography is a response to Shor's algorithm and concerns key exchange and
> signatures. For symmetric encryption the accepted answer is simply an adequate
> key length, and AES-256 is already it. Adding ML-KEM to this design would
> introduce complexity and new attack surface for no security benefit.

The one place the analysis has real consequences is **secret length**, and it
determines two parameters:

| Value | Size | Post-Grover | Rationale |
|---|---|---|---|
| File key | 256-bit | ~128-bit | Sufficient. |
| **Link secret** | **256-bit** | **~128-bit** | Raised from an initially considered 128 bits. |

A 128-bit link secret would retain only about 64 bits of security against
Grover's algorithm, which is not a comfortable margin for a value that is the
sole credential protecting an upload. Sendan therefore uses a 256-bit link
secret. The cost is a longer fragment — 43 base64url characters rather than 22 —
which is an acceptable price for the guarantee.

Where post-quantum primitives *are* appropriate for this project is **artefact
signing**, which protects against an adversary forging a release rather than
reading an upload. Release signatures should use a post-quantum scheme, with
SPHINCS+ preferred on conservatism grounds because its security rests only on
hash functions, or ML-DSA where tooling requires it.

> [!IMPORTANT]
> This analysis holds only while the design remains symmetric-only. Introducing
> a recipient public key — for example, sending to a registered user without
> sharing a link secret — adds a key encapsulation mechanism and with it Shor
> exposure. Such a feature must use a **hybrid** X25519 + ML-KEM-768
> construction, matching current TLS deployment, so that a weakness in either
> component alone is not sufficient to break it.

### 2.5 Absence of a cipher cascade

Layering AES with a second cipher would defend against a risk that has not
materialised, a break in AES-GCM, by doubling the quantity of code able to
contain the risk that materialises routinely, an implementation defect. TLS 1.3,
Signal, age, and WireGuard each use a single well-chosen AEAD.

### 2.6 Lessons adopted from TLS

1. **One cipher suite, no negotiation.** The majority of well-known TLS
   vulnerabilities — BEAST, CRIME, Lucky13, FREAK, Logjam, DROWN — arose from
   legacy options and downgrade negotiation rather than from broken primitives.
   No client-influenced algorithm parameter may exist. Versioning is achieved by
   incrementing a label, and migration by supporting a new version.
2. **Domain-separate every derived key**, as TLS 1.3 does with
   `HKDF-Expand-Label`. Hence `info="sendan/<purpose>/v1"`.
3. **Hybrid construction belongs in key exchange**, which is why it does not
   apply here; see §2.4.

> [!WARNING]
> **AES-GCM nonce reuse is catastrophic**: it discloses the authentication key,
> not merely one message. Nonces must be deterministic per-record counters and
> never random. RFC 8188 derives each record's nonce from the salt and sequence
> number, which is a further reason to adopt it in preference to bespoke framing.

## 3. Expiry and deletion

Three independent limits per upload — **time**, **download count**, and **manual
revocation**. Whichever is reached first applies.

- Unlimited retention requires `SENDAN_ALLOW_INFINITE_TTL=true` and is disabled
  by default.
- **Hard deletion only.** No `deleted_at` column, no soft-delete pattern, and no
  audit table keyed by file identifier.
- A background reaper **and** lazy expiry evaluated on every access, so that an
  expired upload is unreachable even if the reaper is delayed.
- **No file identifiers in logs.** Where correlation is required, log a truncated
  hash. A deletion guarantee is void if identifiers persist in access logs.
- Each blob carries a per-file server-side key stored in its database row, so
  deleting the row cryptographically shreds any block that survives on a
  copy-on-write filesystem or SSD, where overwriting is not meaningful.
- **Deleting a row is not the same as removing its bytes.** Two database
  behaviours defeat the guarantee unless handled explicitly:
  - On SQLite, a deleted row survives verbatim in the write-ahead log until a
    checkpoint retires it, and in the database file until its page is reused.
    Sendan therefore enables `secure_delete`, which zeroes freed content, and
    runs `wal_checkpoint(TRUNCATE)` after reaping and after a revocation. Both
    are load-bearing: removing either leaves the upload identifier and its
    at-rest key recoverable from disk, in the log file and the database file
    respectively.
  - On PostgreSQL, measured against version 17: a deleted row remains in the
    heap file until `VACUUM`, which Sendan runs after reaping and which does
    remove it. What persists is the write-ahead log, which retains the row until
    its segment is recycled and which PostgreSQL offers no way to truncate on
    demand. A recovered row yields the at-rest key, and so the ability to
    decrypt a blob that also survived its own deletion — the end-to-end
    ciphertext, not the content. Deletion is therefore weaker on PostgreSQL
    than on SQLite, and this is documented for operators in
    `docs/configuration.md`.

## 4. Transfer

**Upload** uses two paths, because `fetch` request streaming (`duplex: 'half'`
over HTTP/2) is supported by Chromium and not by Firefox:

- streaming `fetch` where available;
- **tus** resumable chunked upload as the baseline, which additionally provides
  resumption.

**Download** must decrypt as a stream to disk, since buffering a large file
exhausts tab memory:

- `showSaveFilePicker()` with a `WritableStream` where available;
- otherwise a **service worker** decrypting records into the response stream,
  which remains the only portable approach.

## 5. Third-party client compatibility

Adopting RFC 8188 encrypted-content-encoding and HKDF-SHA256 as the *native*
format means that compatibility with the Firefox Send protocol is largely a
matter of routing: `/api/upload` (a WebSocket in Send v3), `/api/download/:id`,
`/api/metadata/:id`, and `/api/exists/:id`. Existing clients such as
[`ffsend`](https://github.com/timvisee/ffsend) then interoperate without
modification.

Gated behind `SENDAN_SEND_COMPAT=true`, disabled by default.

> [!WARNING]
> Uploads made through compatibility endpoints must use that protocol's weaker,
> server-enforced password model, because that is what existing clients
> implement. Such uploads are **less secure** than native ones, and the interface
> must state so rather than conceal it.

## 6. Owner-held upload management

Each upload mints a random **owner token**; the server stores only its hash. The
browser retains the full management link, including the fragment secret, in
IndexedDB.

Loss of browser state means loss of access, and the server is genuinely unable to
assist. Encrypted export and import make this a deliberate choice rather than an
accident.

## 7. Transparency

The upload and download interfaces report what actually protected a given file:
cipher, key derivation function, whether a password contributed to the key, the
expiry rules in force, and whether the upload used native or compatibility
endpoints.

> [!NOTE]
> This report reflects what the delivered client code states it did. It is a
> transparency measure for well-behaved instances, not a defence against a
> hostile one, and must be worded so as not to imply otherwise.

Every instance additionally reports its running version and commit at
`/api/source` and in the client footer, satisfying AGPL §13 and making a fork
that removes the link conspicuous.

> [!WARNING]
> **Not implemented.** The binary serves only `/healthz` today; the version and
> commit are compiled in but not exposed. The endpoint is [#32](https://github.com/Serraniel/sendan/issues/32)
> and the footer [#41](https://github.com/Serraniel/sendan/issues/41). Until both
> land, an instance discloses nothing about what it is running, and the §13
> obligation above is a design commitment rather than a property of the code.

## 8. Abuse mitigation

End-to-end encryption precludes content inspection, so controls must be
structural: size caps, per-address rate limits, a short default retention period,
`X-Robots-Tag: noindex`, and optional upload authentication (token, later OIDC)
for instances that require it.

## 9. Licence

**AGPL-3.0-or-later**, with a Developer Certificate of Origin and no contributor
licence agreement.

Network copyleft is a requirement rather than a preference. GPLv3 is triggered
only by *distribution*, so an operator running weakened cryptography as a hosted
service would incur no obligation. AGPL §13 closes this gap.

Alternatives considered and rejected:

- **EUPL-1.2** — Article 5's compatibility clause permits a derivative combined
  with GPLv2 or GPLv3 code to be relicensed under those licences, neither of
  which has network copyleft. The obligation would not survive.
- **SSPL** — not OSI-approved; Debian and Fedora classify it as non-free.
- **OSL-3.0** — GPL-incompatible and effectively unused.
- **CPAL-1.0** and **RPL-1.5** — obscure, with attribution and internal-use
  triggers respectively.
