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
| `internal/httpapi` | HTTP surface and the middleware every response passes through |
| `internal/webui` | Serving the embedded web client |
| `web` | The client itself: SvelteKit, and the TypeScript half of the scheme |
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

Argon2id runs in the browser via `hash-wasm`, and it is the only password
stretching function. There is no PBKDF2 fallback, and there must not be one.

> [!IMPORTANT]
> **A choice of key derivation function would be a downgrade the instance could
> make.** The parameters travel in the upload's metadata, which the instance
> serves; if the function travelled with them, an instance could name a weaker
> one and a client would comply. That is spec §13 invariant 1 — no algorithm is
> ever selected by input a client did not fix — applied to the one place it
> would be most tempting to relax it. The wire format fixes Argon2id in §4, and
> the shared test vectors fix it in both implementations.
>
> The *parameters* are per-upload, and are stored so they can be raised later
> without invalidating existing links. The interface reports the ones an upload
> actually used, not the current defaults: an old link is protected by what it
> was created with, and saying otherwise would overstate it.

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

> [!NOTE]
> This section is the reasoning. The endpoint reference — paths, methods, status
> codes and what each returns — is [`docs/api.md`](api.md).


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


### 4.0 Storing an upload

An upload arrives in chunks so it can be resumed, which means the blob layer has
to accept writes at an offset rather than only whole blobs. `WriteChunk`,
`Length` and `Finish` describe that on both backends, and a partial upload is
not a blob: `Open` reports it as absent until `Finish`, because what a
half-written upload decrypts to is not what the uploader sent.

**Offsets are checked, not trusted.** A resuming client reports where it
believes it stopped. Writing at a position that does not match what is stored
would leave a gap or an overlap — content that decrypts to nothing from the
point of failure onwards, discovered by the recipient rather than by the server.
A mismatch is a distinct error so a client can act on it: ask how much was
stored and continue from there.

Chunks are encrypted at their offset. The at-rest layer is CTR, whose keystream
is seekable, so a chunk costs work proportional to itself; a mode without that
property would make every resumed chunk cost a pass over everything before it.

| Backend | How a partial upload is held |
|---|---|
| Filesystem | A file beside the blob, renamed into place by `Finish`. A rename is atomic, so a reader never observes a half-written blob. |
| Object store | Spooled to local disk and uploaded by `Finish`, because objects are immutable and cannot be appended to. |

> [!NOTE]
> Spooling costs local disk equal to the upload, and a partial upload does not
> survive losing the machine it was spooled on — with several replicas,
> resumability is per-replica. Multipart uploads remove both and are
> [#111](https://github.com/Serraniel/sendan/issues/111); the interface already
> describes the behaviour without assuming how it is stored, so that is a
> backend change behind a settled contract.

A partial upload holds the same content a finished one would, so it is encrypted
the same way and deleted the same way: `Delete` discards it whether or not a
blob was ever finished.

### 4.0 Uploading

`POST /api/uploads` creates an upload and `PATCH /api/uploads/{id}` writes it, in
chunks, over [tus](https://tus.io). The protocol is adopted rather than
reimplemented: resumption, offset negotiation and the request semantics are a
specification with maintained implementations on both sides, and what is
specific to Sendan is only where bytes go and what a completed upload becomes.

The cryptographic material travels in `Upload-Metadata` at creation — the
wrapped file key, the metadata envelope, their nonces, the token hashes, and the
password parameters when there are any. All of it is opaque to the server, but
its **sizes are not**: a wrapped key of the wrong length, or a token hash that
is not a digest, means a client that cannot be interoperable and an upload
nobody will ever open. Rejecting that at creation beats discovering it at
download, and every fault is reported at once so a client does not fix them one
round trip at a time.

Three protocol extensions are disabled, each for a reason:

| Extension | Why |
|---|---|
| Download | tus would serve content without checking a token. The download endpoint checks one first (§4.2) |
| Termination | it would remove an upload for anyone holding the identifier, which recipients have. Removal requires the owner token (§6) |
| Concatenation | each part would be a row with its own at-rest key and no lifecycle, and the parts would then need reaping |

**A declared length is required.** Accepting bytes without knowing the total
would make `SENDAN_MAX_UPLOAD_SIZE` a limit in name only, since the server would
discover the excess having already written it.

#### Streamed and chunked uploads are the same endpoint

A browser with `fetch` request streaming (`duplex: "half"`) sends the whole
upload as one request whose length it does not declare on the request itself.
That needs no second endpoint and no second protocol: it is the same `PATCH`,
with the body arriving as a stream. A browser without it slices the file and
sends several. The server cannot tell the difference and does not need to.

There is therefore **one upload path on the server**, which matters because the
alternative — a streaming endpoint beside a chunked one — would mean the
fallback rots unnoticed, being the path nobody exercises. Feature detection
belongs to the client, where the difference actually exists.

> [!IMPORTANT]
> **The declared length is what makes the size limit enforceable**, and a
> streamed body is precisely the case where the request cannot be checked up
> front. A client that declares ten bytes and streams a hundred stores ten: the
> excess is refused, and the upload is not extended by it. Both the streamed and
> the chunked shapes are tested, because a regression in the streamed one would
> otherwise surface only in a browser that supports it.

> [!IMPORTANT]
> **A completed upload cannot be written to.** The upload path reads only rows
> that are still incomplete, so a `PATCH` to a finished upload is refused.
> Without that, anyone holding an identifier could append past the end and
> replace what the recipient receives — and identifiers become known to
> recipients as soon as a link is shared, so that is the ordinary order of
> events rather than a contrived one.

On completion the blob is finished first and the row marked complete second. A
crash between the two leaves a finished blob belonging to an incomplete row,
which the reaper removes; the reverse would publish a row whose content was
never finished.

> [!WARNING]
> **tus logs the upload identifier**, as an attribute, inside the request path,
> and inside the `Location` URL. Sendan's guarantee is that identifiers never
> reach a log verbatim, so its records are bridged through a handler that
> replaces the identifier with a truncated hash and forwards only an
> **allowlist** of other attributes.
>
> The allowlist is deliberate. Blocking known-bad keys was tried first and
> leaked three times, each found only because a test looked for it. An attribute
> a future version of tus adds is now dropped rather than published.

### 4.0.1 An upload before it is complete

Chunks are encrypted with the row's at-rest key as they arrive, so the row has
to exist from the moment an upload is created rather than from the moment it
finishes. That leaves a window in which a row describes content that is only
partly written.

`completed_at` is null until the upload finishes, and **completeness is part of
liveness**. An incomplete upload is therefore unreachable by the same mechanism
that already makes an expired one unreachable, rather than by a second rule kept
somewhere else — a rule kept somewhere else is a rule some path will not apply.

Two consequences follow, and both are deliberate:

- **An upload still being written is not reaped by its own expiry.** The
  deadline the uploader chose describes how long the file should be available
  once it exists, not how long they have to finish sending it. A slow transfer
  would otherwise be collected mid-flight by a deadline that had not yet begun
  to mean anything.
- **An upload still being written *is* reaped once abandoned.** It holds an
  at-rest key and a partial blob that nothing will ever finish, which is exactly
  the leftover this project promises not to keep. `SENDAN_INCOMPLETE_TTL`
  governs how long that takes, measured from creation.

Measuring from creation rather than from the last chunk also bounds how long a
single upload may take. A day is generous for any size an instance accepts by
default, and the alternative — a column written on every chunk — would be paid
on every request to answer a question the reaper asks once every few minutes.

### 4.1 Metadata

`GET /api/uploads/{id}/metadata` returns what a client needs before deciding
whether to download: the wrapped file key, the encrypted metadata envelope,
their nonces, whether a password is required and with which Argon2id
parameters, and the remaining lifetime.

It is **unauthenticated**, and must be. The download token derives from the same
key schedule as everything else, so producing one requires the password
(spec §4) — while this endpoint is where a client learns whether a password is
needed and which parameters to derive it with. Requiring the token would make
the response unobtainable by precisely the clients that need it.

Nothing is disclosed by that. The wrapped key and the envelope are AES-256-GCM
ciphertext under keys derived from the link secret, which never reaches the
server; the identifier is 16 random bytes, so responses cannot be reached by
enumeration; and the Argon2id parameters permit no offline attack, because the
password hash is only ever combined with that same link secret.

> [!IMPORTANT]
> **The response must never carry the stored size.** The server knows the
> ciphertext length, and reporting it would hand a file's size to anyone holding
> an identifier — undoing the padding the metadata envelope applies for exactly
> that reason (spec §7). The size a client learns comes from decrypting the
> envelope, which requires the link secret.

Reading metadata does **not** consume the download allowance. A chat client
generating a link preview, or a recipient checking a filename, would otherwise
exhaust a limited upload before anyone fetched the content. Only the content
endpoint claims a download.

Expired, exhausted, revoked and never-existed are one answer, byte for byte. Any
difference between them would report on an upload the caller is not entitled to
know about — including confirming that a link which has since expired once
existed.

> [!NOTE]
> `downloadsRemaining` lets a holder of the identifier observe when a recipient
> downloads, by polling. That is accepted: the recipient's own interface needs
> the count, and an identifier holder can already observe availability by
> attempting a download.

### 4.2 Download authentication

`POST /api/uploads/{id}/auth` verifies a download token (spec §8.1) without
serving anything, so a client can report a wrong password before starting a
transfer rather than part-way through one.

The token travels in `Authorization: Bearer …`, never in the path or query. It
derives from the link secret, which the whole scheme keeps out of logs by
putting it in the URL fragment; a query parameter would write it to every access
log between the client and the server.

> [!IMPORTANT]
> **Verification precedes claiming, which precedes streaming.** Producing a
> valid token requires the link secret and, where set, the password, so this
> ordering is what guarantees that *nobody who could not have decrypted a file
> is able to consume one of its downloads*. Without it, anyone holding only the
> identifier could exhaust a download limit and destroy the upload for its
> recipient — a denial of service against data they cannot read.

Authenticating does not claim a download. Checking a password is not using the
file, and an upload whose allowance could be spent on attempts would be
destroyed by anyone able to reach it.

Attempts are limited **per upload** rather than per address, because an
adversary chooses their address and can rotate through many; keying by upload
bounds the whole attack wherever it originates. The per-address limit of §8.1
still applies alongside it, and neither substitutes for the other.

- The allowance is charged whatever the outcome, so an attempt costs the
  attacker even when their guess is right — which is the case worth bounding.
- A **correct** token clears the record, so a recipient who mistyped a password
  and then succeeded is not left throttled.
- Once throttled, a correct token is refused too. Accepting it would mean the
  limit bounded nothing at the moment it mattered.
- A **malformed** credential is refused without being charged. Otherwise anyone
  could exhaust an upload's allowance with garbage and lock out its recipient
  without ever making a real attempt.

> [!NOTE]
> Issue #30 described this as an HMAC challenge. The specification settled on
> presenting the token instead (§8.1), which is what is implemented: under TLS
> the token is not observable, and it is derived from a secret the URL already
> carries, so a challenge-response would add a round trip and no property.

### 4.3 Content

`GET /api/uploads/{id}/content` streams ciphertext at flat server memory, whatever
the file size, and supports range requests so an interrupted transfer can be
resumed.

Range handling is delegated to `http.ServeContent` rather than parsed here.
Overlapping ranges, suffix ranges, unsatisfiable ranges and conditional requests
are a well-known source of defects, and none of that is specific to this
project.

The ordering is **verify, serve, account**:

1. The download token is verified (§4.2). Nobody who could not have decrypted
   the file can cause its content to be read or its allowance to be spent.
2. Content is streamed from a seekable reader. The at-rest layer is CTR, which
   is what keeps it seekable, so a range is served without reading from the
   start.
3. The bytes actually written are recorded (§4.4).

Three details are load-bearing:

- **An `ETag` is served.** Content never changes, so the identifier is a
  complete validator. Without one, a resumed request carrying `If-Range` fails
  the comparison and `ServeContent` answers with the whole file — charging a
  second download for content the client already holds.
- **`Cache-Control: no-store`.** A shared cache serving content the server never
  saw would make the download limit unenforceable.
- **Accounting does not ride the request context.** A client that disconnects
  has already cancelled it; recording through it would be cancelled too, and
  every abandoned transfer would be free. That is precisely the bypass §4.4
  exists to close, so it is recorded through `context.WithoutCancel`.

The response carries no filename: the server does not know it. `Content-Type` is
`application/octet-stream` and set explicitly, because without it the ciphertext
would be sniffed, and a stream of random bytes can be detected as anything.

### 4.4 Counting downloads

The download counter counts **transfers, not requests**:

```
download_count = bytes_served / size      (integer division)
```

Every byte is charged once, so resuming an interrupted transfer is free, and a
transfer that is abandoned is charged for what it consumed.

Two simpler models were considered and both are wrong:

| Model | Why it fails |
|---|---|
| Count each request | A transfer that drops partway needs a second, ranged request to finish, so one download costs two. On a limit of one, an interrupted transfer destroys the upload before anyone receives it. |
| Count each completion | Evadable. An attacker requests the whole file, aborts at 99%, and repeats forever: the counter never moves, and because each record is independently authenticated, 99% of the ciphertext decrypts to 99% of the file. |

Accounting by volume answers both, and needs nothing from the client — no
completion notification, no session token, no cooperation. The server knows how
many bytes it wrote.

> [!NOTE]
> **Two honest costs.**
>
> A transfer abandoned partway is charged for the bytes it took, so a download
> that fails at 90% consumes nine tenths of an allowance rather than nothing.
> That is the price of a limit that cannot be evaded by aborting.
>
> Concurrent transfers can overshoot the limit slightly, because each is
> permitted before either has finished accounting. This requires a valid
> download token, so only a party who could have decrypted the file can do it,
> and it costs them their own allowance.

Accumulation and the recomputed count are a single statement, so concurrent
transfers cannot lose each other's bytes. That property has its own conformance
case on every backend, replacing the atomic-claim case the previous model
needed.

## 4.5 Serving the client

One binary, one artefact, no second web server. The client is built to static
files and embedded.

**It is a single-page application.** A download URL contains an upload
identifier, so the set of pages is not known at build time and never will be;
any path that does not name a file receives the shell, which routes in the
browser. Nothing is server-rendered, because the link secret lives in the URL
fragment and a server never receives it — there is nothing it could usefully
render.

> [!IMPORTANT]
> **The embed is behind the `embedui` build tag**, and a release must set it:
>
> ```sh
> (cd web && npm ci && npm run build)
> go build -tags embedui ./cmd/sendan
> ```
>
> Without the tag the binary compiles and serves an explanation instead of the
> client. That is deliberate: `go build` and `go test` must not require a
> JavaScript toolchain, or a contributor changing a storage backend would have
> to install one to compile the project.
>
> The embed pattern has no fallback file, so a *tagged* build with no client
> present fails rather than producing a binary silently missing its interface.
> Continuous integration builds both ways and then greps the tagged binary for
> the client, because a forgotten tag is otherwise invisible until a user
> reports a blank page.

The client is registered at the root, so it answers only what nothing else
claimed; the API and the health endpoint keep their paths. Hashed asset names
are content-addressed and cached for a year, while the shell is never cached —
it names the assets of the build that produced it, and a stale one would load
files that no longer exist. The service worker is not cached either, for a
sharper reason: its name never changes, so a long lifetime would pin a browser
to one version of it indefinitely, and it is the code that decrypts downloads.

### 4.6 Saving a decrypted file

Decryption happens in the tab, so the plaintext has to get from there to the
disk without being held whole. Three ways, tried in order, because which are
available depends on the browser.

| | How | Bound |
|---|---|---|
| **File System Access API** | `showSaveFilePicker()` returns a writable; records are written as they decrypt | the disk |
| **Service worker** | the worker answers a request the page makes to itself with a stream of plaintext, and the browser's own download machinery writes it | the disk |
| **Blob** | the whole file is assembled in memory and offered as an object URL | the tab |

The second exists because the first is absent in Firefox and Safari, where the
third would otherwise be the only option — and a multi-gigabyte file in tab
memory does not fail gracefully, it fails as a tab that stops responding.

> [!IMPORTANT]
> **The picker must be opened from the click, before anything is awaited.** It
> requires a user gesture and a gesture does not survive a round trip, so
> prompting after the transfer had begun is refused by the browser. This can
> only fail against a real browser, which is to say never in a test.

The worker holds a file key for as long as one download takes. The page sends it
by `postMessage`, keyed by a random token; the worker deletes it when the
download starts and discards it after a minute if nothing claims it. It is never
written anywhere a worker can persist, because that would outlive the tab that
produced it.

Two details of the response are deliberate. Its media type is always
`application/octet-stream` rather than the envelope's — the response is
same-origin, so an upload claiming `text/html` would otherwise be a document
rendering itself inside the client's own origin. And the filename comes from
whoever uploaded the file, so it is encoded rather than emitted: percent-encoded
in the RFC 5987 form and reduced to unreserved characters in the ASCII one, so
no input can introduce the newline that would end the header and begin another.

The worker caches nothing else. A cached client would mean a browser running
code an instance served at some point in the past, which is exactly what the
source report and the asset manifest exist to make checkable. An offline client
is not worth an unverifiable one.

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

Every value is read from what was used rather than written down. The key size
and record size come from the constants the code encrypts with; the Argon2id
parameters come from the upload rather than from the defaults; a
password-protected upload reports the parameters its own derivation ran with. A
card that named a cipher because somebody typed it would keep naming it after
the code stopped using it, and a reassurance that cannot become wrong is worth
less than none. A test asserts the derivation at the level of the source,
because a literal `256` and `FILE_KEY_SIZE * 8` are the same value and no
behaviour can tell them apart.

> [!NOTE]
> This report reflects what the delivered client code states it did. It is a
> transparency measure for well-behaved instances, not a defence against a
> hostile one, and must be worded so as not to imply otherwise. The wording is
> in one place, `CAVEAT` in `web/src/lib/protection.ts`, so a second interface
> that shows the card cannot quietly omit it.

An upload made through the compatibility endpoints carries its caution beside
the fact it qualifies rather than at the foot of the card. Those uploads use
another protocol's server-enforced password model and are genuinely less
protected; showing one next to a native upload without saying so would claim
protection the file does not have.

Every instance additionally reports its running version and commit at
`/api/source` and in the client footer, satisfying AGPL §13 and making a fork
that removes the link conspicuous.

The report names the version, the revision, whether the binary was built from a
modified tree, where the corresponding source can be obtained, and the licence:

```json
{
  "version": "0.1.0",
  "commit": "e98f80ced3ab68f139a39fb6e62cf90867b28268",
  "modified": false,
  "source": "https://github.com/Serraniel/sendan",
  "license": "AGPL-3.0-or-later"
}
```

> [!IMPORTANT]
> **`source` is configurable, and must be, for §13 to mean anything.** The
> obligation falls on the operator of a *modified* instance, so an endpoint
> hardcoded to upstream would satisfy it for nobody it applies to, while naming
> code that is not what the user is talking to. `SENDAN_SOURCE_URL` defaults to
> upstream because that is correct for an unmodified build; an operator running
> modified code is obliged to change it.

`commit` falls back to the revision Go embeds at build time, so a binary built
with `go build` rather than the release tooling still reports something true
instead of `unknown`. A stamped value always wins: the linker knows which
revision was released, whereas the embedded value describes the tree the binary
was built from, which for a rebuild of an old release is a different thing.

`modified` reports that the working tree was dirty at build time. Such a build
has no commit that corresponds to it, so no source link can be exact — which is
worth stating rather than presenting a link that appears authoritative.

> [!WARNING]
> **This report is a claim, not evidence.** The caveat above applies here as
> much as to the per-file report: the instance compiles and serves this
> endpoint, so an operator who has modified the code can return whatever it
> says. Committing their changes yields a clean tree and `"modified": false`;
> editing the handler yields any version, commit and source they choose, with
> nothing to contradict it.
>
> What the endpoint achieves is therefore narrower than it looks:
>
> - **Honest operators** get a correct answer and an effortless way to meet
>   §13.
> - **Careless operators** are caught, because a dirty build reports
>   `"modified": true` beside a source link that cannot correspond to it.
> - **Dishonest operators** are not caught at all, and no endpoint served by
>   them could catch them.
>
> Nothing an instance serves about itself can be a defence against that
> instance. Verification has to come from outside it: see §7.1.

The client shows this in a persistent footer: the version, a shortened commit,
a link to the source, and the licence. That is the prominent offer §13 asks for;
the endpoint is the machine-readable half.

> [!IMPORTANT]
> **When the build is modified, the footer says the link may not correspond.** A
> build from a modified working tree has no commit that describes it, so no
> source link can be exact. A footer that presented one anyway would be a
> decoration rather than a transparency measure - and the modified case is
> precisely the one §13 exists for.

The footer reads the endpoint after mount and renders nothing if it cannot. An
instance that fails to answer should still serve a page that uploads a file, and
a footer is not worth an error boundary.

### 7.1 Verifying an instance

A user must be able to answer "is this instance running what it claims?" without
taking the instance's word for it.

**No endpoint can answer it.** Any credential an instance serves about itself can
be copied from an honest instance and replayed by a dishonest one, and the
operator compiles the binary that would produce it. This is not a matter of
choosing a better attestation format; it is what "the party under examination
controls the examination" means.

The question is nevertheless tractable, because of what is actually at stake:

> **The client bundle is the trust boundary.** The server holds ciphertext and
> a wrapped key it cannot unwrap; it could be entirely hostile and still learn
> nothing. What decides whether a file is safe is the JavaScript the instance
> delivered to the browser. Verifying an instance therefore reduces to verifying
> what it served — and bytes served can be fetched and hashed by anyone.

So the verifier is a program the user already trusts, obtained independently of
the instance, comparing what the instance serves against a statement published
independently of the operator:

| Piece | Where it comes from | Issue |
|---|---|---|
| A digest manifest of every asset in the published client | the release, built by the project's pipeline | [#102](https://github.com/Serraniel/sendan/issues/102) |
| A signature over that manifest | the release, signed with cosign | [#104](https://github.com/Serraniel/sendan/issues/104) |
| `sendan verify <url>`, which fetches the instance's assets and compares | the command line client, obtained once and reused | [#103](https://github.com/Serraniel/sendan/issues/103) |

The instance is given no part in it beyond serving the bytes it would serve any
visitor. It is not asked, and its answers are not relied on.

#### What this establishes

| Claim | Status |
|---|---|
| The instance serves the published client | **verified**, for the response this verifier received |
| The client was modified | **detected** |
| `/api/source` misreports the version | **detected** — digests will not match the version claimed |
| A backdoored bundle is served to a chosen victim and a clean one to verifiers | **not detected** |
| Server-side code | not covered, and does not need to be |

The last two rows are the honest limits. Targeted serving is inherent to
verifying from a different client than the victim uses; what narrows it is that
anyone may run the check, from anywhere, at any time, so an attack broad enough
to matter is observable, and one narrow enough to hide has to identify its
victim in advance.

#### Considered and not planned

- **A browser extension** verifying what the browser itself received would close
  the targeted-serving gap for whoever installs it. It is the only mechanism
  that verifies the exact bytes the victim ran. It is not planned: a second
  distribution channel, per-browser review processes, and an extension with
  read access to page contents is itself a security surface.
- **Hardware remote attestation** (SEV-SNP, TDX) is the only technology that
  proves what code a remote machine is executing. It is rejected for this
  project: it requires specific hardware, contradicts the goal that anyone can
  self-host anywhere, and substitutes trust in a CPU vendor for trust in an
  operator.

## 8. Abuse mitigation

End-to-end encryption precludes content inspection, so controls must be
structural: size caps, per-address rate limits, a short default retention period,
`X-Robots-Tag: noindex`, and optional upload authentication (token, later OIDC)
for instances that require it.

### 8.1 Rate limiting

Every request except `/healthz` passes a per-address token bucket
(`internal/ratelimit`, applied in `internal/httpapi`). The limit is per client
rather than global: a global one turns a single abusive caller into an outage
for everyone, which is a denial of service delivered by the defence.

Two decisions in choosing the key are worth recording, because both are places
where a plausible implementation is worthless.

**`X-Forwarded-For` is read only when a proxy is configured to exist.** The
header is written by whoever spoke last; on an instance with nothing in front
of it, that is the caller. Reading it unconditionally would let a caller pick a
fresh bucket per request and never meet a limit. `SENDAN_TRUSTED_PROXIES`
defaults to zero, and with *N* proxies the client is the *N*th entry from the
right — each proxy appends the address it observed, so the rightmost was written
by the nearest proxy and entries a caller forges can only pad the left.

Misconfiguring the count too high charges several clients to one bucket:
stricter than intended, never weaker. The dangerous direction is claiming a
proxy that does not exist.

**IPv6 is keyed on the /64, not the address.** A residential allocation is
commonly a /64 or larger, so keying on the full 128-bit address would let one
subscriber present billions of distinct addresses and never meet a limit —
which is not a limit. Clients sharing a /64 share a bucket, which is the
intended trade: a limit that can be evaded is worth nothing, whereas one that is
occasionally shared is merely stricter than necessary.

A refused request receives `429` with `Retry-After`, rounded up so a client is
never told to return at a moment it is certain to be refused again.

> [!NOTE]
> This is the request-rate limit. Password guessing is limited separately and
> per upload, by `ratelimit.PasswordAttempts`, because an attacker with many
> addresses would otherwise get many attempts at one file.

### 8.2 Response headers

Every response carries the same header set, applied as one middleware around the
router rather than per route, so an endpoint added later inherits it. See
`internal/httpapi`.

Three carry most of the weight, for reasons specific to this design:

- **`Referrer-Policy: no-referrer`.** The link secret is in the URL fragment.
  Browsers do not put a fragment in a referrer, so this is not what protects it,
  but a referrer would still disclose which instance and which upload a visitor
  came from — and it removes the possibility that a future page which puts the
  secret anywhere else leaks it outright.
- **`connect-src 'self'`.** The client holds the file key in memory. This is
  what ensures an injected script has nowhere to send it: script injection
  becomes a local failure rather than a key disclosure.
- **`base-uri 'none'`.** An injected `<base>` element would silently redirect
  every relative API request, which on a page performing key exchange is
  equivalent to changing the server.

> [!IMPORTANT]
> **The policy carries the hash of the client's inline bootstrap.** SvelteKit
> emits one inline script: the few hundred bytes that tell the application where
> it was served from, which differ per build and so cannot be a separate file.
> The policy forbids `'unsafe-inline'`, so without its hash a browser refuses to
> run it and the application never starts.
>
> The hash is computed at startup from the shell actually embedded in the
> binary, rather than written down or emitted by the client. A value written
> down goes stale on the next build; a policy emitted by the client would be a
> second policy, and two policies both apply — the intersection of a header
> without the hash and a meta tag with it still blocks the script.
>
> This is the failure that no test which serves the page without executing it
> can see. The test that guards it recomputes the hash from the served document
> independently, because asking the implementation what the answer is and then
> checking that answer against itself passes whatever convention it used.

> [!IMPORTANT]
> **`script-src` must permit `'wasm-unsafe-eval'`.** WebCrypto offers no
> Argon2id, so password derivation runs in WebAssembly, and instantiating a
> module counts as evaluation. Removing the directive — an obvious-looking
> hardening — breaks password-protected uploads and downloads while leaving
> every other path working, so the failure survives any test that does not set a
> password. A test asserts the directive is present for this reason.

HSTS is sent only when `SENDAN_BASE_URL` is `https`. The decision is taken from
configuration rather than `X-Forwarded-Proto`, which is written by whatever
spoke last and, on a deployment without a proxy, is the client.

> [!WARNING]
> The built client is also audited: `scripts/audit-assets.sh` fails the build if
> the output would load anything from a third party. It looks for references
> that cause a load — `src` and `href` in markup, `url()` in stylesheets, and
> imports of absolute URLs — rather than for the text of a URL, because an
> earlier version grepped every script for `https://` and fired on the
> documentation links inside Svelte's own error messages. A check that fires on
> those is one somebody turns off.
>
> It also fails the build if the client would depend on an **inline style**.
> `style-src 'self'` carries no `'unsafe-inline'`, and `style-src-attr` falls
> back to `style-src`, so a `style` attribute is refused. Nothing reports this:
> a blocked style is not a broken page, the development server sends no policy,
> and the result renders correctly everywhere it is looked at. The upload
> progress bar is the case that prompted the check — written the obvious way,
> `style="width: {percent}%"`, it compiles to `style.cssText` and would be an
> empty bar on every real instance. It is a `<progress>` element instead.

> [!WARNING]
> A reverse proxy that sets its own security headers may replace these rather
> than merge them. Operators terminating TLS should confirm the policy reaching
> the browser is the one below, particularly `connect-src`.

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
