# HTTP API

Every endpoint an instance serves. The reasoning behind each is in
[`docs/design.md`](design.md) §4; this page is the reference.

> [!NOTE]
> The web client speaks this API, so a file can be sent and received in a
> browser without reading any of it. This page is for anything else — another
> client, a script, or checking what an instance actually promises.

## Conventions

Binary values are **unpadded base64url** (RFC 4648 §5), matching the wire format
specification. Errors are JSON:

```json
{ "code": "not_found", "message": "no such upload" }
```

`code` is stable and may be branched on; `message` is for a person reading a
log. Neither ever names a table, a path, or a driver: an error that describes
the deployment tells an attacker something and tells a legitimate caller nothing
they can act on.

| Code | Meaning |
|---|---|
| `not_found` | No such upload, or one that is expired, exhausted, revoked or still being written |
| `unauthorized` | Missing or invalid download token |
| `too_many_attempts` | Too many failed attempts **against this upload** |
| `rate_limited` | Too many requests **from this client** |
| `method_not_allowed` | The path exists; the method does not |
| `internal` | A fault the operator must look at. Details are logged, never returned |

Every response carries the security headers of §8.2, and `Cache-Control:
no-store` wherever a cached copy would be wrong.

---

## Uploading

Uploads use [tus 1.0.0](https://tus.io). The protocol handles resumption and
offset negotiation; what follows is what Sendan adds.

### `POST /api/uploads`

Creates an upload. The body is empty; everything travels in headers.

| Header | Required | Meaning |
|---|---|---|
| `Tus-Resumable: 1.0.0` | yes | Protocol version |
| `Upload-Length` | yes | Total size in bytes |
| `Upload-Metadata` | yes | The cryptographic material, below |

`Upload-Metadata` is the tus format: `key base64(value),key base64(value)`. The
base64 there is the protocol's own, so values are **raw bytes**, not encoded
again.

| Key | Size | Meaning |
|---|---|---|
| `fileID` | 16 | The identifier the client generated, and the salt its keys derive from |
| `wrappedFileKey` | 48 | The file key sealed under the KEK (spec §6) |
| `wrapNonce` | 12 | Its nonce |
| `metadataEnvelope` | multiple of 256, plus 16 | Encrypted filename, type and size (spec §7) |
| `metadataNonce` | 12 | Its nonce |
| `authTokenHash` | 32 | SHA-256 of the download token (spec §8.1) |
| `ownerTokenHash` | 32 | SHA-256 of the owner token (spec §8.2) |
| `passwordSalt` | 16 | Present only when a password is set |
| `argon2MemoryKiB`, `argon2Iterations`, `argon2Parallelism` | — | Decimal. Required, and non-zero, when `passwordSalt` is present |
| `ttlSeconds` | — | Decimal. Requested lifetime; `0` selects the instance default |
| `maxDownloads` | — | Decimal. `0` means no limit |

The sizes are checked. A value of the wrong length means a client that cannot be
interoperable and an upload nobody will ever open, so it is refused at creation
rather than discovered at download. Every fault is reported at once.

> [!IMPORTANT]
> **The client generates `fileID`, and the order this implies is not optional.**
> It is the salt in the key schedule (spec §4), so every value above derives
> from it and none of them can exist before it does. A client therefore
> generates the identifier first, derives, and only then creates:
>
> ```
> fileID     = random(16)
> keys       = derive(fileID, linkSecret [, password])
> wrappedFK  = seal(keys.wrapping, fileKey)
> envelope   = seal(keys.metadata, {name, type, size})
> POST /api/uploads  with all of the above
> ```
>
> The server validates the length and alphabet, refuses a duplicate with `409`,
> and refuses a value that is a single repeated byte — an absent generator
> rather than a weak one. It can do no more, and spec §13.1 records why.

| Status | When |
|---|---|
| `201` | Created. `Location` names the upload, as a **path** |
| `400` | Malformed metadata, an undeclared length, or a lifetime the instance does not permit |
| `409` | The identifier is already in use |
| `413` | Larger than `SENDAN_MAX_UPLOAD_SIZE` |
| `429` | Rate limited |

> [!NOTE]
> **`Location` is relative, and deliberately.** The tus specification permits
> it, and a path cannot be wrong about a connection the instance cannot see.
> This binary does not terminate TLS, so an absolute URL built from the request
> would name `http` for a browser that is talking `https` through a proxy — and
> a browser refuses to follow that as mixed content. Resolve it against the
> request you made.

> [!IMPORTANT]
> **The length must be declared.** `Upload-Defer-Length` is refused: accepting
> bytes without knowing the total would make the size limit a limit in name
> only, since the excess would be discovered having already been written.

### `PATCH /api/uploads/{id}`

Writes bytes at an offset. `Content-Type: application/offset+octet-stream` and
`Upload-Offset` are required.

The body may be **streamed** — sent with no `Content-Length`, as a browser does
with `fetch` request streaming — or sent as one of several chunks. These are the
same request; the server cannot tell them apart and does not need to. A client
that streams more than it declared stores only what it declared.

| Status | When |
|---|---|
| `204` | Written |
| `404` | No such upload, **or one that is already complete** |
| `409` | The offset does not continue where the stored bytes end |
| `413` | The body exceeds the declared length |

> [!IMPORTANT]
> **A completed upload cannot be written to.** Its identifier is shared with
> recipients once a link goes out, and without this anyone holding one could
> append past the end and replace what the recipient receives.

### `HEAD /api/uploads/{id}`

Reports `Upload-Offset` and `Upload-Length`, which is how a client resumes. It
answers only for uploads still being written; a completed one is `404`.

### Not offered

`GET` on an upload (tus download), `DELETE` (tus termination) and the
concatenation extension are disabled. Each is discussed in `docs/design.md` §4.0.1.

---

## Downloading

### `GET /api/uploads/{id}/metadata`

Everything a client needs before deciding whether to download.

```json
{
  "id": "…",
  "wrappedFileKey": "…",
  "wrapNonce": "…",
  "metadataEnvelope": "…",
  "metadataNonce": "…",
  "passwordRequired": true,
  "kdf": { "salt": "…", "memoryKiB": 65536, "iterations": 3, "parallelism": 1 },
  "expiresAt": "2026-08-07T12:00:00Z",
  "downloadsRemaining": 2
}
```

`kdf` is absent when no password is set. `expiresAt` is absent when the upload
never expires, and `downloadsRemaining` when there is no limit.

**Unauthenticated, and necessarily so:** the download token derives from the same
key schedule as everything else, so producing one requires the password — while
this is where a client learns whether a password is needed. Requiring the token
would make the response unobtainable by the clients that need it.

Nothing is disclosed by that. The wrapped key and envelope are ciphertext under
keys derived from the link secret, which never reaches the server, and the
identifier is 16 random bytes, so responses cannot be reached by enumeration.

> [!IMPORTANT]
> **The size is deliberately absent.** The server knows the stored ciphertext
> length; reporting it would hand a file's size to anyone holding an identifier,
> undoing the padding the metadata envelope applies for exactly that reason. The
> size a client learns comes from decrypting the envelope.

Reading metadata does **not** consume a download.

| Status | When |
|---|---|
| `200` | The upload is available |
| `404` | Expired, exhausted, revoked, still being written, unknown, or a malformed identifier — one answer for all of them |

### `POST /api/uploads/{id}/auth`

Verifies a download token without serving anything, so a client can report a
wrong password before starting a transfer.

`Authorization: Bearer <base64url(AT)>`. The token is **never** accepted in the
query: it derives from the link secret, which the whole scheme keeps out of logs
by putting it in the URL fragment, and a query parameter would write it to every
access log between the client and the server.

| Status | When |
|---|---|
| `204` | The token is valid |
| `401` | Missing, malformed, or wrong |
| `404` | No such upload |
| `429` | Too many attempts against this upload. `Retry-After` in seconds |

Attempts are limited **per upload**, because an adversary chooses their address
and can rotate through many. A malformed credential is refused without being
charged — otherwise anyone could exhaust the allowance with garbage and lock out
the recipient. A correct token clears the record.

### `GET /api/uploads/{id}/content`

Streams ciphertext. Same `Authorization` header. Range requests are supported,
and an `ETag` is served so a resumed request validates and receives the range
rather than the whole file.

| Status | When |
|---|---|
| `200` | The whole upload |
| `206` | The requested range |
| `401` | Missing, malformed, or wrong token |
| `404` | No such upload |
| `416` | The range cannot be satisfied |
| `429` | Too many attempts against this upload |

**Verify, serve, account, in that order.** Producing a valid token requires the
link secret and, where set, the password, so nothing is read and no allowance
spent by anyone who could not have decrypted the file.

The download counter counts **transfers, not requests**: bytes served divided by
the file size. Resuming is free, because every byte is charged once; a transfer
abandoned at 90% consumes nine tenths of an allowance. See `docs/design.md` §4.4
for why the alternatives are worse.

---

## Removing an upload

### `DELETE /api/uploads/{id}`

Removes an upload before it would otherwise expire.

```
Authorization: Bearer <owner token, base64url>
```

The **owner token** is minted when the upload is created and shown once. This
server stores only its SHA-256 hash, so it can check a token and cannot produce
one: possession is the proof, and an operator cannot revoke an upload they did
not make. Losing the token means losing the ability to remove the upload early,
and nothing here can recover it.

It travels in the header rather than the path for the same reason a link secret
lives in the fragment: a path reaches access logs, proxies and browser history.

| Status | Meaning |
|---|---|
| `204` | Removed. The row, the blob and the at-rest key are gone |
| `401` | No credential, or not a bearer token |
| `403` | The token does not match — **or the upload does not exist** |
| `404` | The identifier is not the right shape |

`403` covers both a wrong token and an absent upload, deliberately: telling them
apart would let somebody discover which identifiers are real by asking about
each in turn.

Removing is idempotent in the way that matters. An upload that is already gone
answers the same as one this request removed, so a client retrying a request
whose response it never saw is not told that something went wrong.

---

## Instance

### `GET /api/source`

What the instance is running, and where its corresponding source can be
obtained. This is the AGPL §13 mechanism.

```json
{
  "version": "0.1.0",
  "commit": "…",
  "modified": false,
  "source": "https://github.com/Serraniel/sendan",
  "license": "AGPL-3.0-or-later"
}
```

`source` comes from `SENDAN_SOURCE_URL`. **An operator running modified code
must set it**: §13 obliges them to offer the source of the version actually
running, and the default names upstream.

> [!WARNING]
> This report is a **claim, not evidence**. The instance compiles and serves it,
> so a dishonest operator can return anything. `docs/design.md` §7.1 describes
> what checking an instance actually requires.

Unauthenticated: a user deciding whether to trust an instance needs it before
they have anything to authenticate with.

### `GET /healthz`

Liveness. Reports that the process is serving, not that its backends are
reachable — a health check that failed when the database blinked would restart a
server that was about to recover.

It is the one endpoint that is **never rate limited**, because a check that
began failing on a limit would cause the restart it exists to prevent.
