# Sendan wire format and key schedule, version 1

Status: **draft**. Normative for implementations once merged.

This document specifies the cryptographic scheme precisely enough that the Go
and TypeScript implementations can be written independently and still agree byte
for byte. [`docs/design.md`](../design.md) gives the reasoning; this document
gives the definition. Where they disagree, this document governs.

## 1. Conventions

- `||` denotes concatenation of byte strings.
- `x[a..b]` denotes bytes `a` through `b` inclusive, zero-indexed.
- Integers on the wire are **big-endian** and unsigned.
- **base64url** means RFC 4648 §5 without padding.
- ASCII string literals in labels are encoded as UTF-8 with no terminator.
- All random values come from a cryptographically secure source:
  `crypto/rand` in Go, `crypto.getRandomValues` in the browser.

## 2. Primitives

| Purpose | Primitive |
|---|---|
| Content and key encryption | AES-256-GCM, 96-bit nonce, 128-bit tag |
| Key derivation | HKDF-SHA-256 (RFC 5869) |
| Password stretching | Argon2id (RFC 9106) |
| Verifier hashing | SHA-256 |

> [!IMPORTANT]
> There is exactly one cipher suite. No field in this format identifies an
> algorithm, and no implementation may offer a choice. Changing any primitive
> means defining version 2 and incrementing every label in §4.

## 3. Values and sizes

| Value | Size | Origin |
|---|---|---|
| File identifier `fileID` | 16 bytes | server, random |
| Link secret `LS` | **32 bytes** | client, random |
| File key `FK` | 32 bytes | client, random |
| Password salt `pwSalt` | 16 bytes | client, random |
| Content salt `cSalt` | 16 bytes | client, random |
| Owner token `OT` | 32 bytes | client, random |
| GCM nonces | 12 bytes | client, random unless stated |

`LS` is 32 bytes rather than 16 because it is the sole credential protecting an
upload, and Grover's algorithm halves effective symmetric security. See
[`docs/design.md`](../design.md) §2.4.

## 4. Key schedule

Let `pwHash` be defined as:

```
no password:    pwHash = "" (empty)
with password:  pwHash = Argon2id(password  = UTF-8(password),
                                  salt      = pwSalt,
                                  memory    = 65536 KiB,
                                  iterations = 3,
                                  parallelism = 1,
                                  tagLength = 32)
```

Then:

```
IKM = LS || pwHash

PRK = HKDF-Extract(salt = fileID, IKM = IKM)

KEK = HKDF-Expand(PRK, "sendan/v1/kek",      32)
MK  = HKDF-Expand(PRK, "sendan/v1/metadata", 32)
AT  = HKDF-Expand(PRK, "sendan/v1/auth",     32)
```

Every derived key has a distinct label, following TLS 1.3's
`HKDF-Expand-Label` discipline. Labels are constants and are never assembled
from caller-supplied input.

> [!NOTE]
> The metadata key `MK` derives from the same `PRK` as `KEK`, so a
> password-protected upload discloses **no** filename, media type, or size
> without the password — not merely no content.

The Argon2id parameters are stored per upload (§7) so they may be raised later
without invalidating existing links.

> [!IMPORTANT]
> A password **must not be empty**. An upload marked password-protected whose
> password is the empty string is a meaningless state: any holder of the link
> could open it while the interface claimed otherwise. Implementations reject it
> rather than deriving from it.
>
> This is also a practical necessity. The browser's Argon2id implementation
> refuses an empty password outright, so permitting one would make the two
> implementations disagree about whether an upload could be created at all.

The password is taken as its UTF-8 encoding with **no normalisation**.
Normalising would silently change which passwords open which files, and would do
so differently in each implementation.

## 5. Content encoding

Content uses the framing of RFC 8188 with a 256-bit key.

> [!WARNING]
> RFC 8188 defines only the `aes128gcm` content coding. Sendan uses identical
> framing with a 256-bit key and a distinct info string, designated
> `aes256gcm`. This is a deliberate deviation and is **not** byte-compatible
> with RFC 8188 or with implementations of it. Compatibility endpoints (§10)
> therefore use unmodified `aes128gcm` and are a separate code path.

### 5.1 Derivation

```
cPRK  = HKDF-Extract(salt = cSalt, IKM = FK)
CEK   = HKDF-Expand(cPRK, "Content-Encoding: aes256gcm" || 0x00, 32)
NONCE = HKDF-Expand(cPRK, "Content-Encoding: nonce"     || 0x00, 12)
```

### 5.2 Header

```
cSalt (16 bytes) || rs (4 bytes) || idlen (1 byte) || keyid (idlen bytes)
```

`rs` is the record size, fixed at **65536**. `idlen` is 0 and `keyid` is empty.

### 5.3 Records

Plaintext is split into records of `rs - 17` bytes. Each record's plaintext is
suffixed with a delimiter octet — `0x01` for a non-final record, `0x02` for the
final record — and encrypted with AES-256-GCM.

The nonce for record `seq`, counting from zero, is:

```
nonce(seq) = NONCE XOR big-endian-96(seq)
```

> [!WARNING]
> **Nonce reuse under one key discloses the GCM authentication key**, not merely
> one record. `seq` is a strictly increasing counter and nonces are never
> random here. Implementations must make it structurally impossible to encrypt
> two records of one stream at the same `seq`.

The final record carries the `0x02` delimiter, so truncating a stream is
detectable: a decryptor that reaches end of input without having seen a `0x02`
record **must** raise an error and **must not** return the partial plaintext.
Records are authenticated in sequence, so reordering and replay are rejected by
the nonce derivation.

### 5.4 Strictness

Sendan's profile is deliberately narrower than RFC 8188 permits. A decryptor
**must** reject a stream in each of these cases:

| Condition | Reason |
|---|---|
| `rs` is not 65536, or `idlen` is not 0 | Honouring a value taken from the stream would make it a negotiated parameter, which §11 forbids |
| A record's plaintext ends in anything other than `0x01` or `0x02` | RFC 8188 permits zero padding after the delimiter; accepting it would make two distinct encodings of one plaintext valid |
| A non-final record is shorter than `rs` | Otherwise a truncated stream could be presented as a complete one |
| Any data follows the final record | Trailing bytes are unauthenticated |
| A record's plaintext is empty | There is no delimiter to inspect |

> [!NOTE]
> Rejecting the optional padding of RFC 8188 costs nothing — this profile never
> produces it — and removes a source of malleability. Two encodings of the same
> content should never both be valid.

The record sequence number is bounded at 2^48, far below the point at which the
96-bit nonce space could wrap. Exceeding it is an error rather than a wrap.

## 6. File key wrapping

```
wrapNonce = 12 random bytes
wrappedFK = AES-256-GCM(key        = KEK,
                        nonce      = wrapNonce,
                        plaintext  = FK,
                        additional = "sendan/v1/wrap")
```

The server stores `wrapNonce` and `wrappedFK` and never sees `FK`, `KEK`, or
`LS`.

Changing a password re-derives `KEK` and re-wraps the same `FK` with a **fresh**
`wrapNonce`, touching 48 bytes rather than re-encrypting the content.

Unwrap failure — a wrong password or a corrupt container — is reported to the
caller as a single indistinguishable error.

## 7. Metadata envelope

The metadata plaintext is a UTF-8 JSON object:

```json
{ "name": "report.pdf", "type": "application/pdf", "size": 1048576 }
```

Members appear in exactly that order, with no insignificant whitespace, so the
encoding is deterministic across implementations.

`name` and `type` **must** be valid UTF-8. An implementation encountering
invalid UTF-8 rejects the metadata rather than substituting replacement
characters, which would differ between implementations.

`size` is a non-negative decimal integer with no sign, leading zeros, decimal
point, or exponent, and **must not exceed 2^53 − 1** (9007199254740991).

> [!WARNING]
> The upper bound is not arbitrary. JavaScript numbers are IEEE-754 doubles, so
> a larger value parses back rounded rather than failing: `9007199254740993`
> becomes `9007199254740992`. Without the bound, an envelope written by one
> implementation would be read with a different size by the other, silently.
> Implementations reject an out-of-range size both when encoding and when
> decoding, since an envelope may originate elsewhere.

### 7.1 String escaping

Exactly these escapes are produced, and no others:

| Input | Output |
|---|---|
| `"` | `\"` |
| `\` | `\\` |
| U+0008, U+000C, U+000A, U+000D, U+0009 | `\b`, `\f`, `\n`, `\r`, `\t` |
| Any other character below U+0020 | `\u00xx`, lowercase hexadecimal |
| Everything else | emitted literally as UTF-8 |

> [!WARNING]
> The general-purpose JSON encoders of both languages are **unsuitable** here
> and must not be used for this envelope. Go's `encoding/json` escapes U+2028
> and U+2029 unconditionally, and HTML-significant characters by default;
> JavaScript's `JSON.stringify` does neither. A filename containing any of `<`,
> `>`, `&`, U+2028, or U+2029 would then produce different ciphertext in each
> implementation, and the shared vectors would diverge for reasons unrelated to
> the cryptography. Each implementation writes this encoding directly.
>
> Decoding may use a general-purpose JSON parser, since parsing is unambiguous.

The plaintext is padded to a multiple of **256 bytes** using ISO/IEC 7816-4
padding: a single `0x80` octet followed by `0x00` octets. Padding blunts the
disclosure of filename length through ciphertext length.

```
metaNonce    = 12 random bytes
metaEnvelope = AES-256-GCM(key        = MK,
                           nonce      = metaNonce,
                           plaintext  = padded JSON,
                           additional = "sendan/v1/meta")
```

## 8. Authentication and ownership

### 8.1 Download authentication

`AT` from §4 is the download authentication token. The server stores only:

```
authTokenHash = SHA-256(AT)
```

A client presents `base64url(AT)`; the server compares in constant time. This
allows an incorrect password to be rejected before any ciphertext is streamed.

> [!NOTE]
> This is defence in depth, **not** the security boundary. Confidentiality rests
> on the password contributing to `KEK` (§4), so disclosed ciphertext remains
> useless without the password. This check must never be treated as a licence to
> weaken the wrapping scheme.

### 8.2 Ownership

The owner token `OT` is 32 random bytes generated by the client and never
derived from `LS`, so an upload can be revoked without the ability to read it.
The server stores only `SHA-256(OT)`.

## 9. Server-held values

The server stores, per upload, and learns nothing else:

| Field | Notes |
|---|---|
| `fileID` | 16 bytes |
| `wrapNonce`, `wrappedFK` | §6 |
| `metaNonce`, `metaEnvelope` | §7 |
| `authTokenHash` | §8.1 |
| `ownerTokenHash` | §8.2 |
| `passwordRequired` | boolean |
| `pwSalt`, Argon2id parameters | present only when `passwordRequired` |
| expiry deadline, download count and limit | §3 of `docs/design.md` |
| per-file server-side key | crypto-shredding; see `docs/design.md` §3 |

`passwordRequired`, `pwSalt`, and the Argon2id parameters are necessarily
public: a client must know them before it can derive anything. They disclose
only that a password exists.

## 10. URL format

```
https://<host>/d/<base64url(fileID)>#<base64url(LS)>
```

`fileID` encodes to 22 characters and `LS` to 43.

The link secret appears **only** in the fragment, which browsers do not
transmit. Implementations must serve `Referrer-Policy: no-referrer` so that the
fragment cannot leak through a referrer from any link the download page renders.

Compatibility endpoints use their own URL format and key schedule and are
outside this specification.

## 11. Versioning

The literal `v1` in every label of §4 is the version of this specification.

A change to any primitive, label, size, padding rule, or record framing requires
a **new version**: increment the label suffix and publish an updated document.
Implementations must not attempt to negotiate, detect, or fall back to another
version. A server may support several versions simultaneously; which one applies
is determined by the stored record, never by client-supplied input.

## 12. Test vectors

Shared vectors live in `testdata/vectors/` and are the contract between
implementations. Both the Go and TypeScript implementations are verified against
them on every pull request.

Vectors must cover, at minimum:

- the key schedule, with and without a password;
- Argon2id output for empty, ASCII, and multi-byte UTF-8 passwords;
- wrapping and unwrapping, including a failing unwrap;
- metadata envelopes at, just below, and just above a padding boundary;
- content of length 0, 1, `rs - 18`, `rs - 17`, `rs - 16`, and several records;
- a truncated stream, which must fail;
- a stream with one flipped ciphertext bit, which must fail.

## 13. Invariants

An implementation is non-conforming if any of these does not hold.

1. No algorithm is ever selected by client-supplied input.
2. A record nonce is never reused under one key.
3. Truncated, reordered, or modified ciphertext never yields plaintext.
4. `LS`, `FK`, `KEK`, `MK`, and the password never reach the server.
5. Wrong password and corrupt container are indistinguishable to the caller.
6. Filename, media type, and size are never recoverable without `LS`, and
   additionally without the password where one is set.
