# Third-party client compatibility

Sendan can speak another file-sharing protocol, so clients written for it work
against an instance without changes.

> [!IMPORTANT]
> **Off by default, and it should usually stay off.** Uploads made through these
> endpoints are protected **less well** than native ones, for a reason no
> configuration can fix — see below. The mode exists so that people with an
> existing client and existing habits can be served, not because it is as good.

```sh
SENDAN_SEND_COMPAT=true
```

Enabling it logs a warning at startup, registers the endpoints, and changes
nothing about uploads made the native way.

## The password model is weaker, and this is why

Setting a password through these endpoints replaces the key **the server**
checks a downloader against. It does not change the key that decrypts the
content: that is derived from the secret in the link and is the same with or
without a password.

| | Native upload | Compatibility upload |
|---|---|---|
| What a password changes | part of the key-wrapping key | the key the server checks |
| Who enforces it | the cryptography | the instance |
| Can the operator bypass it? | **no** | **yes** |
| Derivation | Argon2id, 64 MiB, 3 iterations | PBKDF2-SHA256, **100 iterations** |

Both differences matter, and the second is not a typo: that protocol derives its
authenticator with a hundred iterations of PBKDF2, salted with the share URL.

So an instance running in this mode can serve a password-protected file to
somebody who does not know the password. Sendan's own model cannot: an instance
holding every byte it stores still cannot open a protected upload.

**This is surfaced rather than hidden.** An upload made through these endpoints
is marked, the metadata endpoint reports which protocol produced it, and the
transparency card names the model with the reason beside it rather than in a
footnote.

## What is tested

Compatibility that is not continuously tested is compatibility that has already
broken, so this is not a claim about reading a specification.

Every pull request installs the **latest release of `ffsend`** — the most widely
used client for this protocol — starts an instance with the mode enabled,
uploads a 5 MB file and downloads it again, and fails if the bytes differ. The
version current when this was written was 0.2.77.

## What "compatible" covers

| Operation | |
|---|---|
| Upload | **yes** — the WebSocket protocol, streamed |
| Download | **yes**, with either credential its clients send |
| Metadata | **yes** |
| Existence and password check | **yes** |
| Setting a password | **yes**, owner-authenticated |
| Version discovery | **yes** |

## What it does not cover

| Operation | Why not |
|---|---|
| Deleting an upload | its clients can, and this does not yet implement it. An upload still expires and is still removed by its own limits |
| Changing an upload's parameters after the fact | the same |
| Reading an upload's download count | the same |
| Abuse reporting | that endpoint reports to a hosted service this project does not run |
| Account file lists | requires a third-party account system Sendan has no equivalent of |

Nothing in that list stops a file being sent or received. If one of them matters
for how you use a client, it is worth an issue rather than a surprise.

## Where the behaviour differs

**A download is spent on transfer, not on asking.** That protocol spends one
when a client **asks for a token**, so a client that asks and never transfers
still consumes one. Sendan counts bytes actually served: a download nobody
received is not a download. The count still advances on transfer, so a limit is
still a limit — it is simply not spent by a request that delivered nothing.

**An upload with no stated download limit is single-use here, and unlimited
natively.** The protocol's default is one, and its clients rely on that: a
client that does not ask for a limit has already told the user the file may be
downloaded once. A native upload that names no limit instead follows
`SENDAN_DEFAULT_MAX_DOWNLOADS`, which is `0` — no limit — unless the operator
says otherwise.

> [!NOTE]
> This is not a difference chosen for its own sake; it is what conformance
> requires. Reading the absent value as "unlimited" — which is what this did
> first — turns an upload its sender was told was single-use into a permanent
> one. It was found by downloading the same link twice, and it is the reason
> the compatibility suite runs a real client on every pull request rather than
> a transcript of one.

## What it shares with a native upload

Everything below the protocol. A compatibility upload is an ordinary row: it
expires, it is reaped, its content is encrypted at rest, and deleting it
destroys the key that opens it, all through the same code that does those things
for a native upload. The weaker credential lives in its own table so the
difference is structural rather than a convention.
