# Security Policy

## Reporting a vulnerability

**Please report privately. Do not open a public issue.**

Either channel is acceptable:

- **GitHub private vulnerability reporting** —
  [report a vulnerability](https://github.com/Serraniel/sendan/security/advisories/new).
- **Email** — <mail@serraniel.dev>, for researchers who prefer not to use GitHub.
  Encrypted mail is welcome and preferred for anything sensitive.

### PGP

```
B589 0C67 9CA1 66FE B2EC  94AB 3690 B4E7 3645 25D3
```

```sh
gpg --keyserver keyserver.ubuntu.com \
    --recv-keys B5890C679CA166FEB2EC94AB3690B4E7364525D3
```

Please verify the fingerprint against a second source before relying on it.

Please include enough detail to reproduce: the affected version or commit, the
component (server, web client, or CLI), and a proof of concept where available.

Reports are acknowledged within **7 days**. Sendan is maintained by a single
person outside of working hours; remediation timelines will reflect that. If no
acknowledgement is received within 7 days, please escalate by contacting the
maintainer publicly **without disclosing details**.

Reporters are free to publish on their own timeline. A 90-day disclosure period
is considered reasonable and will not be contested. There is no bug bounty
programme. Reporters are credited in the resulting advisory unless they request
otherwise.

## Supported versions

> [!WARNING]
> **Sendan is pre-alpha and nothing here has been implemented or audited yet.**
> No version is currently supported, and Sendan should not be used to protect
> anything real.

## Threat model

Understanding what Sendan does and does not defend against matters more than any
individual bug report.

### What Sendan is designed to resist

- **A server operator reading your files.** Content, filename, MIME type, and
  size are encrypted client-side. The server sees ciphertext and an opaque
  metadata envelope.
- **A database or storage compromise.** The same holds for anyone who steals the
  disk or the database — the decryption key never reaches the server.
- **Link secrets appearing in logs.** The secret lives in the URL fragment,
  which browsers never send to the server, combined with
  `Referrer-Policy: no-referrer`.
- **Someone holding the link but not the password.** A password contributes to
  the key-wrapping key, so it is enforced cryptographically rather than by
  server-side policy. Even the operator cannot bypass it.
- **Data surviving expiry.** Expired uploads are hard-deleted, with no
  soft-delete rows, no tombstones, and no identifiers retained in logs.
- **A cold copy of the database**, if an operator configures a master key. The
  per-file at-rest keys are then stored wrapped, so a backup, a volume snapshot
  or a decommissioned disk carries nothing that opens a blob. Off by default,
  because losing that key makes every upload unrecoverable.
  [`docs/configuration.md`](docs/configuration.md) has the procedure. This is
  defence in depth below the content guarantee, which rests on the link secret
  and is unchanged either way — and it does nothing against a live host, where
  the key is in memory by definition.

### What Sendan cannot protect you from

> [!IMPORTANT]
> **A malicious operator can deliver modified client code.** This is not a defect
> in Sendan; it is a structural property of every browser-delivered end-to-end
> encrypted application. The server delivers the code that performs the
> encryption, so an operator seeking the key can extract it from the page before
> encryption occurs.
>
> **What you can do today: run the instance yourself.** Sendan is self-hosted,
> and an operator who is you is not an adversary. That is a complete answer for
> your own files and no answer at all for a file somebody sends you from an
> instance you do not control.
>
> **For that case, use the command line client instead of a browser.** It sends
> and receives, and using it means never executing the instance's code — which is
> the whole of this problem. See **Verifying the command line client** below for
> how to check the binary you have is the one that was published.
>
> **Checking that a browser is being served the published client is separate,
> and can be done today.** Three parts, all in this repository:
>
> | Part | State |
> |---|---|
> | A digest manifest of every file in the published client | **done** — published with each release ([#102](https://github.com/Serraniel/sendan/issues/102)) |
> | `sendan verify <url>`, which fetches what an instance serves and compares | **done** — see **Verifying an instance** below ([#103](https://github.com/Serraniel/sendan/issues/103)) |
> | A signature over that manifest | **done** — see **Verifying the manifest by hand** below ([#104](https://github.com/Serraniel/sendan/issues/104)) |
>
> `sendan verify` refuses to use a manifest it cannot authenticate, so replacing
> the manifest on the releases page no longer changes what an instance is checked
> against — it produces a refusal instead. `docs/design.md` §7.1 sets out what
> the mechanism does and does not establish, notably that it cannot detect a
> backdoor served only to a chosen victim.

Also out of scope:

- **Anyone you gave the link to.** The link *is* the credential. Sendan has no
  way to distinguish an intended recipient from someone who read over their
  shoulder.
- **A compromised endpoint.** Malware on the sender's or recipient's machine
  defeats client-side encryption entirely.
- **Traffic analysis.** Sendan does not hide upload times, the fact that you are
  using it, or the size of a file. The *metadata envelope* is padded, so the
  filename and media type do not leak their lengths, and the metadata endpoint
  deliberately omits the size for the same reason — but stored ciphertext is
  proportional to the file, so anyone who can observe a transfer or measure a
  response can infer roughly how large it is. Content padding is not
  implemented.
- **Third-party client compatibility mode**, when enabled, uses that protocol's
  weaker server-enforced password model for interoperability. Uploads made
  through those endpoints are **less secure** than native ones, and the interface
  states so.

## Verifying the command line client

The client is the trust anchor, so it is worth being able to check rather than
assume. Each release publishes a binary for every supported platform and a
`SHA256SUMS` file beside them, at
[github.com/Serraniel/sendan/releases](https://github.com/Serraniel/sendan/releases).
[`docs/cli.md`](docs/cli.md) has the per-platform download and install steps.

> [!NOTE]
> **No release has been cut yet.** The pipeline that produces and checks these
> is in place, and this describes what it publishes. Until a tag exists, build
> from source — which is the stronger check anyway, and is the second procedure
> below.

**Check what you downloaded:**

```sh
sha256sum -c SHA256SUMS --ignore-missing
sendan version          # must match the release you took the checksums from
```

That tells you the file is the one the release published. It does not tell you
the release was built from the source in this repository — for that, build it
yourself and compare:

```sh
git checkout v0.5.0        # the tag the release names

SENDAN_VERSION=v0.5.0 \
SENDAN_COMMIT=<the commit the release names> \
  ./scripts/release-build.sh

sha256sum -c dist/SHA256SUMS
```

Identical bytes mean the published binary contains nothing that is not in the
source you just read.

> [!IMPORTANT]
> **Use the same Go toolchain.** Two versions of the compiler do not produce the
> same bytes, and a mismatch looks exactly like a compromised binary. Each
> release records the version it used; `REPRODUCING.md` beside the binaries has
> the exact command.

The build is deterministic because it is made so: `CGO_ENABLED=0` (also what
makes it static, with no runtime dependency), `-trimpath` so no path from the
building machine survives, `-buildvcs=false` so no version control state leaks
in, and `-buildid=` because that identifier is not stable across environments.
Version and commit are injected rather than discovered, which is why a
reproduction has to pass them.

Continuous integration builds every target **twice**, with the build cache
cleared in between, and fails the release if the checksums differ. That check
runs the same script you would.

> [!NOTE]
> **The checksums are not yet signed.** Anybody who could replace a binary on
> the releases page could replace the checksums beside it, so this establishes
> that a download was not corrupted and that a build is reproducible — not that
> the release came from this project. Signing is
> [#104](https://github.com/Serraniel/sendan/issues/104). Until then, a
> reproduction from source is the stronger check, because it does not depend on
> the release page being honest.

## Verifying an instance

The client bundle is the trust boundary: the server only ever holds ciphertext,
so what decides whether a file is safe is the JavaScript the instance delivered.
Checking an instance therefore means checking what it served.

```sh
sendan verify https://files.example.org
```

```
  instance   https://files.example.org
  claims     v0.5.0, commit 1a2b3c4, unmodified
  manifest   v0.5.0
             signed by this build's release key

  ✓ 41 of 41 assets match the published client
```

and when they do not, the exit status is non-zero and the assets are named:

```
  ✗ /_app/immutable/chunks/crypto.BxK2.js
      served   sha256-9f3a…
      expected sha256-2c71…

  This instance is not serving the published client. Do not assume
  uploads made through it are end-to-end encrypted.
```

The manifest comes from the **release**, never from the instance — an instance
serving the statement it is measured against would be attesting to itself.
`--manifest <path|url>` takes one directly, which is how a fork with its own
releases is checked, and how this works offline.

`/api/source` is read only to know *which* published build to compare against.
It is a claim, and an instance that lies about its version is caught by the
digests failing to match the version it named.

### The manifest must be signed

A manifest fetched over the network is refused unless it carries a valid
detached signature by the release key, whose public half is compiled into the
binary rather than fetched — a key obtained at the moment of checking is a key
whoever answers the request gets to choose. **Refused, not warned about:**
carrying on after a bad signature would replace the question "is this the
published client?" with "does this instance agree with a file I found next to
it?", which anyone who can reach that file can answer however they like.

Two cases are reported differently, because they call for different things:

| | |
|---|---|
| the signature does not verify | the manifest is not the one that was published |
| no signature is published | that release cannot be checked at all |

`--key <line\|path>` checks against a key you obtained some other way, which is
how a fork's releases are verified.

A manifest given as a **local file** is used without a signature, and the report
says so. Somebody who built the client from source and produced their own
manifest is the authority for it; demanding our signature on their own work
would ask them to trust us about something they already know first-hand.

### Verifying the manifest by hand

Two signatures cover the manifest, and `sendan verify` requires both.

The first is [minisign](https://jedisct1.github.io/minisign/) format, so the
command line client is not the only thing that can check it:

```sh
gh release download v0.5.0 -p 'manifest.json*'
minisign -Vm manifest.json -P '<the release public key>'
```

The second is **SLH-DSA** — SPHINCS+ as standardised — which rests only on hash
functions and so is not exposed to Shor's algorithm:

```sh
go run ./tools/pq-sign verify release.pqpub manifest.json
```

Signing is the one place in this project where post-quantum primitives genuinely
apply. The encryption is symmetric and already out of reach; a signature is
different, because it has to still mean something years after it was made. An
adversary who records a release today and eventually has a quantum computer
defeats the first signature and not the second.

SLH-DSA has no third-party tool equivalent to minisign, so unlike the first this
signature can only be checked with software from this repository. That is the
cost of the conservative scheme, and it is why it is the *second* signature
rather than the only one.

Both public keys are published in [`docs/cli.md`](docs/cli.md). A signature also
goes into Sigstore's public transparency log at release time, which is a second,
independent record of what was published and by which workflow:

```sh
cosign verify-blob \
  --bundle manifest.json.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Serraniel/sendan/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  manifest.json
```

The two signatures rest on different things. The minisign one is made offline
by a key CI never holds, so compromising this repository does not produce one.
The Sigstore one is made by CI and cannot be made without running the workflow,
which is publicly logged. Checking both means a forgery has to survive both.

`SHA256SUMS` is signed the same way, so the checksum file the install
instructions tell you to trust is itself checkable.

### What this establishes

| | |
|---|---|
| The instance serves the published client | **verified**, for the response this verifier received |
| The client was modified | **detected** |
| `/api/source` misreports the version | **detected** |
| A backdoored bundle served to a chosen victim and a clean one to verifiers | ⚠️ **not detected** |
| Server-side code | not covered, and does not need to be: it only ever holds ciphertext |

That last gap is inherent to verifying from a different client than the victim
uses. It is narrowed by anyone being able to run this, from anywhere, at any
time: a broad attack is visible to any observer, so it has to be precisely
targeted to survive. Closing it for a specific person would need a verifier
inside their browser, which `docs/design.md` §7.1 records as considered and not
planned.

> [!NOTE]
> Verifying the binary (above) and verifying an instance (here) answer different
> questions, and both are worth asking. The first says the program doing the
> checking is the published one. The second says the instance is serving the
> published client. Neither implies the other.

## Cryptographic design

The full scheme, including the reasoning for using AES-256-GCM and for **not**
adding a post-quantum layer, is documented in [`docs/design.md`](docs/design.md).

If you believe the design itself is wrong — as opposed to the implementation —
that is a very welcome report, and the design document is the right thing to
critique.
