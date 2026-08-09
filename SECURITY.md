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

### What Sendan cannot protect you from

> [!IMPORTANT]
> **A malicious operator can deliver modified client code.** This is not a defect
> in Sendan; it is a structural property of every browser-delivered end-to-end
> encrypted application. The server delivers the code that performs the
> encryption, so an operator seeking the key can extract it from the page before
> encryption occurs.
>
> **There is no mitigation for this today.** The intended one is a command line
> client — a fixed, reproducibly built binary obtained independently of any
> instance — and it is not built yet
> ([#42](https://github.com/Serraniel/sendan/issues/42)). Until it exists, an
> adversary who includes the operator of the instance is outside what Sendan can
> protect against, and the browser client cannot change that.
>
> The first half of checking an instance does exist: each release publishes a
> digest manifest of every file in the client, so what an instance serves can be
> compared against what was published. The program that performs that comparison
> is [#103](https://github.com/Serraniel/sendan/issues/103), also outstanding.
> `docs/design.md` §7.1 sets out what the finished mechanism does and does not
> establish — notably that it cannot detect a backdoor served only to a chosen
> victim.

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

## Cryptographic design

The full scheme, including the reasoning for using AES-256-GCM and for **not**
adding a post-quantum layer, is documented in [`docs/design.md`](docs/design.md).

If you believe the design itself is wrong — as opposed to the implementation —
that is a very welcome report, and the design document is the right thing to
critique.
