# Sendan

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Self-hosted, end-to-end encrypted file sharing.

Sendan accepts a file, returns a link, and stores only ciphertext it cannot
read. The upload is removed on the sender's terms: after a deadline, after a
number of downloads, or on demand.

The name is 船団 *sendan*, a convoy of ships carrying cargo across together.

> [!IMPORTANT]
> **Status: beta. The planned feature set is complete; nothing has been
> independently audited.** All ten milestones are closed, and releases carry
> signed static binaries for Linux, macOS and Windows on both architectures.
>
> **What "not audited" means.** No independent review of the cryptographic
> design or of this implementation has taken place. The scheme is conventional
> and the Go and TypeScript implementations are held to each other by shared
> test vectors — which catches the two disagreeing, and says nothing about
> whether the construction is right. An unaudited implementation is not what to
> trust with something whose exposure would be serious, and that is a statement
> about review rather than about how finished this is.
>
> **Built and tested:** the cryptographic scheme in Go and TypeScript, verified
> against each other by shared test vectors; metadata storage on SQLite and
> PostgreSQL; blob storage on the filesystem and S3-compatible object stores,
> with encryption at rest; the expiry, revocation and reaping lifecycle;
> configuration, structured logging and abuse controls; the web client's
> upload and download flows, with per-upload password, expiry and download
> limit; owner-held management, so the browser that made an upload can list it,
> delete it early, and export that list to a passphrase-encrypted file; the
> interface itself, in light and dark themes, on one layout that holds from a
> small phone to a desktop display; and optional wrapping of at-rest keys under
> an operator-held master key, so a database backup carries nothing that opens
> a blob.
>
> **The command line client is complete:** `sendan up` and `sendan down` send
> and receive with password, expiry and download-limit options, `sendan delete`
> removes an upload early, and `sendan verify` checks an instance against a
> published release.
>
> **Releases carry what they promise.** The current release ships those
> binaries, a signed asset manifest and checksums. The manifest is signed three
> ways — keyless, classical and post-quantum — and `sendan verify` refuses a
> signature it cannot authenticate.

## Try it

A public instance runs at **<https://demo.sendan.app>**. It is there to be used
rather than looked at: send a file, open the link in another browser, watch it
expire.

It is configured as a demo, and says so through the API the client reads:
uploads up to 50 MB, a deadline of one day by default and three at most, and a
download limit is required rather than optional. Nothing on it is backed up, and
an instance that exists to be tried on is not a place to keep anything.

**It is also an instance you do not control**, which is the one case this
project cannot answer with cryptography — see the note under *Cryptographic
design*. What it can do is let you check that the code being served is the code
that was published:

```console
$ sendan verify https://demo.sendan.app
  instance   https://demo.sendan.app
  claims     v0.3.0, commit 7d7904e, unmodified
  manifest   v0.3.0
             signed by this build's release keys, classical and post-quantum

  ✓ 31 of 31 assets match the published client
```

That compares what the instance serves against a manifest taken from the
release rather than from the instance, so the answer does not depend on the
instance being honest. Run it against any instance somebody sends you a link
from, including this one.

## Features

- **End-to-end encryption in every code path.** There is no configuration in
  which the server can read an upload.
- **Password-protected downloads**, enforced cryptographically rather than by
  server-side policy.
- **Expiry by deadline, by download count, or by manual revocation**, whichever
  occurs first.
- **Owner-held management, with no account.** The browser that made an upload
  keeps the link and an owner token, so it can list what it sent and delete a
  file early — from the page or with `sendan delete`. The instance stores only
  a hash of that token, so it cannot forge one, and cannot tell whose uploads
  are whose. The list can be exported to a passphrase-encrypted file, which is
  the only copy that survives the browser: *there is no recovery path, and the
  interface says so before anything is stored rather than after.*
- **Complete deletion.** Expired uploads leave no orphaned blobs, no tombstone
  rows, and no file identifiers in logs. Unlimited retention is available but
  must be enabled explicitly.
- **Single-container deployment.** One static binary serving an embedded web
  client, on an image with no distribution, no package manager and no shell.
  *(Builds and runs; not yet published — see the status above.)*
- **Cross-platform command line client**, sharing one cryptographic
  implementation with the server. *(Sends and receives; no binary published
  yet — see the status above.)*
- **Light and dark themes**, following the system by default with a control to
  override it, on one layout that holds from a small phone to a desktop
  display. No web font is loaded and no request leaves the instance: the whole
  stylesheet is 4 KB compressed.
- **Optional compatibility endpoints** for existing third-party clients,
  disabled by default. Tested against a real one on every pull request.
  *(Uploads made through them are **less protected** than native ones — that
  protocol has the instance check the password rather than the key, and the
  interface says so beside the file.)*

## Cryptographic design

- A random 256-bit **file key** encrypts the content using **AES-256-GCM** in
  [RFC 8188](https://www.rfc-editor.org/rfc/rfc8188) encrypted-content-encoding
  records, allowing both the browser and the CLI to stream arbitrarily large
  files at constant memory.
- The file key is **wrapped** under a key derived from a random link secret:
  `KEK = HKDF(linkSecret)`, or `HKDF(linkSecret ‖ Argon2id(password, salt))`
  when a password is set. The server stores only the wrapped key.
- The link secret is carried in the **URL fragment**, which browsers do not
  transmit. It therefore does not appear in server logs, proxy logs, or CDN
  access logs.
- Filename, media type, and size are encrypted separately. The server stores an
  opaque blob and an opaque metadata envelope.

Because the password contributes to the key-wrapping key rather than to a
server-checked token, a password-protected link cannot be opened without the
password by anyone, including the operator of the instance.

Sendan contains **no asymmetric cryptography**, which is why it ships no
post-quantum key exchange: there is no key agreement for Shor's algorithm to
attack, and Grover's algorithm leaves a 256-bit symmetric key at approximately
128-bit security. The full reasoning, including the parameter choices made
specifically for quantum resistance, is in [`docs/design.md`](docs/design.md).

> [!IMPORTANT]
> **Browser-delivered end-to-end encryption has a structural limitation.** The
> server delivers the code that performs the encryption, so a malicious operator
> can serve modified code regardless of the contents of this repository.
>
> **Running the instance yourself answers this**, and is what Sendan is for. For
> an instance you do not control, there are two answers, and both exist:
>
> - Use the command line client instead of a browser. Using it means never
>   executing that instance's code. See [`docs/cli.md`](docs/cli.md).
> - `sendan verify <url>` checks that an instance is serving the published
>   client, against a manifest from the release rather than from the instance.
>
> The manifest is **signed** — three ways, and `sendan verify` refuses one it
> cannot authenticate. Both checks work against a released instance today; the
> demo above is one, and the command that proves it is in that section.
> [SECURITY.md](SECURITY.md) sets out what each check does and does not
> establish — including that none of the signatures survives a compromise of
> this repository.

## Browser requirements

The encryption happens in the browser, so the browser has to be able to perform
it. A recent Firefox, Chrome, Edge or Safari can.

What decides it is the list of capabilities below, not a version number. Those
capabilities became available around Chrome and Edge 107, Firefox 104 and
Safari 16, which is the floor the interface is styled to — but no build setting
enforces that figure, and it is a snapshot of where browsers were rather than a
promise. The list is the thing to read: it stays true as browsers move, and it
is what the client checks at runtime, naming whichever capability is missing
instead of failing somewhere inside the cryptography.

> [!IMPORTANT]
> **An instance must be served over HTTPS.** Browsers withhold WebCrypto outside
> a secure context, so an instance on plain HTTP cannot encrypt anything at all
> — on any browser. `localhost` counts as secure, which is why a local build
> works without a certificate and a deployment does not.

Required, with no fallback: a secure context, WebCrypto, the Streams API,
reading a file as a stream, and — for password-protected files only —
WebAssembly. A browser missing any of these is told which, rather than being
shown an error from inside the cryptography.

Saving a download uses whichever of three paths the browser offers, in order:

1. **The File System Access API**, where the browser can be asked for a file to
   write. Chromium-based browsers have it; Firefox and Safari do not.
2. **A service worker**, which answers a request the page makes to itself with a
   stream of plaintext so the browser's own download machinery writes it. This
   exists for the browsers in the first line's second half — without it they
   would have only the third.
3. **A blob held in memory**, where neither is available.

Only the third is bounded by the size of a tab, so only there does a large file
fail. The first two are bounded by the disk.

## Documentation

| Document | Contents |
|---|---|
| [`docs/design.md`](docs/design.md) | Architecture, cryptographic scheme, and the reasoning behind each decision |
| [`docs/spec/wire-format-v1.md`](docs/spec/wire-format-v1.md) | Normative wire format and key schedule |
| [`docs/workflows/`](docs/workflows/README.md) | What each CI workflow does, and what a failure means |
| [`docs/cli.md`](docs/cli.md) | The command line client: installing it, and every command and option |
| [`docs/api.md`](docs/api.md) | Every endpoint: paths, methods, status codes and what each returns |
| [`docs/configuration.md`](docs/configuration.md) | Every environment variable and its default |
| [`docs/deployment.md`](docs/deployment.md) | Running the container image, the reverse proxy in front of it, backups, and what you can and cannot do when a user asks for help |
| [`docs/compatibility.md`](docs/compatibility.md) | Third-party client support: what it covers, and why those uploads are less protected |
| [`SECURITY.md`](SECURITY.md) | Threat model and vulnerability disclosure policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution process, DCO, and testing requirements |

## Roadmap

All ten [milestones](https://github.com/Serraniel/sendan/milestones) are
complete. They were sequenced so that the cryptographic core and its
cross-language test vectors were finished and verified before anything was built
on top of them, and that order is why the scheme was never adjusted to suit
something built above it.

What remains is not a feature list. An independent audit is the one thing that
would change what this is ready for, and it has not happened. Beyond that, work
is whatever is open in [issues](https://github.com/Serraniel/sendan/issues).

## License

Copyright © 2026 Serraniel and the Sendan contributors.

Licensed under [AGPL-3.0-or-later](LICENSE).

The network copyleft provision is deliberate. Operating a modified instance as a
hosted service obliges the operator to offer users the corresponding source,
which means a weakened build cannot avoid disclosure by never distributing a
binary. Every instance reports the version and commit it is running at
`/api/source`, and the web client shows it in a persistent footer along with a
link to where the corresponding source can be obtained.

Contributions are accepted under the [Developer Certificate of
Origin](https://developercertificate.org/). There is no contributor licence
agreement and no copyright assignment; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Vulnerabilities should be reported privately. See [SECURITY.md](SECURITY.md).
