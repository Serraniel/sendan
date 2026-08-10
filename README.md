# Sendan

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Self-hosted, end-to-end encrypted file sharing.

Sendan accepts a file, returns a link, and stores only ciphertext it cannot
read. The upload is removed on the sender's terms: after a deadline, after a
number of downloads, or on demand.

The name is 船団 *sendan*, a convoy of ships carrying cargo across together.

> [!WARNING]
> **Status: pre-alpha, and nothing has been audited.** A file can be sent and
> received in a browser today; a hostile operator is not yet something this can
> defend against. Do not use Sendan to protect anything that matters.
>
> **Built and tested:** the cryptographic scheme in Go and TypeScript, verified
> against each other by shared test vectors; metadata storage on SQLite and
> PostgreSQL; blob storage on the filesystem and S3-compatible object stores,
> with encryption at rest; the expiry, revocation and reaping lifecycle;
> configuration, structured logging and abuse controls; and the web client's
> upload and download flows, with per-upload password, expiry and download
> limit.
>
> **Partly built:** the command line client sends and receives (`sendan up`,
> `sendan down`), with password, expiry and download-limit options. Releases
> carry static binaries for Linux, macOS and Windows on both architectures, with
> checksums and a reproduction procedure, and `sendan verify` checks that an
> instance serves the published client — but releases are not signed yet.
>
> **Not built:** the container image.

## Features

- **End-to-end encryption in every code path.** There is no configuration in
  which the server can read an upload.
- **Password-protected downloads**, enforced cryptographically rather than by
  server-side policy.
- **Expiry by deadline, by download count, or by manual revocation**, whichever
  occurs first.
- **Complete deletion.** Expired uploads leave no orphaned blobs, no tombstone
  rows, and no file identifiers in logs. Unlimited retention is available but
  must be enabled explicitly.
- **Single-container deployment.** One static binary serving an embedded web
  client. *(The binary serves the client today; the container image is not
  built.)*
- **Cross-platform command line client**, sharing one cryptographic
  implementation with the server. *(Sends and receives; not yet released as a
  binary.)*
- **Optional compatibility endpoints** for existing third-party clients,
  disabled by default. *(Not built.)*

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
> an instance you do not control, the answer is the command line client: using it
> means never executing that instance's code. It sends and receives today, but
> **must be built from source** — there is no released binary to check, and no
> `sendan verify` yet. See [SECURITY.md](SECURITY.md) for what that leaves open.

## Browser requirements

The encryption happens in the browser, so the browser has to be able to perform
it. A recent Firefox, Chrome, Edge or Safari can; the build targets roughly
Chrome and Edge 107, Firefox 104, and Safari 16.

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
| [`docs/api.md`](docs/api.md) | Every endpoint: paths, methods, status codes and what each returns |
| [`docs/configuration.md`](docs/configuration.md) | Every environment variable and its default |
| [`SECURITY.md`](SECURITY.md) | Threat model and vulnerability disclosure policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution process, DCO, and testing requirements |

## Roadmap

Work is tracked in [milestones](https://github.com/Serraniel/sendan/milestones),
sequenced so that the cryptographic core and its cross-language test vectors are
completed and verified before anything is built on top of them.

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
