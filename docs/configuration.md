# Configuration

Sendan is configured entirely through environment variables. Every value is
validated once at startup, and the process **refuses to start** if anything is
wrong: a server that silently degrades to a weaker setting is worse than one
that will not run.

All problems are reported together, so fixing a misconfiguration does not
require restarting repeatedly to discover the next fault.

## Server

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_LISTEN` | `:8080` | Address the HTTP server binds to |
| `SENDAN_BASE_URL` | `http://localhost:8080` | Externally visible origin, used to build download links. Must be absolute `http` or `https` |
| `SENDAN_SERVE_UI` | `true` | Serve the embedded web client. `false` gives a backend-only instance from the same binary |

## Retention

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_DEFAULT_TTL` | `24h` | Applied when an uploader does not choose one |
| `SENDAN_MAX_TTL` | `168h` | Upper bound an uploader may choose |
| `SENDAN_ALLOW_INFINITE_TTL` | `false` | Permit uploads that never expire |
| `SENDAN_DEFAULT_MAX_DOWNLOADS` | `0` | Download limit when the uploader does not choose one. `0` means no limit |

> [!IMPORTANT]
> Setting `SENDAN_DEFAULT_TTL=0` or `SENDAN_MAX_TTL=0` requests **unlimited
> retention** and is rejected unless `SENDAN_ALLOW_INFINITE_TTL=true`.
>
> This is deliberate. Sendan's guarantee is that an expired upload leaves
> nothing behind; reaching unlimited retention by leaving a value unset would
> make that an accident rather than a choice.

## Limits

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_MAX_UPLOAD_SIZE` | `1GiB` | Largest single upload |

Sizes accept a plain byte count or a binary suffix: `1024`, `500MiB`, `2GiB`,
`1TiB`.

## Storage

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_DATABASE` | `sqlite:data/sendan.db` | Metadata store location. `sqlite:<path>` or a `postgres://` URL |
| `SENDAN_STORAGE` | `file:data/blobs` | Blob store location. `file:<path>` or an `s3://` URL |

The S3 form is `s3://key:secret@endpoint/bucket/prefix`, where the prefix is
optional and lets one bucket hold several instances. TLS is used unless
`?ssl=false` is given, so forgetting the parameter yields the safe behaviour
rather than a plaintext connection. A `?region=` parameter is accepted for
providers that require one.

The bucket must already exist. Sendan does not create it, because doing so
silently would hide a typo behind a working but wrong deployment.

> [!NOTE]
> Objects are written by the same crypto-shredding layer as local files, so an
> object store operator sees ciphertext whose key lives in the metadata
> database. Deleting the database row makes the object unreadable regardless of
> the object store's own retention, versioning or backup behaviour — which is
> worth knowing, since object stores often keep more than you asked them to.

> [!IMPORTANT]
> **Deletion is stronger on SQLite than on PostgreSQL.** SQLite is configured
> with `secure_delete`, which zeroes a deleted row's content rather than merely
> marking its page free, and Sendan checkpoints the write-ahead log after
> reaping so removed rows do not survive in it.
>
> PostgreSQL offers neither control directly. Measured against PostgreSQL 17: a
> deleted row remains in the heap file until `VACUUM`, which Sendan runs after
> reaping, and that does remove it. What persists is the **write-ahead log**,
> which retains the row until its segment is recycled, and PostgreSQL has no
> equivalent of truncating it on demand.
>
> A recovered row yields the at-rest key, and so the ability to decrypt a blob
> that also survived its own deletion. That is the end-to-end ciphertext, **not
> the content** — reading it still requires the link secret, which never reaches
> the server.
>
> Choose SQLite if the stronger guarantee matters, or encrypt the database
> volume. Both backends pass the same conformance suite, so they behave
> identically in every other respect.

## Compatibility

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_SEND_COMPAT` | `false` | Enable third-party client compatibility endpoints |

> [!WARNING]
> Uploads made through the compatibility endpoints use that protocol's weaker,
> **server-enforced** password model rather than Sendan's cryptographic one.
> They are less secure than native uploads. The interface says so, and the
> server logs a warning at startup when this is enabled.

## Logging

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_LOG_LEVEL` | `info` | One of `debug`, `info`, `warn`, `error` |
| `SENDAN_LOG_FORMAT` | `json` | `json` or `text` |

> [!NOTE]
> File identifiers are never written to logs verbatim. They appear as a
> truncated hash, which is enough to correlate lines within one request and
> useless for enumerating uploads. Secrets are not logged at all, not even as a
> correlatable hash. See `internal/logging`.
