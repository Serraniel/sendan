# Configuration

Sendan is configured entirely through environment variables. Every value is
validated once at startup, and the process **refuses to start** if anything is
wrong: a server that silently degrades to a weaker setting is worse than one
that will not run.

All problems are reported together, so fixing a misconfiguration does not
require restarting repeatedly to discover the next fault.

> [!NOTE]
> **Every variable below is honoured**, with one exception named in the table.
> The transfer API is complete and the web client speaks it, so a file can be
> sent and received in a browser, or with the command line client.
>
> | Variable | Effect today |
> |---|---|
> | `SENDAN_SEND_COMPAT` | no endpoints; the compatibility layer is M7. It does log a warning at startup when enabled |
>
> Everything else applies: storage opens at startup, uploads are accepted and
> bounded, downloads are served and counted, expiry and reaping run, every
> request is rate limited, and `SENDAN_SERVE_UI` decides whether the embedded
> client is served — in a build that has one, which is a build tagged
> `embedui`. See below.

## The command line client

The client reads two variables. Neither is a server setting, and both are here
because this is where somebody looks.

| Variable | Meaning |
|---|---|
| `SENDAN_INSTANCE` | The instance `sendan up` uploads to, so `--to` need not be repeated. A link carries its own origin, so `sendan down` ignores this. |
| `SENDAN_PASSWORD` | The password, for uploading and for opening a protected file. |

> [!IMPORTANT]
> **There is no `--password <value>`, deliberately.** An argument appears in the
> process list, in shell history, and in whatever a CI job records, and the
> password contributes to the wrapping key — so it is the one value that must
> not be written down. `--password` prompts and asks twice;
> `--password-file <path>` reads one; `SENDAN_PASSWORD` is for scripts, where
> the alternative is worse.
>
> Asking twice is not politeness. A password mistyped while uploading produces a
> file nobody can open — not the sender, who never tries, and not the recipient,
> who is told only that the password did not work. Nothing later in the system
> can detect it.

## Server

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_LISTEN` | `:8080` | Address the HTTP server binds to |
| `SENDAN_BASE_URL` | `http://localhost:8080` | Externally visible origin, used to build download links. Must be absolute `http` or `https` |

> [!IMPORTANT]
> **Serve the client over HTTPS, or it cannot encrypt anything.** Browsers
> withhold WebCrypto outside a secure context, so an instance reached over plain
> `http` at anything other than `localhost` produces a client that refuses to
> run — on every browser, for every upload. The client says so plainly, and
> names the instance rather than the browser, but the only fix is a certificate.
>
> `SENDAN_BASE_URL` being `https` is also what causes HSTS to be sent. It is
> taken from configuration rather than from `X-Forwarded-Proto`, which is
> written by whatever spoke last.
>
> The instance does **not** need to be told it is behind a proxy in order to
> address itself correctly. The upload endpoint answers with a path rather than
> an absolute URL, so a client resolves it against the request it actually
> made. Nothing about the deployment has to be configured for that to be right,
> and no forwarded header is believed.
| `SENDAN_SERVE_UI` | `true` | Serve the embedded web client. `false` gives a backend-only instance from the same binary |

> [!NOTE]
> The client is embedded behind the `embedui` build tag. A binary built without
> it serves an explanation rather than the client, whatever this setting says,
> and logs a warning at startup. See [`docs/design.md`](design.md) §4.5.
| `SENDAN_SOURCE_URL` | the upstream repository | Where this instance's corresponding source can be obtained, reported at `/api/source` |

> [!IMPORTANT]
> **If you run modified code, you must set `SENDAN_SOURCE_URL`.** AGPL §13
> obliges the operator of a modified instance to offer its users the source of
> the version they are actually talking to. The default names the upstream
> repository, which is correct only for an unmodified build; leaving it in place
> on a modified instance both fails the obligation and points users at code that
> is not running.
>
> `/api/source` also reports whether the binary was built from a modified tree,
> which catches the common case of forgetting to set this. It is not a check on
> a dishonest operator: the instance compiles and serves that endpoint, so its
> answers are claims, not evidence. Checking an instance rather than believing
> it is `sendan verify`, described in [`docs/design.md`](design.md) §7.1.

## Retention

| Variable | Default | Meaning |
|---|---|---|
| `SENDAN_DEFAULT_TTL` | `24h` | Applied when an uploader does not choose one |
| `SENDAN_MAX_TTL` | `168h` | Upper bound an uploader may choose |
| `SENDAN_ALLOW_INFINITE_TTL` | `false` | Permit uploads that never expire |
| `SENDAN_INCOMPLETE_TTL` | `24h` | How long an upload may remain unfinished before it is treated as abandoned and removed |
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
| `SENDAN_RATE_LIMIT` | `120` | Sustained requests per minute, per client. `0` disables rate limiting |
| `SENDAN_RATE_BURST` | `30` | How many requests may arrive at once |
| `SENDAN_TRUSTED_PROXIES` | `0` | How many reverse proxies stand in front of this instance |

`/healthz` is never rate limited. It reads nothing, and a health check that
began failing because a limit was reached would cause the restart it exists to
prevent.

> [!WARNING]
> **`SENDAN_TRUSTED_PROXIES` is a security setting, not a convenience.**
>
> At `0`, `X-Forwarded-For` is ignored entirely and the peer address is used.
> Setting it to `1` tells Sendan to believe the last entry in that header.
>
> **Set it above the number of proxies actually in front of the instance — in
> particular, set it at all when there is no proxy — and a caller can write the
> header that decides which bucket they are charged to, and so opt out of the
> limit entirely.**
>
> Setting it too high is safe by comparison: several clients share one bucket,
> which is stricter than intended rather than weaker. Both misconfigurations
> are logged at startup.

Rate limits are keyed per address, so one abusive client cannot exhaust the
budget of others. IPv6 is keyed on the **/64** rather than the full address: a
single subscriber is commonly allocated a /64 or larger, and keying on the
address would let them present billions of distinct ones and never meet a limit
at all. Clients sharing a /64 therefore share a bucket, which is the intended
trade.

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

An unrecognised location is a **startup failure** naming the accepted forms,
never a silent fallback to the default. A server that quietly stores uploads
somewhere other than where you asked is worse than one that refuses to run.

Credentials embedded in a location are removed before it is logged, so the
startup line names the backend without disclosing its password.

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
