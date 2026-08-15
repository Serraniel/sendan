# Deployment

Sendan is one static binary. The container image is that binary on an empty
base — no distribution, no package manager, no shell. Around 17 MB, of which
about 16 is the program.

> [!NOTE]
> **No image has been published yet**, because no release has been tagged. The
> pipeline that builds and signs it is in place. Until a tag exists, build the
> image yourself from a checkout — the instructions below work either way.

## Running it

```sh
docker run -d --name sendan \
  --read-only --tmpfs /tmp \
  -v sendan-data:/var/lib/sendan \
  -p 8080:8080 \
  -e SENDAN_BASE_URL=https://files.example.org \
  ghcr.io/serraniel/sendan:latest
```

To build it instead of pulling it:

```sh
docker build -t sendan .
```

`SENDAN_BASE_URL` is the one variable with no sensible default: it is what goes
into the links the instance hands out, so it has to be the address people will
actually use, not the one the process can see.
[`docs/configuration.md`](configuration.md) has every variable.

### Why `--read-only --tmpfs /tmp`

The root filesystem is read only because nothing needs to write to it. `/tmp`
is the exception: an S3 backend spools an upload there while it is being stored
([#111](https://github.com/Serraniel/sendan/issues/111) is about removing that).
Without the `tmpfs`, a read-only container fails on the first upload rather than
at startup, which is the worst time to find out.

The filesystem backend does not use `/tmp` — it writes to its own directory —
but the flag costs nothing and means the same command works for both.

### The volume

`/var/lib/sendan` holds everything that must survive a restart:

| | |
|---|---|
| `sendan.db` | SQLite metadata, with the default `SENDAN_DATABASE` |
| `blobs/` | encrypted content, with the default `SENDAN_STORAGE` |

Both defaults point inside the volume, so a plain `docker run -v` is the whole
of persistence. Pointing `SENDAN_DATABASE` at Postgres or `SENDAN_STORAGE` at an
object store replaces the corresponding half, and an instance using both needs
no volume at all.

The image runs as UID **65532**, and the volume is created owned by it. A bind
mount from the host is not: `chown 65532:65532` the directory first, or the
process will start and fail to write.

## In front of it

The binary does not terminate TLS. Run it behind a reverse proxy that does, and
set `SENDAN_TRUSTED_PROXIES` to **how many proxies stand in front of it** —
normally `1`. It defaults to `0`, which ignores `X-Forwarded-For` entirely, and
then every request appears to come from the proxy: rate limiting is
per-address, so one client's burst is everybody's.

It is a count and not a switch on purpose. Believing one entry more of that
header than there are proxies lets a client write its own address into it.

The proxy must not buffer request bodies. Uploads are streamed, and a proxy that
collects a multi-gigabyte body before passing it on turns a constant-memory
transfer into an outage.

## What the image contains

```
/sendan                              the binary
/etc/ssl/certs/ca-certificates.crt   for reaching Postgres or S3 over TLS
/var/lib/sendan                      empty, owned by 65532
```

That is all of it. There is no shell, so `docker exec` gets you nothing, and
neither does anything that reaches the container looking for one.

The image is built for `linux/amd64` and `linux/arm64`, from the same source
with the same compiler flags as the released binaries, so an image and a release
binary of the same version are the same program.

## Checking what you pulled

Each image is signed at release time:

```sh
cosign verify ghcr.io/serraniel/sendan:v0.5.0 \
  --certificate-identity-regexp '^https://github\.com/Serraniel/sendan/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

An image reports what it was built from at `/api/source`, which is a claim
rather than a fact — [`SECURITY.md`](../SECURITY.md) explains what turns it into
something checkable, and `sendan verify` is what does the checking.

## Backend-only mode

`SENDAN_SERVE_UI=false` disables the embedded client, so the same image serves
as an API-only instance for an operator fronting it with their own. One image,
not two.
