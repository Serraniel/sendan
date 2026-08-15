# Deployment

Sendan is one static binary. The container image is that binary on an empty
base — no distribution, no package manager, no shell. Around 17 MB, of which
about 16 is the program.

> [!NOTE]
> **No image has been published yet**, because no release has been tagged. The
> pipeline that builds and signs it is in place. Until a tag exists, build the
> image yourself from a checkout — the instructions below work either way.

## The short way

[`compose.yaml`](../compose.yaml) in the repository root runs Sendan behind a
reverse proxy that obtains a certificate on its own:

```sh
SENDAN_DOMAIN=files.example.org docker compose up -d
```

That is the whole deployment. The domain must already resolve to the host, and
ports 80 and 443 must reach it, because the proxy proves control of the name to
get a certificate.

Until a release is tagged there is no published image, so build this checkout
instead:

```sh
SENDAN_DOMAIN=files.example.org docker compose up -d --build
```

> [!NOTE]
> Building needs BuildKit. The `Dockerfile` cross-compiles, which requires
> `docker buildx`; on a Docker installation without it the build fails at the
> first line with `failed to parse platform`. Debian and Ubuntu ship it in
> `docker-buildx-plugin`, Arch in `docker-buildx`.

## Running it without compose

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

TLS is not only about confidentiality here. Streaming an upload from a browser
needs HTTP/2, which browsers offer only over TLS, so an instance served over
plain HTTP falls back to buffering the file in memory before sending it.

### The failure operators hit first

**A default nginx refuses every upload over one megabyte.** Measured, not
recalled: with a stock configuration, 400 kB uploads and 2 MB answers `413` on
the `PATCH`, logged as *client intended to send too large body*. The default
`client_max_body_size` is `1m`.

Three settings, all of which matter:

```nginx
server {
    client_max_body_size 0;          # or larger than SENDAN_MAX_UPLOAD_SIZE
    proxy_request_buffering off;     # stream uploads through
    proxy_buffering off;             # stream downloads back
    proxy_http_version 1.1;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # A large transfer over a slow connection is a long-lived request, not
        # a stalled one. The default of 60s ends it midway.
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

With those, the same 2 MB upload and download completes and the bytes match.

`proxy_request_buffering off` is the one with consequences beyond an error
message. Left on, nginx collects the entire body before Sendan sees any of it:
a constant-memory transfer becomes a copy of every upload on the proxy's disk,
and resumability stops meaning anything, because a resumed upload has to be
re-sent in full before the offset is even consulted.

Caddy needs none of this for uploads — it does not buffer request bodies — but
it does buffer responses unless told otherwise, which is what
`flush_interval -1` in [`deploy/Caddyfile`](../deploy/Caddyfile) is for.

## Backups

There is less to back up than usual, and restoring one has a consequence worth
understanding before it happens.

The volume holds two halves that must be consistent with each other: the
metadata, which records what exists and when it expires, and the blobs, which
hold the ciphertext. Copying them at different moments gives metadata naming
blobs that are not in the copy, or blobs no row refers to.

**Do not copy `sendan.db` while the instance is running.** SQLite in WAL mode
keeps recent writes in a side file, and a plain copy takes the database without
them. There is no shell and no `sqlite3` in the image to run a proper online
backup with — that is the point of the image — so the copy is made from outside,
with the instance stopped:

```sh
docker compose stop sendan
docker run --rm \
  -v sendan_sendan-data:/data:ro \
  -v "$PWD":/backup \
  alpine tar czf /backup/sendan-$(date +%F).tar.gz -C /data .
docker compose start sendan
```

Stopping is what makes the two halves consistent, and it is brief: the archive
is of a stopped instance's disk, not a live one's.

For a deployment where stopping is not acceptable, run PostgreSQL and an object
store instead. Then `pg_dump` handles the metadata online, the object store
handles its own durability, and the container holds nothing worth backing up.

### What a restore means

Restoring an older backup brings back uploads that were deleted, expired, or
had run out of downloads. Those links start working again — a file somebody was
told had gone has not gone.

That is a property of restoring, not a defect, but it is at odds with what this
project promises about deletion. Keep backups only as long as they are needed,
and treat a restore as a decision rather than a routine.

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

### Where it came from

Every image carries **SLSA build provenance** and an **SBOM**, one of each per
architecture. The provenance is what ties an image to this repository and to the
workflow run that produced it:

```sh
docker buildx imagetools inspect ghcr.io/serraniel/sendan:v0.5.0 \
  --format '{{ json .Provenance }}'
```

It records the build arguments, so the version an image reports at `/api/source`
can be checked against the version it was actually built with rather than taken
on trust. It also lists the resolved dependencies, including the digests of the
base images the build used.

The bill of materials, for asking what is in the image without running it:

```sh
docker buildx imagetools inspect ghcr.io/serraniel/sendan:v0.5.0 \
  --format '{{ json .SBOM }}'
```

> [!NOTE]
> These are BuildKit attestations attached to the image index, not signatures
> made with `cosign attest`. `cosign verify-attestation` does not read them —
> the commands above do.

Attestations say what a build claims about itself. The signature above is what
makes those claims worth reading, because it is the part an attacker cannot
produce without the workflow.

### What none of this establishes

That the source it names is source you have read. Provenance proves an image was
built by this workflow from a particular commit; it says nothing about what that
commit contains. For the client an instance serves, `sendan verify` is the check
that closes that gap, and it works against a running instance rather than
against an image.

## Backend-only mode

`SENDAN_SERVE_UI=false` disables the embedded client, so the same image serves
as an API-only instance for an operator fronting it with their own. One image,
not two.
