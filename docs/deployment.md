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
  --read-only \
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

### Why `--read-only`

Nothing needs to write to the root filesystem. Neither backend needs scratch
space: the filesystem one writes beside its blobs, and the object store
accumulates a partial upload in the object store.

That was not always true — an S3 backend used to spool each upload to local
disk, so a read-only container needed a writable `/tmp` and failed on the first
upload without one. It no longer does. A 12 MB upload, larger than one multipart
part, completes in a container with no writable filesystem outside its volume.

Adding `--tmpfs /tmp` is harmless if you prefer it, and no longer required.

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

### The three shapes

Metadata and blobs are configured separately, which gives three deployments
worth naming. [`compose.yaml`](../compose.yaml) is the first; the other two are
the same file with `environment:` changed.

**One volume, no other services.** The default, and the right answer for a
personal instance:

```yaml
environment:
  SENDAN_BASE_URL: https://${SENDAN_DOMAIN}
  SENDAN_TRUSTED_PROXIES: "1"
volumes:
  - sendan-data:/var/lib/sendan
```

**Object storage for blobs, SQLite for metadata.** Content goes to a bucket;
the volume still holds the database, so it is still the thing to back up:

```yaml
environment:
  SENDAN_BASE_URL: https://${SENDAN_DOMAIN}
  SENDAN_TRUSTED_PROXIES: "1"
  SENDAN_STORAGE: s3://KEY:SECRET@s3.example.org/sendan
volumes:
  - sendan-data:/var/lib/sendan
```

**Neither on disk — no volume at all.** With PostgreSQL and an object store,
the container holds nothing that must survive it:

```yaml
environment:
  SENDAN_BASE_URL: https://${SENDAN_DOMAIN}
  SENDAN_TRUSTED_PROXIES: "1"
  SENDAN_DATABASE: postgres://sendan:secret@db.example.org/sendan
  SENDAN_STORAGE: s3://KEY:SECRET@s3.example.org/sendan
# no volumes at all
```

This is the shape to run more than one replica in. Nothing about a partial
upload is kept in the process or on its disk, so a resumed chunk reaching a
different replica finds the upload rather than nothing.

> [!IMPORTANT]
> Deleting is **weaker on PostgreSQL than on SQLite**. A deleted row survives in
> the write-ahead log until its segment is recycled, and PostgreSQL offers no
> way to truncate that on demand. `docs/design.md` §3 sets out exactly what
> persists; a master key narrows it, because what survives is then a wrapped key
> rather than a usable one.

Credentials appear in these URLs, so they belong in an environment file or a
secret rather than a compose file in version control. The startup log redacts
them; a `git log` does not.

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

**The two halves are useless apart, and must be captured together.** The
metadata records what exists, when it expires, and — crucially — the key that
decrypts each blob. The blobs hold the ciphertext. A database backup without
its blobs restores rows pointing at content that is gone; a backup of the blobs
without the database restores files nothing holds a key for, which is to say
noise. Copying them at different moments gives a subtler version of the same
thing: metadata naming blobs the copy does not contain, or blobs no row refers
to.

That matters most in the split deployments, where the halves live in different
systems and are easy to back up on different schedules:

| Shape | Metadata | Blobs |
|---|---|---|
| one volume | in the volume | in the volume — one archive covers both |
| object store for blobs | in the volume | in the bucket: enable versioning, and keep it at least as long as the volume's backups |
| PostgreSQL and object store | `pg_dump` | the bucket — take the dump **first**, so every row it names already exists in the bucket |

**Take the metadata first** in every shape. Whichever order you choose, uploads
that happen during the window end up mismatched; the order decides which kind:

- Metadata first — the mismatches are uploads *deleted* during the window, so
  the restored instance refuses files that were meant to be gone anyway, and
  gains some unreferenced blobs.
- Blobs first — the mismatches are uploads *created* during the window, so the
  restored instance has rows for files somebody was told had uploaded
  successfully, and cannot serve them.

An unreferenced blob is unreadable, because the key that opens it was in the row
that is missing. It is wasted space and nothing more — but note that **nothing
sweeps it up**: reaping works from the database outwards, so a blob no row
mentions is invisible to it and stays until somebody removes it by hand.

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

## What you can do when a user asks

An operator running this will be asked for help, and most of the usual answers
are not available here. That is the design working, but it sets support
expectations badly if nobody says so in advance.

| The request | What you can do |
|---|---|
| "I lost the link." | Nothing. The part after `#` never reaches the instance, is not in any log, and is not in the database. There is no reissue, and no partial recovery: the file is ciphertext nobody holds the key to. |
| "I lost the fragment but have the rest of the link." | Nothing, for the same reason. The identifier alone names a blob that cannot be decrypted. |
| "I forgot the password." | Nothing, for a native upload. The password contributes to the wrapping key rather than being checked, so there is no stored value to reset and no way to try one on a user's behalf. For an upload made through the compatibility endpoints the answer differs, and not in your favour — see below. |
| "Delete my upload." | They can, if they still hold the owner token: from the page or with `sendan delete`. You cannot do it on their behalf without it — the instance keeps only a hash — and if they hand you the token you are simply another holder of it, which is worth being reluctant about. |
| "Which files are mine?" | Nothing. There are no accounts, and no record connects an upload to a person. The list a browser shows is held in that browser. |
| "I cleared my browser data." | Nothing, unless they exported the list beforehand. The export is encrypted under a passphrase you also cannot recover. |
| "Take this file down." | Partly. There is **no administrative command for this** — the binary has no such subcommand and the API has no such endpoint. What you have is the database: deleting the upload's row destroys the at-rest key stored in it, and the blob is unreadable from that moment whether or not the object itself has gone yet. Remove the blob too, or the reaper's guarantee of leaving nothing behind stops holding for that upload. |

The pattern is that possession is the only credential. Anything you could do on
a user's behalf without it, an attacker could do by asking you for it — which is
why the honest answer to most of these is that the instance genuinely cannot,
not that policy forbids it.

The one exception is the last row, and it is asymmetric on purpose: an operator
can destroy an upload but cannot open one. Nothing in the removal path needs the
key, and nothing an operator holds produces it.

**Uploads made through the compatibility endpoints do not follow this pattern.**
That protocol has the instance check the password instead of the password
contributing to the key, so the value a password is checked against is a column
in the database — and anything an operator can write, an operator can replace.
The password gate on such an upload is therefore the operator's to reset, not
only the uploader's. The file still cannot be read without the link, because the
content key is still only in the fragment and no operator holds it, but a
protection the uploader believed was theirs alone is not. This is one of the
reasons those endpoints are off unless an operator turns them on;
`docs/compatibility.md` sets out the rest.

Two consequences worth stating to users before they rely on the service, rather
than at the moment they need help:

- **A lost link is a lost file.** Sending it to oneself is not paranoia.
- **The browser holding an upload list is the only thing holding it.** The
  export exists so that losing it is a decision rather than an accident;
  `SECURITY.md` sets out what the export costs in exchange.

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
