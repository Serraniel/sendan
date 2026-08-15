# The command line client

`sendan` sends and receives files through a Sendan instance, and checks that an
instance is serving the client it claims to.

It is a separate binary from the server on purpose. This is the program you are
asked to obtain and trust — see [`docs/design.md`](design.md) §7.1 — so it links
none of the server's dependencies: no database drivers, no object storage
client, no embedded web client.

> [!IMPORTANT]
> **No release has been published yet.** The release pipeline is in place and
> produces binaries and checksums for every platform below, but no tag has been
> cut, so today the only way to get `sendan` is to build it. The download
> instructions describe what a release will provide; the build instructions
> describe what works now.

## Building it

Needs [Go](https://go.dev/dl/) 1.25 or later, and nothing else.

```sh
git clone https://github.com/Serraniel/sendan
cd sendan
go build -o sendan ./cmd/sendan-cli
./sendan version
```

That works on Linux, macOS and Windows alike. To produce the same static,
stripped binaries a release does — for all six platforms at once:

```sh
./scripts/release-build.sh
```

They land in `dist/`, with a `SHA256SUMS` beside them.

## Installing a release

Once a release exists, each one carries a static binary per platform. There is
nothing to install: the binary has no runtime dependency.

| Platform | File |
|---|---|
| Linux, Intel/AMD | `sendan-linux-amd64` |
| Linux, ARM | `sendan-linux-arm64` |
| macOS, Intel | `sendan-darwin-amd64` |
| macOS, Apple silicon | `sendan-darwin-arm64` |
| Windows, Intel/AMD | `sendan-windows-amd64.exe` |
| Windows, ARM | `sendan-windows-arm64.exe` |

**Linux and macOS:**

```sh
curl -LO https://github.com/Serraniel/sendan/releases/latest/download/sendan-linux-amd64
curl -LO https://github.com/Serraniel/sendan/releases/latest/download/SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing        # shasum -a 256 -c on macOS
chmod +x sendan-linux-amd64
sudo mv sendan-linux-amd64 /usr/local/bin/sendan
sendan version
```

**Windows**, in PowerShell:

```powershell
curl.exe -LO https://github.com/Serraniel/sendan/releases/latest/download/sendan-windows-amd64.exe
curl.exe -LO https://github.com/Serraniel/sendan/releases/latest/download/SHA256SUMS

# Compare against the line for this file in SHA256SUMS
Get-FileHash .\sendan-windows-amd64.exe -Algorithm SHA256

.\sendan-windows-amd64.exe version
```

macOS will refuse an unsigned binary downloaded with a browser until it is
cleared: `xattr -d com.apple.quarantine sendan`. Downloading with `curl` avoids
the quarantine attribute entirely.

> [!IMPORTANT]
> **Checking the checksum is not optional if the operator is part of your threat
> model.** [`SECURITY.md`](../SECURITY.md) sets out what that check establishes,
> and how to go further by reproducing the build from source.

## Sending a file

```sh
sendan up --to https://files.example.org report.pdf
```

The link is printed on standard output and nothing else is, so it composes:

```sh
sendan up report.pdf | pbcopy
tar cz project | sendan up --name project.tgz
```

Set `SENDAN_INSTANCE` so `--to` need not be repeated:

```sh
export SENDAN_INSTANCE=https://files.example.org
sendan up report.pdf
```

### Options

| | |
|---|---|
| `--to <url>` | the instance, if `SENDAN_INSTANCE` is not set |
| `--name <name>` | the filename a recipient sees; **required** when reading a pipe, which carries none |
| `--password` | protect the file; prompts twice, and does not echo |
| `--password-file <path>` | read that password from a file |
| `--expires <duration>` | `30m`, `12h`, `7d`; the instance decides if omitted |
| `--downloads <n>` | allow `n` downloads, then remove it |

```sh
sendan up --password --expires 7d --downloads 3 report.pdf
```

> [!IMPORTANT]
> **There is no `--password <value>`.** An argument appears in the process list,
> in shell history, and in whatever a CI job records, and the password
> contributes to the key — so it is the one value that must not be written down.
> Use the prompt, a file, or `SENDAN_PASSWORD`.
>
> The prompt asks twice because a password mistyped here produces a file nobody
> can open: not you, who never tries it, and not the recipient, who is told only
> that the password did not work. Pressing return means no password at all.

After an upload you are also given an **owner token**. It is shown once and
stored nowhere; it is what removes the upload before it expires.

## Receiving a file

```sh
sendan down 'https://files.example.org/d/…#…'
```

Quote the link. Bourne-style shells pass an unquoted `#` through unharmed when
it is inside a word, but zsh with `extendedglob` treats it as a pattern
character, and a link is a URL that may contain other characters a shell reads.
Quoting costs nothing, and the failure it avoids is silent: the part after `#`
is the key, and a link that arrives truncated cannot be repaired by anybody.

| | |
|---|---|
| `-o <path>` | write here instead of the name the sender chose |
| `-o -` | write to standard output |

```sh
sendan down "$link" -o - | tar tz
```

A protected file prompts for the password, or takes `SENDAN_PASSWORD`. The file
is written under a temporary name and renamed only once it has passed its
integrity check, so an interrupted download never leaves something that looks
like the file.

## Checking an instance

```sh
sendan verify https://files.example.org
```

Fetches every asset the published manifest names, from the instance, and
compares digests. Exit status is non-zero if anything differs.

| | |
|---|---|
| `--manifest <path\|url>` | compare against this manifest instead of the release for the version the instance claims |
| `--key <line\|path>` | require the manifest to be signed by this key instead of the one this build was published with |

`--manifest` is how a fork with its own releases is checked, and how this works
offline. [`SECURITY.md`](../SECURITY.md) sets out what a pass does and does not
establish.

### The release key

A manifest fetched over the network is refused unless it is signed by the
release key. The public half is compiled into the binary, so the copy you
obtained carries the key it checks against rather than fetching one at the time
of checking.

> [!IMPORTANT]
> **No release key exists yet**, because no release has been cut. Until one is
> published, `sendan verify` against a release URL stops and says so rather than
> checking against nothing. Verify with `--manifest` pointing at a manifest you
> produced yourself:
>
> ```sh
> (cd web && npm ci && npm run build)
> ./scripts/asset-manifest.sh /tmp/manifest.json
> sendan verify https://files.example.org --manifest /tmp/manifest.json
> ```
>
> That is the stronger check anyway: it compares the instance against a client
> you built, rather than against a statement somebody else signed.

The signature is in [minisign](https://jedisct1.github.io/minisign/) format, so
`minisign -Vm manifest.json -P <key>` checks it without this program.
[`SECURITY.md`](../SECURITY.md) gives the full procedure.

## Environment

| Variable | Meaning |
|---|---|
| `SENDAN_INSTANCE` | where `sendan up` uploads. A link carries its own origin, so `down` and `verify` ignore this. |
| `SENDAN_PASSWORD` | the password, for uploading and for opening a protected file. |

## Exit status

| | |
|---|---|
| `0` | it worked |
| `1` | it did not, and standard error says why |
| `130` | interrupted |

`sendan verify` uses `1` for an instance that is not serving the published
client, which is a real answer rather than a failure to check — the output says
which it was.
