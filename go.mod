module github.com/Serraniel/sendan

// The minimum Go this module requires.
//
// This is not what continuous integration builds with, and should not be: CI
// resolves the newest patch of a release line so that standard library fixes
// arrive without anyone editing a file. Pinning CI to this exact version was
// tried in #117 and reverted, because it built against a version with known
// vulnerabilities - govulncheck reported them within minutes.
//
// A contributor's Go may therefore differ from both. GOTOOLCHAIN only ever
// moves forward, so a newer local installation is used in preference; see
// CONTRIBUTING.md for how to reproduce a CI run when that matters.
go 1.25.8

// The toolchain this project is built and checked with. It is a minimum rather
// than a pin - a newer local Go is used in preference to it - so the scripts
// read the version from here and set GOTOOLCHAIN to it exactly. Without that,
// a machine whose Go has moved ahead runs the linters against a standard
// library they cannot parse, and the failure looks like a finding.
toolchain go1.27.1

require (
	github.com/cloudflare/circl v1.6.5
	github.com/coder/websocket v1.8.15
	github.com/jackc/pgx/v5 v5.10.0
	github.com/minio/minio-go/v7 v7.3.0
	github.com/tus/tusd/v2 v2.10.0
	golang.org/x/crypto v0.55.0
	golang.org/x/exp v0.0.0-20260727155853-b88d891fe743
	golang.org/x/term v0.45.0
	modernc.org/sqlite v1.58.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
