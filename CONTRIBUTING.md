# Contributing to Sendan

> [!NOTE]
> Sendan is pre-alpha and its architecture is still settling. Please open an
> issue to agree an approach before starting substantial work.

## Developer Certificate of Origin

Sendan uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO). There is no contributor licence agreement and no copyright assignment;
contributors retain copyright in their contributions.

Every commit must carry a `Signed-off-by` line matching its author:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it automatically. To correct the most recent commit:

```sh
git commit --amend -s --no-edit
```

To correct an entire branch:

```sh
git rebase --signoff main
```

Signing off certifies that you wrote the contribution, or otherwise hold the
right to submit it under the project's licence.

> [!IMPORTANT]
> Because Sendan uses a DCO rather than a contributor licence agreement,
> relicensing the project would require the agreement of every contributor. This
> is intentional: no single party, including the maintainer, can unilaterally
> move Sendan away from the AGPL.

## Commit messages

Commit subjects must follow
[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[(scope)][!]: <description>
```

Permitted types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `revert`. An exclamation mark, or a `BREAKING CHANGE:`
footer, marks a breaking change.

```
feat(cli): add --expire flag for download limits
fix(crypto): reject records reordered within a stream
feat(crypto)!: change the key derivation labels to v2
```

This is enforced on every commit, not merely on the pull request title, because
squash merging is disabled and each commit enters `main` as written.

> [!IMPORTANT]
> Release tooling derives the version number and the changelog directly from
> these subjects. A `fix:` produces a patch release and a `feat:` a minor one, so
> a mislabelled commit produces an incorrect version and misleading release
> notes. Write the subject for the person reading the changelog.

The body should explain the reasoning rather than restate the diff, and must
carry the `Signed-off-by` line described above.

## Licensing of contributions

Contributions are licensed under **AGPL-3.0-or-later**, matching the project.
New source files must carry an SPDX header:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors
```

Contributors retain copyright in their own contributions; the collective notice
identifies the licensor without transferring anything. Do not add individual
copyright lines to existing files — authorship is recorded in the git history.

## Testing requirements

Sendan is a security product, and test coverage is treated as a correctness
requirement rather than a matter of preference. Pull requests that add or modify
behaviour without tests will not be merged.

**Every pull request must include:**

- **Unit tests** for the behaviour introduced or changed, covering the failure
  paths as well as the success path. Error handling that is never exercised by a
  test should be assumed not to work.
- **Regression tests** accompanying any bug fix, written so that they fail
  against the unfixed code.
- **Table-driven tests** in Go where a function has multiple input classes, in
  keeping with the surrounding code.

**Additional requirements by area:**

| Area | Requirement |
|---|---|
| `internal/crypto` | Shared cross-language test vectors, updated in the same pull request. Property tests and fuzz targets for any parsing or framing change. |
| Storage and lifecycle | Tests asserting that expiry and deletion leave no residual row, blob, or log entry. |
| HTTP handlers | Tests covering authentication failure, rate limiting, and the presence of required security headers. |
| Web client | Unit tests for cryptographic and stream-handling logic; end-to-end tests for the upload and download flows. |

Continuous integration enforces these checks, including the cross-language
vector comparison. A failing pipeline blocks merge, and no check may be marked
`continue-on-error`.

### Reproducing continuous integration

Continuous integration reads the Go version from `go.mod`, so it cannot drift
from what the module declares. Your local Go may still differ: `GOTOOLCHAIN`
only ever moves *forward*, so a newer installation is used in preference and
you build against a different standard library than CI does.

That difference is real. `net/http.ServeMux` changed the redirect it issues for
a cleaned path between 1.25 and 1.26, and a test asserting it passed locally and
failed in CI for a reason unrelated to the change. The next such difference may
not fail a test at all.

To run exactly what CI runs:

```sh
GOTOOLCHAIN=$(go mod edit -json | jq -r .Go | sed 's/^/go/') go test ./...
```

or simply name the version in `go.mod`:

```sh
GOTOOLCHAIN=go1.25.8 go test ./...
```

Worth doing before opening a pull request that touches anything timing-,
protocol- or standard-library-sensitive.

### Coverage floors

Go coverage is held to a per-package floor in `.coverage-floors`; TypeScript
coverage to thresholds in `web/vitest.config.ts`.

These are a **ratchet, not a target**. Each sits just below the coverage
actually achieved, so a change that reduces coverage fails rather than being
noticed later. **When your change raises coverage, raise the floor in the same
pull request** — that is what keeps it a ratchet rather than a line everyone
eventually forgets.

The check also rejects a package with no floor, and a floor for a package that
no longer exists, so the file cannot drift out of step with the code.

> [!IMPORTANT]
> Coverage is a floor, not a goal. A high percentage over code that never
> exercises a failure path is worthless. The area-specific requirements above
> are what actually matter; the floors exist to stop them eroding silently.

## Cryptographic code

Changes affecting cryptography are held to a stricter standard, and review will
be correspondingly slow and detailed. This is the only part of the codebase in
which a subtle error silently invalidates the entire project.

- **Do not add a second cipher, mode, or key derivation function as an option.**
  Sendan ships exactly one cipher suite by design; algorithm negotiation is the
  origin of most historical TLS vulnerabilities.
- Any change to the key schedule, record framing, or wrapping scheme **must**
  include updated cross-language test vectors, and the Go and TypeScript
  implementations **must** be updated in the same pull request. They may not
  diverge at any commit.
- Increment the version label in key derivation info strings rather than
  altering the meaning of an existing one.
- Do not introduce a dependency that performs cryptography without first
  agreeing it in an issue.

Vulnerabilities must not be reported as pull requests; see
[SECURITY.md](SECURITY.md).

## Pull requests

- Keep each pull request to a single concern.
- Include tests, as described above.
- Ensure continuous integration passes in full.
- Write commit messages that explain the reasoning, not only the change.

## Code of conduct

Contributors are expected to conduct themselves professionally. Harassment,
personal attacks, and bad-faith argument are not tolerated. The maintainer
resolves such matters at their discretion.
