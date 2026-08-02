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
