# release-please

## Purpose

Maintains a standing pull request that accumulates the next release, so version
numbers and changelogs are derived rather than written by hand.

## Triggers

Pushes to `main`, and on demand.

## What it does

Parses Conventional Commit subjects since the last release and keeps a "release"
pull request up to date with the next version number and the generated
`CHANGELOG.md` entries.

- `fix:` bumps the patch version
- `feat:` bumps the minor version
- `feat!:` or a `BREAKING CHANGE:` footer bumps the major version

Merging that pull request tags the release, which triggers
[release](release.md).

## Versioning

Sendan starts at **0.1.0**. Under SemVer, `0.0.x` offers no way to distinguish a
feature from a fix; `0.1.0` gives the normal pre-1.0 rhythm.

**1.0.0 is reserved** for the point at which the wire format is frozen and an
independent security audit has been completed. It is a claim about
trustworthiness, not about feature completeness.

## What a failure means

Usually a malformed commit subject that reached `main`, or insufficient token
permissions. No release is produced until the release pull request is merged, so
a failure here delays a release rather than corrupting one.
