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
- `feat!:` or a `BREAKING CHANGE:` footer bumps the **minor** version while this
  project is below 1.0.0, and the major version afterwards

Merging that pull request tags the release, which triggers
[release](release.md).

## Versioning

Sendan starts at **0.1.0**. Under SemVer, `0.0.x` offers no way to distinguish a
feature from a fix; `0.1.0` gives the normal pre-1.0 rhythm.

**1.0.0 is reserved** for the point at which the wire format is frozen and an
independent security audit has been completed. It is a claim about
trustworthiness, not about feature completeness.

Two settings enforce that, because neither is the default:

- `.release-please-manifest.json` records the last released version. It starts
  at `0.0.0`, which is what makes the first release `0.1.0`. Without a manifest,
  release-please has no prior version to reason from and calls a first release
  `1.0.0`.
- `bump-minor-pre-major` in `release-please-config.json` keeps a breaking change
  inside `0.x` rather than declaring 1.0.0 on its own. A project below 1.0.0 is
  saying its interfaces may still move; a breaking change is expected there and
  is not the moment to make a claim about trustworthiness.

`bump-patch-for-minor-pre-major` is deliberately left off, so a `feat:` still
bumps the minor version: `0.1.0` to `0.2.0`. Turning it on would flatten every
feature into a patch and lose the distinction the choice of `0.1.0` was made to
keep.

The manifest is updated by release-please itself when a release pull request is
merged. It is not a value to edit by hand afterwards.

## What a failure means

Usually a malformed commit subject that reached `main`, or insufficient token
permissions. No release is produced until the release pull request is merged, so
a failure here delays a release rather than corrupting one.
