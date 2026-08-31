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

- `initial-version` names the first release: `0.1.0`. This is the setting that
  decides it, and nothing else does. A manifest of `0.0.0` is not enough on its
  own — with no release to reason from, release-please proposes `1.0.0` — which
  was observed rather than assumed: the manifest was in place and the standing
  pull request still read `chore(main): release 1.0.0`.
- `.release-please-manifest.json` records the last released version, and
  release-please rewrites it when a release pull request is merged.
- `bump-minor-pre-major` keeps a breaking change inside `0.x` rather than
  declaring 1.0.0 on its own. A project below 1.0.0 is saying its interfaces may
  still move; a breaking change is expected there and is not the moment to make
  a claim about trustworthiness. It is set **inside the package entry** as well
  as at the top level: set only at the top level it did not take effect, and the
  proposed release stayed at 1.0.0.
- `include-component-in-tag` is `false`. It defaults to **true**, and naming the
  package would then put that name in the tag — `sendan-v0.1.0` rather than
  `v0.1.0`. [release](release.md) triggers on `v*`, so a component in the tag
  means the release workflow never runs at all: no binaries, no image, no
  signatures, and nothing failing loudly enough to notice.

The package is deliberately left unnamed for the same reason. A name makes
release-please treat this as one component among several, which also moves the
pull request onto its own branch — and a second release pull request appeared
beside the first, proposing the same version under a different name.

`bump-patch-for-minor-pre-major` is deliberately left off, so a `feat:` still
bumps the minor version: `0.1.0` to `0.2.0`. Turning it on would flatten every
feature into a patch and lose the distinction the choice of `0.1.0` was made to
keep.

The manifest is updated by release-please itself when a release pull request is
merged. It is not a value to edit by hand afterwards.

## Why pull request titles are not Conventional Commits

Squash merging is disabled, so every commit enters `main` as written and each
pull request also leaves a merge commit. GitHub fills that merge commit's body
with the pull request's title, and this tool reads commit messages — so a
Conventional Commit title is counted twice: once from the commit that did the
work, and once from the merge commit repeating it. The changelog then lists the
change twice, distinguishable only by the entry that carries `closes #N` being
the real commit.

No setting fixes this. The tool has no option to ignore merge commits, and
GitHub permits only three title-and-body combinations for merge commits, each of
which places the pull request title somewhere in the message. What works is
giving pull requests plain-language titles, which `CONTRIBUTING.md` requires.

Commits inside a pull request must still be Conventional Commits; only the pull
request's own title must not look like one.

## What a failure means

Usually a malformed commit subject that reached `main`, or insufficient token
permissions. No release is produced until the release pull request is merged, so
a failure here delays a release rather than corrupting one.
