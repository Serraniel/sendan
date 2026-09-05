# registry-prune

## Purpose

Removes old `edge` builds from the container registry.

## Triggers

Weekly on Monday at 06:00 UTC, and on demand. A dispatch prints the plan and
changes nothing unless `apply` is set, so the selection can be read before it is
trusted.

## Why it exists

Every push to `main` publishes five versions, not one:

| | |
|---|---|
| 1 index, tagged | `edge` and `sha-<commit>` |
| 2 images, untagged | `linux/amd64`, `linux/arm64` |
| 2 attestations, untagged | provenance and SBOM |

Nothing is wrong with that — it is how a multi-platform image is stored. But at
five per push the registry grows without limit. See #225.

## What it will not do

**It never touches a released image.** A release has to stay pullable for as
long as anybody might reproduce or verify it, which is the point of publishing
digests and signatures at all. Only versions whose tags are all `edge` or
`sha-` are candidates; any other tag protects a version outright, so a future
tagging scheme cannot silently become a deletion.

**It never deletes a child on its own.** Children are referenced by an index
rather than named. Removing one leaves an index that resolves to nothing on
that architecture: the image still appears to exist, and a pull fails on an
arm64 machine while succeeding on amd64. Deletions go children-first, and only
for an index that is itself being removed.

**It refuses to act on an index whose children it could not list.** Guessing
there is exactly how children are orphaned.

A child that a surviving index also references is kept. That is not
hypothetical — two builds of unchanged source produce the same child digest.

## What a failure means

A permissions failure reads very differently from a version somebody already
removed, so the tool prints the API's own response rather than a status code.
`tools/registry-prune` carries the selection rules, and they are covered by
tests in the same directory: what is kept, what is never touched, and the order
deletions happen in.
