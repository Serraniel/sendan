# interop-test

## Purpose

Verifies that third-party clients speaking the Firefox Send protocol still
interoperate with Sendan's compatibility endpoints.

## Triggers

Pull requests touching `internal/compat/**` or `internal/api/**`, weekly on
Monday, and on demand.

## What it does

Downloads the current `ffsend` release, starts Sendan with
`SENDAN_SEND_COMPAT=true`, uploads a 5 MiB random file, downloads it back, and
asserts the round-trip is byte-identical.

Despite the name this is a code test, not a browser test — it drives a
third-party binary rather than a user interface.

## What a failure means

**Possibly nothing you did.** This is the only workflow with an external
dependency, and it can fail because `ffsend` published a release, changed its
asset naming, or altered its behaviour.

Check whether upstream moved before investigating your own change. This is why
the workflow is path-filtered and not a required check: another project's
release schedule must not block an unrelated pull request.
