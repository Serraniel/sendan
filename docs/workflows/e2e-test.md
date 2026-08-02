# e2e-test

## Purpose

Exercises the flows a user actually performs, in a real browser, against a real
server.

## Triggers

Pull requests, nightly at 03:00 UTC, and on demand.

## What it does

Runs the Playwright suite against Chromium and Firefox: upload and download
round-trips, password-protected files, expiry by deadline and by download count,
large-file streaming through both save paths, and cross-implementation transfers
between the CLI and the browser.

Retries are configured in `playwright.config.ts` (2 on CI) so a flaky test
reruns on its own rather than failing the job. Tests that pass only on retry are
reported as **flaky** and counted in the job summary.

## What a failure means

**Probably a real bug, but confirm before assuming.** Browser tests fail for
environmental reasons more often than unit tests do.

This workflow is **not a required check**. That is deliberate: a flaky required
check trains people to bypass branch protection, which is worse than not having
the check at all. Promote it to required once it has been stable for a sustained
period.

A rising flaky count is a warning worth acting on. Tests usually become flaky
before they become broken.
