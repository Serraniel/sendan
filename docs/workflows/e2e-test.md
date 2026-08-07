# e2e-test

## Purpose

Exercises the flows a user actually performs, in a real browser, against a real
server.

## Triggers

Pull requests, nightly at 03:00 UTC, and on demand.

## What it does

Runs the Playwright suite against Chromium and Firefox: upload and download
round-trips, password-protected files with the right password and the wrong one,
expiry by deadline and by download count, both save paths, the transparency
card, and the Content-Security-Policy the instance actually serves.

Both browsers are run rather than one being treated as representative. Chromium
has the File System Access API and Firefox does not, and that difference is what
the save paths turn on: the test that writes to a chosen file is skipped on
Firefox, and the service worker path is exercised on both.

The suite drives the real interface against a binary built with the client
embedded — not the development server, which sends no policy at all. A run
against a development server would pass on a client no instance could serve.

> [!NOTE]
> **Transfers between the command line client and the browser are not covered
> yet.** That is the case that catches divergence between the two
> implementations in a realistic setting rather than at the vector level, and it
> needs a CLI, which is M5 (#42). The shared cryptographic vectors cover the
> same ground at the level of the primitives in the meantime.

Retries are configured in `playwright.config.ts` (2 on CI) so a flaky test
reruns on its own rather than failing the job. Tests that pass only on retry are
reported as **flaky** and counted in the job summary.

## What a failure means

**Probably a real bug, but confirm before assuming.** Browser tests fail for
environmental reasons more often than unit tests do.

They also catch things nothing else can. A Content-Security-Policy is enforced
by a browser and by nothing else; a service worker needs a scope and a secure
context; a file picker needs the click it was opened from; and `postMessage`
structure-clones its argument, so a reactive object cannot cross to a worker.
Each of those is invisible to a test that calls a function.

This workflow is **not a required check**. That is deliberate: a flaky required
check trains people to bypass branch protection, which is worse than not having
the check at all. Promote it to required once it has been stable for a sustained
period.

A rising flaky count is a warning worth acting on. Tests usually become flaky
before they become broken.
