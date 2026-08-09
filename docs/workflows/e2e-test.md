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

A third project, `chromium-h2`, runs the `*.h2.spec.ts` files against the same
instance **through a TLS-terminating proxy** (`tools/e2e-tlsproxy`), which is
how it is actually deployed and the only way a browser will speak HTTP/2. The
certificate is generated at startup and valid for an hour.

That project exists because a whole class of fault is invisible without it. The
instance infers its own scheme from the connection it can see, and reaching it
directly over plain HTTP makes every such inference happen to be right. An
upload `Location` naming `http` for a browser talking `https` went unnoticed
until something reached the instance the way a deployment does.

`interop.spec.ts` moves a file **between the command line client and the
browser**, both ways and with a password. It builds the CLI from the same source
the browser client came from and drives it as a program, which is the case that
catches divergence between the two implementations in a realistic setting rather
than at the level of the primitives. Changing one label in the Go key schedule
fails all three of its tests.

The shared cryptographic vectors pin the primitives; this pins everything built
on them — the key schedule's inputs, the metadata envelope, the tus metadata
header, the link format, and the declared length both clients compute
independently and the instance enforces.

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
