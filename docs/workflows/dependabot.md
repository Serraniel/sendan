# dependabot

## Purpose

Keeps dependencies and pinned action SHAs current.

## Triggers

Weekly on Monday, per ecosystem. Configured in `.github/dependabot.yml`; this is
configuration rather than a workflow.

## What it covers

| Ecosystem | Directory | Commit prefix |
|---|---|---|
| github-actions | `/` | `ci` |
| gomod | `/` | `build` |
| npm | `/web` | `build` |
| docker | `/` | `build` |

GitHub Actions updates matter more here than usual: because actions are pinned
to commit SHAs, pinning without automated updates would mean never receiving
upstream fixes.

## Cryptographic dependencies are excluded from grouping

Routine updates are grouped into a single pull request to reduce noise. Certain
dependencies are deliberately excluded so they arrive individually:

- `golang.org/x/crypto`
- `filippo.io/*`
- `hash-wasm`

A grouped bump buries an individual change inside a larger diff. Every
cryptographic dependency change must be reviewed on its own, with the diff
actually read. This is the policy deferred during the workflow discussion:
**automate the noise, never automate the cryptography.**

## Overrides

`web/package.json` carries one `overrides` entry:

```json
"overrides": { "cookie": "^0.7.0" }
```

`cookie` below 0.7.0 accepts out-of-bounds characters in a cookie's name, path
and domain, so a name can set the other fields (GHSA, alert 1). It arrives
through `@sveltejs/kit`, which asks for `^0.6.0` and so cannot receive the fix;
Dependabot could only offer a path that downgraded `@sveltejs/adapter-static`
from 3.0.10 to 0.0.17.

Nothing here was exposed to it. The interface sets `ssr = false` and
`prerender = false` and is served by the Go binary as static files, so SvelteKit
runs no server code, which is the only place `cookie` is used - no file under
`internal/webui/dist` contains the string, and the server sets no cookies of its
own.

The override is still the better answer than dismissing the alert: an
unreachable vulnerable version is a claim that has to be re-checked every time
the interface grows, and this removes the version instead. Drop it once
`@sveltejs/kit` widens its range - `npm ls cookie` should then already resolve
to 0.7 or later on its own.

## What a failure means

A Dependabot pull request failing CI means the update is not safe to merge as-is.
Read the upstream changelog before assuming the test is wrong.
