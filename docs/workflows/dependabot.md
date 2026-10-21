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

## Peer-coupled dependencies are forced into one pull request

The opposite case to the one above. Some packages declare each other as peers
with major ranges, so a bump that arrives alone cannot install: `npm ci` fails
on the peer conflict before a single test runs, and the pull request shows
several red checks that are all the same failure. Such a set is grouped across
*every* update type, majors included, so the halves arrive together.

| Group | Members | The edge |
|---|---|---|
| `vitest` | `vitest`, `@vitest/*` | `@vitest/coverage-v8` declares `vitest` as a peer (#99) |
| `sveltekit` | `@sveltejs/*`, `svelte`, `svelte-check`, `vite` | `adapter-static` requires `kit`; `kit` requires `svelte`, `vite` and `vite-plugin-svelte`; `svelte-check` requires `svelte` (#316, #317) |

These groups are ordered before `npm-minor-patch` in the configuration, because
a dependency joins the first group whose patterns it matches.

A red Dependabot pull request whose failures all begin with `npm error ERESOLVE`
is this, not a breaking change in the dependency. Look for the peer that was
left behind before reading any changelog.

## Overrides

`web/package.json` carries no `overrides` entry, and the one it used to carry is
worth recording so that it is not reintroduced.

`cookie` below 0.7.0 accepts out-of-bounds characters in a cookie's name, path
and domain, so a name can set the other fields (GHSA, alert 1). It arrived
through `@sveltejs/kit`, which asked for `^0.6.0` and so could not receive the
fix, and Dependabot could only offer a path that downgraded
`@sveltejs/adapter-static` from 3.0.10 to 0.0.17. An `overrides` entry of
`^0.7.0` removed the vulnerable version instead of arguing that it was
unreachable.

SvelteKit 3 asks for `cookie@^2.0.1`, which is far above the version that
carried the flaw, so the entry had nothing left to do - and it had become
actively harmful, because it pinned `cookie` back to 0.7.2, a CommonJS build
without the named exports SvelteKit 3 imports. The build failed on
`parseCookie` until the entry was removed. `npm ls cookie` now resolves to 2.0.1
on its own and `npm audit` reports nothing.

The condition this document set for dropping it - that `@sveltejs/kit` widen its
range so the version resolves correctly without help - is the condition that was
met.

## Updates that are ignored on purpose

Two majors do not arrive automatically. Both are cases where Dependabot cannot
see the constraint that decides the answer.

| Dependency | Ignored | The constraint |
|---|---|---|
| `typescript` | majors | `svelte-check` refuses TypeScript 7 unless 6 is installed beside it under an alias and it is run behind an experimental flag (#93) |
| `node` | majors | the major has to be LTS on the day it is adopted, because it decides the bundler's output (#260) |

Node is the one that costs something to get wrong. The release builds the client
twice - on a runner for the signed asset manifest, and inside the `Dockerfile`
for the image - and two majors emit two sets of content-hashed filenames. That
shipped in v0.2.0, and `sendan verify` reported the project's own image as not
serving the published client, because it was not.

Dependabot proposed Current in #165 and #278, and in #323 it proposed Node 25,
which had been end of life since June 2026 - a tag newer than the pinned one and
a support window four months shorter. Neither mistake is one it can be taught.

Digest updates are **not** ignored in either case, so security patches for the
pinned line keep arriving on their own. Only the major is a deliberate change,
and `CONTRIBUTING.md` carries the rule for making it.

## What a failure means

A Dependabot pull request failing CI means the update is not safe to merge as-is.
Read the upstream changelog before assuming the test is wrong.
