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

## What a failure means

A Dependabot pull request failing CI means the update is not safe to merge as-is.
Read the upstream changelog before assuming the test is wrong.
