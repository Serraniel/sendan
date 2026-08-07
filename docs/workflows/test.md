# test

## Purpose

The primary merge gate. If this passes, the code builds and behaves.

## Triggers

Pull requests, and pushes to `main`.

## What it does

| Job | Covers |
|---|---|
| `lint-go` | golangci-lint |
| `test-go` | `go vet`, then unit and integration tests with the race detector, then the per-package coverage floors in `.coverage-floors` |
| `test-web` | lint, type-check, unit tests, production build, and an audit asserting the built client can run under the policy it is served with |
| `test-vectors` | the shared cryptographic vectors, run against **both** the Go and TypeScript implementations |
| `build` | builds the web client, then the binary with assets embedded |

## What a failure means

**You broke something.** Every job here reports on your code, not on the outside
world, so a failure is always actionable.

`test-vectors` deserves particular attention. It failing means the Go and
TypeScript implementations disagree about the cryptographic scheme — that a file
written by the CLI may not be readable in the browser, or the reverse. It is
never a flake, and it must never be made non-blocking.

The asset audit in `test-web` fails for two reasons, and the message says which.

An **external origin** means a dependency or asset reached outside the origin.
That breaks the strict CSP and reintroduces a third party into a page performing
end-to-end encryption.

An **inline style** means something in the client sets a `style` attribute,
which `style-src 'self'` refuses. This is worth stating plainly because nothing
else catches it: a blocked style is not an error, the development server sends
no policy, and the page therefore renders correctly in every place it is looked
at and wrongly on every real instance. Move the rule into a component
stylesheet, or use an element that does not need one.

### The coverage gate

`scripts/coverage.sh` fails for three distinct reasons, and the message says
which:

| Message | Meaning |
|---|---|
| `BELOW FLOOR` | Coverage fell. Add tests for what you changed, or explain in review why the floor should move down |
| `has no floor` | A new package is held to nothing. Add it to `.coverage-floors` |
| `package does not exist` | A floor outlived its package. Remove the line |

It also reports floors sitting well below actual coverage. That is advice rather
than a failure: **when your change raises coverage, raise the floor in the same
pull request**, which is what keeps it a ratchet rather than a line everyone
eventually forgets.

> [!IMPORTANT]
> The floors assume the PostgreSQL and object store containers are running, as
> they are in continuous integration. Run the script without them and
> `internal/store` and `internal/blob` fall roughly twenty-five points short,
> because their alternative backends skip. That is not your change breaking; the
> script says so when the environment variables are unset.

Coverage is a floor, not a goal. It records that a line ran, not that anything
checked what it did, so meeting it is not evidence the tests are any good. The
area-specific requirements in [CONTRIBUTING.md](../../CONTRIBUTING.md) are what
actually matter.
