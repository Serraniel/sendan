# test

## Purpose

The primary merge gate. If this passes, the code builds and behaves.

## Triggers

Pull requests, and pushes to `main`.

## What it does

| Job | Covers |
|---|---|
| `lint-go` | golangci-lint |
| `test-go` | `go vet`, then unit and integration tests with the race detector and coverage |
| `test-web` | lint, type-check, unit tests, production build, and an audit asserting no external origin appears in the built output |
| `test-vectors` | the shared cryptographic vectors, run against **both** the Go and TypeScript implementations |
| `build` | builds the web client, then the binary with assets embedded |

## What a failure means

**You broke something.** Every job here reports on your code, not on the outside
world, so a failure is always actionable.

`test-vectors` deserves particular attention. It failing means the Go and
TypeScript implementations disagree about the cryptographic scheme — that a file
written by the CLI may not be readable in the browser, or the reverse. It is
never a flake, and it must never be made non-blocking.

The external-origin audit in `test-web` failing means a dependency or asset
reached outside the origin. That breaks the strict CSP and reintroduces a third
party into a page performing end-to-end encryption.
