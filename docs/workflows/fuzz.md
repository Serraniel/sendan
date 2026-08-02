# fuzz

## Purpose

Explores the input space beyond the cases someone thought to write down. The
unit tests assert known properties; the fuzzers look for the inputs nobody
anticipated.

## Triggers

Nightly at 02:00 UTC, and on demand with a configurable per-target duration
(300 seconds by default).

## What it does

Runs each Go fuzz target as a separate job:

| Target | Property |
|---|---|
| `FuzzContentRoundTrip` | decrypting an encrypted stream returns the input exactly |
| `FuzzContentBitFlipIsRejected` | no single-bit change to a stream ever decrypts |
| `FuzzMetadataRoundTrip` | metadata is either rejected or round trips unchanged, never silently mangled |
| `FuzzUnpadRejectsGarbage` | anything unpadding accepts must re-pad to the identical bytes |

## Why this is not a merge gate

Fuzzing is unbounded work. A pull request cannot wait on it, and a time-boxed
run that happens to find nothing proves very little. Running it on a schedule
means it accumulates coverage over time instead of costing every contributor
five minutes.

## What a failure means

**A crasher was found: a specific input that breaks an invariant.** This is the
most valuable output this repository produces, and it must not be discarded.

1. Download the `fuzz-crashers-*` artifact from the failed run.
2. Commit the crasher under `internal/crypto/testdata/fuzz/<Target>/`. Go
   replays committed crashers as ordinary unit tests, so it becomes a permanent
   regression case that runs on every pull request.
3. Fix the defect. The crasher test must fail before the fix and pass after it.

> [!WARNING]
> Never delete a crasher to make the build green. In a cryptographic codebase a
> reproducible failing input is a finding, not an inconvenience.
