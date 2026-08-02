# codeql

## Purpose

Static analysis of Go and TypeScript for security defects.

## Triggers

Pull requests, pushes to `main`, and weekly on Monday.

## What it does

Runs GitHub's CodeQL analysis with the `security-extended` query suite over both
languages. Results appear under the repository's Security tab rather than as
inline pull request comments.

## What a failure means

**A job failure is a tooling problem; a CodeQL *alert* is the actual output.**
The job failing usually means the build step CodeQL performs could not complete.

Alerts require triage rather than reflexive fixes. CodeQL produces false
positives, particularly around cryptographic code where it cannot see the
scheme's invariants. Dismiss with a written reason, never silently.

Not a required check: static analysis alerts are advisory, and blocking merges on
them would make dismissal the path of least resistance.
