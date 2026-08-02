# commit-check

## Purpose

Enforces the two rules that must hold for every commit in history: the
Developer Certificate of Origin, and Conventional Commits.

## Triggers

Pull requests only.

## What it does

- **`dco`** — every non-merge commit must carry a `Signed-off-by` line matching
  its author.
- **`conventional-commits`** — every non-merge commit subject must match
  `<type>[(scope)][!]: <description>`.

Both checks read individual commits rather than the pull request title, because
squash merging is disabled and every commit lands in `main` as written.

## What a failure means

**You need to rewrite your commits.** Neither failure indicates a problem with
the code.

- Missing sign-off: `git commit --amend -s --no-edit`, or
  `git rebase --signoff main` for a branch.
- Malformed subject: `git rebase -i --signoff main` and reword.

A missing sign-off is a licensing problem: the DCO is the project's record that
a contributor had the right to submit their work, and it must live in permanent
history. A malformed subject is a release problem: `release-please` derives the
version number and changelog from these subjects.
