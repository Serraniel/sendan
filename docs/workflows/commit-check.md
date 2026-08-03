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

### Automated pull requests

A pull request opened by a bot account still requires a `Signed-off-by` line,
but it need not match the commit author. Dependency updates sign off under an
identity that differs from the one they author with:

```
author:        dependabot[bot] <…+dependabot[bot]@users.noreply.github.com>
Signed-off-by: dependabot[bot] <support@github.com>
```

An exact match can never succeed there, and no rewrite is available, because
nobody holds the bot's key.

> [!IMPORTANT]
> The exemption is decided by the **pull request's author**, which GitHub
> authenticates — not by the commit author field, which is chosen by whoever
> made the commit. Keying on the commit would let any contributor bypass the
> check by claiming to be a bot.

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
