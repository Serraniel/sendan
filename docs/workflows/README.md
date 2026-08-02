# Workflows

Continuous integration for Sendan. Each workflow has a short document here
describing what it is for, when it runs, and what a failure means.

| Workflow | Trigger | Merge gate |
|---|---|---|
| [commit-check](commit-check.md) | pull request | Yes |
| [test](test.md) | pull request, push to `main` | Yes |
| [e2e-test](e2e-test.md) | pull request, nightly | No |
| [interop-test](interop-test.md) | pull request (compat paths), weekly | No |
| [security-scan](security-scan.md) | pull request, daily | Yes |
| [codeql](codeql.md) | pull request, push to `main`, weekly | No |
| [release-please](release-please.md) | push to `main` | n/a |
| [release](release.md) | tag `v*` | n/a |
| [edge](edge.md) | push to `main` | n/a |
| [dependabot](dependabot.md) | schedule (config, not a workflow) | n/a |

## Conventions

**Actions are pinned to a commit SHA**, with the version as a trailing comment.
Tags are mutable and can be repointed by whoever controls the action; for a
project whose CI signs release artefacts, that is a supply-chain risk. Dependabot
updates the SHA and the comment together.

**Jobs are guarded while the repository has no code.** Each job checks for the
relevant manifest (`go.mod`, `web/package.json`, and so on) and no-ops with a
notice if it is absent. This is deliberate: a required check that is *skipped*
never reports a status, which leaves pull requests blocked forever waiting on it.
A guarded job runs and passes instead. **Remove each guard in the pull request
that introduces the corresponding code.**
