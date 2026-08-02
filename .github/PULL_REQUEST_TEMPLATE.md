<!--
  Thank you for contributing to Sendan.
  Please read CONTRIBUTING.md before opening a pull request.
-->

## Summary

<!-- What does this change, and why? Explain the reasoning, not only the diff. -->

Closes #

## Checklist

- [ ] Every commit is signed off (`git commit -s`) — see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] New and changed behaviour is covered by unit tests, including failure paths
- [ ] Any bug fix includes a regression test that fails without the fix
- [ ] New source files carry the SPDX header
- [ ] Continuous integration passes in full

## Cryptographic changes

<!-- Delete this section if the pull request does not touch cryptography. -->

- [ ] Cross-language test vectors are updated
- [ ] **Both** the Go and TypeScript implementations are updated in this pull request
- [ ] No new cipher, mode, or key derivation function has been introduced as an option
- [ ] Key derivation version labels are incremented rather than redefined

> [!WARNING]
> Do not report a vulnerability by opening a pull request. See
> [SECURITY.md](../SECURITY.md) for the disclosure process.
