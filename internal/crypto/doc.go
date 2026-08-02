// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Package crypto implements the Sendan v1 cryptographic scheme.
//
// The normative definition is docs/spec/wire-format-v1.md. This package and the
// TypeScript implementation under web/ are two implementations of that one
// document, and they are verified against shared test vectors on every pull
// request. Neither may be changed without the other.
//
// The scheme is symmetric throughout. A random file key encrypts the content;
// that file key is wrapped under a key derived from a random link secret, and
// optionally from a password. The server stores only wrapped material and never
// observes the link secret, the file key, or the password.
//
// Three rules govern changes here:
//
//   - There is exactly one cipher suite. Nothing in this package may accept an
//     algorithm as a parameter, and no caller may select one.
//   - Every derived key has its own domain-separation label. Labels are
//     constants and are never built from caller input.
//   - Changing any primitive, label, or size means defining version 2, not
//     editing version 1 in place.
package crypto
