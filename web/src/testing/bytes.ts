// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Comparing file-sized byte arrays in tests.
 *
 * Not a convenience. `expect(a).toEqual(b)` walks a typed array element by
 * element building a structural diff, which costs about 460ms for 200 kB - two
 * hundred times what decrypting the same bytes costs, and enough to push a test
 * that compares a few files past the default timeout. That is what it did: a
 * test asserting four decryptions took two seconds locally and six on a slower
 * runner, of which the decryption was sixty milliseconds.
 *
 * A byte comparison says the same thing in under a millisecond, and reports a
 * more useful failure than a diff nobody can read: where the arrays first
 * differ, and what is around it.
 */

import { expect } from "vitest";

/** The first index at which two arrays differ, or -1. */
function firstDifference(got: Uint8Array, want: Uint8Array): number {
  const shared = Math.min(got.length, want.length);
  for (let i = 0; i < shared; i++) {
    if (got[i] !== want[i]) return i;
  }
  return got.length === want.length ? -1 : shared;
}

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" ");

/** Asserts two byte arrays are identical. */
export function expectBytes(got: Uint8Array, want: Uint8Array, context = ""): void {
  const where = firstDifference(got, want);
  if (where === -1) return;

  const label = context === "" ? "" : `${context}: `;
  if (got.length !== want.length && where >= Math.min(got.length, want.length)) {
    expect.fail(`${label}got ${got.length} bytes, want ${want.length}`);
  }

  // A window rather than the whole array. Twenty bytes either side of the first
  // difference is what identifies the fault; two hundred thousand is noise.
  const from = Math.max(0, where - 20);
  const to = Math.min(want.length, where + 20);
  expect.fail(
    `${label}differs at byte ${where} of ${want.length}\n` +
      `  got:  ${hex(got.subarray(from, to))}\n` +
      `  want: ${hex(want.subarray(from, to))}`,
  );
}
