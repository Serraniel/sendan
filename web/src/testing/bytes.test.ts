// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { expectBytes } from "./bytes.js";

const filled = (n: number) => new Uint8Array(n).map((_, i) => (i * 31 + 7) % 256);

/**
 * A comparison helper that always passed would silently disarm every test that
 * checks a file survived a round trip - which is most of the ones that matter.
 * So it is tested for failing, not only for passing.
 */
describe("comparing bytes", () => {
  it("accepts identical arrays", () => {
    expectBytes(filled(200_000), filled(200_000));
    expectBytes(new Uint8Array(0), new Uint8Array(0));
  });

  it("rejects a single differing byte, wherever it is", () => {
    for (const at of [0, 1, 99_999, 199_999]) {
      const got = filled(200_000);
      got[at] = (got[at] as number) ^ 0xff;
      expect(() => expectBytes(got, filled(200_000)), `byte ${at}`).toThrow(
        new RegExp(`differs at byte ${at}\\b`),
      );
    }
  });

  it("rejects a length that differs", () => {
    expect(() => expectBytes(filled(100), filled(101))).toThrow(/got 100 bytes, want 101/);
    expect(() => expectBytes(filled(101), filled(100))).toThrow(/got 101 bytes, want 100/);
    expect(() => expectBytes(new Uint8Array(0), filled(1))).toThrow(/got 0 bytes, want 1/);
  });

  /**
   * A prefix that matches is the dangerous case: a truncated file is exactly
   * this, and "the first hundred bytes were right" must not read as equal.
   */
  it("rejects a truncation", () => {
    const want = filled(200_000);
    expect(() => expectBytes(want.subarray(0, 199_999), want)).toThrow(/199999.*200000/s);
  });

  it("says where and what, rather than printing the whole array", () => {
    const got = filled(200_000);
    got[1234] = 0x00;

    let message = "";
    try {
      expectBytes(got, filled(200_000), "a chunk size");
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain("a chunk size: ");
    expect(message).toContain("differs at byte 1234 of 200000");
    // A window, not the file: a diff nobody can read is a diff nobody reads.
    expect(message.length).toBeLessThan(400);
  });
});
