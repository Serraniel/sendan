// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The encoder, checked against another implementation.
 *
 * The vectors in `qr.vectors.json` were produced by `qrencode`, forced into
 * byte mode at level M. Comparing module for module is the only check worth
 * having here: an encoder tested only against itself produces something
 * plausible, and a plausible QR code is an unreadable one.
 */

import { describe, expect, it } from "vitest";
import { dataModuleCount, encode, encodeWithMask, type Matrix, TooMuchData, toPath } from "./qr.js";
import vectors from "./qr.vectors.json" with { type: "json" };

function render(matrix: Matrix): string[] {
  return matrix.map((row) => row.map((dark) => (dark ? "1" : "0")).join(""));
}

describe("against an independent implementation", () => {
  it.each(
    vectors.map((v) => [`${v.size}x${v.size} at mask ${v.mask}`, v]),
  )("matches %s", (_label, vector) => {
    // The mask is pinned in the vector and applied here, so a mismatch means
    // the encoding is wrong rather than that two implementations scored the
    // masks differently. Which mask this encoder picks on its own is a
    // separate question, below.
    const matrix = encodeWithMask(vector.text, vector.mask);

    expect(matrix.length).toBe(vector.size);
    // Compared row by row rather than as one blob: a failure then names the
    // row it went wrong in, which is the difference between a bug that can be
    // found and one that can only be rewritten.
    const produced = render(matrix);
    for (let row = 0; row < vector.size; row++) {
      expect(produced[row], `row ${row}`).toBe(vector.modules[row]);
    }
  });
});

describe("the space left for data", () => {
  // Data codewords plus error correction codewords, and the remainder bits the
  // standard adds after them, per version at level M.
  const TOTAL = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346];
  const REMAINDER = [0, 7, 7, 7, 7, 7, 0, 0, 0, 0];

  it.each(TOTAL.map((_, i) => i + 1))("matches the standard at version %i", (version) => {
    // Reserving one module too many or too few shifts every data bit after the
    // mistake. The result still scans and decodes to nothing, so this is
    // checked as a number rather than left to the module comparison to catch.
    const want = (TOTAL[version - 1] as number) * 8 + (REMAINDER[version - 1] as number);
    expect(dataModuleCount(version)).toBe(want);
  });
});

describe("choosing a mask", () => {
  it("picks one, and the result is a code with the same modules every time", () => {
    // Which mask scores best is the standard's business; that the choice is
    // deterministic is this encoder's.
    const link = "https://files.example.org/d/aaaaaaaaaaaaaaaaaaaaaa#bbb";
    const once = encode(link).map((r) => r.join(""));
    const twice = encode(link).map((r) => r.join(""));
    expect(once).toEqual(twice);
  });

  it("chooses one of the eight", () => {
    const link = "https://files.example.org/d/aaaaaaaaaaaaaaaaaaaaaa#bbb";
    const chosen = encode(link).map((r) => r.join(""));
    const candidates = Array.from({ length: 8 }, (_, mask) =>
      encodeWithMask(link, mask).map((r) => r.join("")),
    );
    expect(candidates.some((c) => c.join("|") === chosen.join("|"))).toBe(true);
  });
});

describe("choosing a version", () => {
  it("grows only as far as the data needs", () => {
    // 21, 25, 29 modules: versions one, two and three.
    expect(encode("a").length).toBe(21);
    expect(encode("x".repeat(20)).length).toBe(25);
    expect(encode("x".repeat(40)).length).toBe(29);
  });

  it("refuses data it cannot carry rather than truncating it", () => {
    // A code that silently dropped the end of a link would scan, and open
    // nothing.
    expect(() => encode("x".repeat(300))).toThrow(TooMuchData);
  });

  it("carries a link comfortably", () => {
    const link = `https://files.example.org/d/${"a".repeat(22)}#${"b".repeat(43)}`;
    expect(() => encode(link)).not.toThrow();
  });
});

describe("the text that comes out", () => {
  it("survives characters outside ASCII", () => {
    // Byte mode is UTF-8 here, and a link need not be ASCII: an instance can be
    // served from an internationalised domain.
    expect(() => encode("https://exämple.test/d/x#y")).not.toThrow();
  });

  it("gives different codes for different links", () => {
    const a = render(encode("https://example.test/d/aaa#bbb")).join("");
    const b = render(encode("https://example.test/d/aaa#bbc")).join("");
    expect(a).not.toBe(b);
  });
});

describe("the path it draws", () => {
  const matrix = encode("sendan");

  it("surrounds the code with the quiet zone it needs to scan", () => {
    const { size } = toPath(matrix);
    expect(size).toBe(matrix.length + 8);
  });

  it("draws one square per dark module", () => {
    const { path } = toPath(matrix);
    const dark = matrix.flat().filter(Boolean).length;
    expect(path.split("M").length - 1).toBe(dark);
  });

  it("is one path rather than thousands of elements", () => {
    // A version 9 code has 2809 modules; that many elements is a page that
    // scrolls badly on a phone for no benefit.
    expect(typeof toPath(matrix).path).toBe("string");
  });
});
