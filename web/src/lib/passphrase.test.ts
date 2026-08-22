// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  DEFAULT_WORDS,
  describeStrength,
  entropyBits,
  generate,
  type RandomSource,
} from "./passphrase.js";
import { WORDS } from "./words.js";

/** Feeds a fixed sequence of 16-bit values, so a draw can be predicted. */
function fixedRandom(values: number[]): RandomSource {
  let at = 0;
  return (bytes) => {
    const value = values[at % values.length] as number;
    at++;
    bytes[0] = (value >> 8) & 0xff;
    bytes[1] = value & 0xff;
  };
}

describe("the word list", () => {
  it("has exactly a power of two entries, so the arithmetic is exact", () => {
    expect(WORDS.length).toBe(1024);
    expect(Math.log2(WORDS.length) % 1).toBe(0);
  });

  it("has no duplicates", () => {
    // A duplicate silently lowers the entropy of every passphrase drawn.
    expect(new Set(WORDS).size).toBe(WORDS.length);
  });

  it("is lowercase ASCII, three to eight letters", () => {
    for (const word of WORDS) {
      expect(word, word).toMatch(/^[a-z]{3,8}$/);
    }
  });

  it("contains no word that is a prefix of another", () => {
    // Read aloud without pauses, "car" and "carpet" run together and the
    // boundary is lost. Held mechanically because a word added by hand later is
    // exactly how a list stops satisfying this.
    const sorted = [...WORDS].sort();
    for (let i = 1; i < sorted.length; i++) {
      const previous = sorted[i - 1] as string;
      const current = sorted[i] as string;
      expect(current.startsWith(previous), `${current} starts with ${previous}`).toBe(false);
    }
  });
});

describe("generating", () => {
  it("draws the number of words asked for", () => {
    for (const count of [1, 3, 6, 12]) {
      expect(generate(count, fixedRandom([0])).split("-")).toHaveLength(count);
    }
  });

  it("uses only words from the list", () => {
    const words = generate(8).split("-");
    for (const word of words) expect(WORDS).toContain(word);
  });

  it("separates words visibly, for somebody transcribing it", () => {
    expect(generate(4, fixedRandom([0]))).toMatch(/^[a-z]+(-[a-z]+){3}$/);
  });

  it("refuses a length that is not a positive whole number", () => {
    for (const count of [0, -1, 1.5, Number.NaN]) {
      expect(() => generate(count, fixedRandom([0]))).toThrow(RangeError);
    }
  });

  it("takes every word from the randomness it is given", () => {
    // Index 0 and index 1023, so the ends of the list are reachable: an
    // off-by-one in the mapping would leave one of them unreachable forever.
    expect(generate(2, fixedRandom([0, 1023]))).toBe(`${WORDS[0]}-${WORDS[1023]}`);
  });

  it("does not favour the start of the list", () => {
    // The failure a modulo over a single byte would produce. Drawn from real
    // randomness, so this is a smoke test rather than a proof - but a generator
    // that could only reach the first 256 words would fail it every time.
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      for (const word of generate(6).split("-")) seen.add(word);
    }

    const late = [...seen].filter((w) => WORDS.indexOf(w) >= WORDS.length / 2);
    expect(late.length).toBeGreaterThan(100);
  });
});

describe("what it is worth", () => {
  it("is stated exactly rather than rounded", () => {
    expect(entropyBits(6)).toBe(60);
    expect(entropyBits(1)).toBe(10);
  });

  it("says the length, the list and the bits", () => {
    // Entropy stated rather than implied: "strong" means nothing, and a number
    // somebody can check means rather more.
    const said = describeStrength(DEFAULT_WORDS);
    expect(said).toContain(`${DEFAULT_WORDS} words`);
    expect(said).toContain("1024");
    expect(said).toContain("60 bits");
  });
});
