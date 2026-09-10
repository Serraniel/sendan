// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  bitsOf,
  DEFAULT_CHARACTERS,
  DEFAULT_WORDS,
  describeStrength,
  describeStyle,
  entropyBits,
  generate,
  generateCharacters,
  generateStyle,
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

describe("the character style", () => {
  it("is the same strength as the default passphrase", () => {
    // Equal on purpose. A choice between two generators must not read as a
    // choice about security, and the only way to make that true is to make it
    // true.
    expect(bitsOf("characters", DEFAULT_CHARACTERS)).toBe(bitsOf("words", 6));
    expect(bitsOf("characters", DEFAULT_CHARACTERS)).toBe(60);
  });

  it("draws every character from the alphabet, and only from it", () => {
    const password = generateCharacters(200);
    expect(password).toMatch(/^[a-zA-Z0-9_-]{200}$/);
  });

  it("uses the whole alphabet", () => {
    // A generator that quietly used a slice of its alphabet would still look
    // random and would be worth fewer bits than it claims.
    const seen = new Set(generateCharacters(20_000).split(""));
    expect(seen.size).toBe(64);
  });

  it("is uniform over the alphabet", () => {
    // 256 is four times 64, so every byte maps to exactly one character and
    // none is more likely than another. A modulo over a set that did not divide
    // would favour the first few, invisibly.
    const counts = new Map<string, number>();
    for (const c of generateCharacters(64_000)) counts.set(c, (counts.get(c) ?? 0) + 1);
    const expected = 64_000 / 64;
    for (const [character, count] of counts) {
      expect(Math.abs(count - expected) / expected, character).toBeLessThan(0.25);
    }
  });

  it("refuses a length that is not one", () => {
    expect(() => generateCharacters(0)).toThrow(RangeError);
    expect(() => generateCharacters(1.5)).toThrow(RangeError);
  });
});

describe("describing either style", () => {
  it("says the same kind of thing about both", () => {
    // Two descriptions that read differently invite the reader to conclude that
    // one is better.
    expect(describeStyle("words")).toBe(
      "6 words from a list of 1024, which is 60 bits of randomness.",
    );
    expect(describeStyle("characters")).toBe(
      "10 characters from an alphabet of 64, which is 60 bits of randomness.",
    );
  });
});

describe("generating in a chosen style", () => {
  it("produces words or characters as asked", () => {
    expect(generateStyle("words")).toMatch(/^[a-z]+(-[a-z]+){5}$/);
    expect(generateStyle("characters")).toMatch(/^[a-zA-Z0-9_-]{10}$/);
  });
});
