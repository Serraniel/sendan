// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Generating a password worth using.
 *
 * The field is optional and empty by default, so the passwords that do get set
 * are the ones people invent on the spot. This offers something better at no
 * cost to anybody who ignores it.
 *
 * ## Words, not characters
 *
 * A password here is the second half of the protection and travels separately
 * from the link - which in practice means somebody reads it out, writes it on
 * paper, or types it into a different application. Words survive that; a string
 * of symbols does not, and the one people actually choose after failing to
 * transcribe one is worse than either.
 *
 * ## Where the randomness comes from
 *
 * `crypto.getRandomValues`, and nothing else. Not the time, not the file, not
 * anything about the person: a passphrase that could be reconstructed from
 * something an observer also has is not a passphrase.
 */

import { WORDS } from "./words.js";

/** How many words a generated passphrase has by default. */
export const DEFAULT_WORDS = 6;

/** What a generated passphrase is worth, in bits. */
export function entropyBits(wordCount: number): number {
  // The list is a power of two on purpose, so this is exact rather than a
  // rounded logarithm somebody has to take on trust.
  return wordCount * Math.log2(WORDS.length);
}

/** Random bytes, narrowed so a test can supply its own. */
export type RandomSource = (bytes: Uint8Array) => void;

function browserRandom(bytes: Uint8Array): void {
  crypto.getRandomValues(bytes);
}

/**
 * Picks one word, uniformly.
 *
 * Rejection sampling rather than a modulo. With 1024 words a modulo over a byte
 * would be biased before it was even wrong in an interesting way, and the habit
 * of reaching for `% length` is how a generator that looks fine ends up
 * favouring the first few entries of its own list.
 */
function pick(random: RandomSource): string {
  // Two bytes give 65536 values; 65536 = 64 × 1024, so every value maps to a
  // word and nothing is ever rejected for this list. The loop stays because the
  // list length is not this function's to assume.
  const limit = Math.floor(65536 / WORDS.length) * WORDS.length;
  const bytes = new Uint8Array(2);

  for (;;) {
    random(bytes);
    const value = ((bytes[0] as number) << 8) | (bytes[1] as number);
    if (value < limit) return WORDS[value % WORDS.length] as string;
  }
}

/**
 * A passphrase of the given length.
 *
 * Joined with hyphens: a separator that survives being copied out of a message,
 * read aloud, and typed back in, and one that makes the word boundaries visible
 * to somebody transcribing it.
 */
export function generate(
  wordCount: number = DEFAULT_WORDS,
  random: RandomSource = browserRandom,
): string {
  if (!Number.isInteger(wordCount) || wordCount < 1) {
    throw new RangeError("passphrase: a passphrase needs at least one word");
  }

  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) words.push(pick(random));
  return words.join("-");
}

/** How to describe a generated passphrase, without overstating it. */
export function describeStrength(wordCount: number = DEFAULT_WORDS): string {
  const bits = entropyBits(wordCount);
  return `${wordCount} words from a list of ${WORDS.length}, which is ${bits} bits of randomness.`;
}
