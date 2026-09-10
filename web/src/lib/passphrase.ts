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

/**
 * The two ways a password can be generated.
 *
 * Neither is the strong one. At the defaults they are the same strength, and
 * the choice is about how the password travels: words are read out, written
 * down and retyped; characters are pasted. On a tool whose password must reach
 * somebody by a second route, that is not a comfort - it is what makes the
 * password arrive intact.
 */
export type Style = "words" | "characters";

/**
 * The alphabet for the character style: sixty-four symbols, so each one is
 * exactly six bits.
 *
 * A power of two for the same reason the word list is one - the arithmetic is
 * exact rather than a rounded logarithm somebody has to take on trust - and it
 * needs no rejection sampling, since 256 divides by 64.
 *
 * These sixty-four and not another sixty-four: no quotes, backslashes or
 * spaces, which are the characters that get mangled by a shell, a spreadsheet
 * or a copy that trims. A password that arrives altered is a password that
 * does not work, and the person on the other end cannot tell which character
 * went missing.
 */
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/**
 * How many characters make the same strength as the default passphrase.
 *
 * Ten, at six bits each: sixty, which is what six words from a list of 1024
 * come to. Equal on purpose, so the choice between them cannot be read as a
 * choice about security.
 */
export const DEFAULT_CHARACTERS = 10;

/** What a generated passphrase is worth, in bits. */
export function entropyBits(wordCount: number): number {
  // The list is a power of two on purpose, so this is exact rather than a
  // rounded logarithm somebody has to take on trust.
  return wordCount * Math.log2(WORDS.length);
}

/**
 * Random bytes, narrowed so a test can supply its own.
 *
 * The buffer is spelled out because `crypto.getRandomValues` will not take a
 * view that might sit on a `SharedArrayBuffer`, and a bare `Uint8Array` might.
 */
export type RandomSource = (bytes: Uint8Array<ArrayBuffer>) => void;

function browserRandom(bytes: Uint8Array<ArrayBuffer>): void {
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

/**
 * Picks one character, uniformly.
 *
 * No rejection needed: 256 is four times 64, so every byte maps to exactly one
 * character and none is more likely than another.
 */
function pickCharacter(random: RandomSource): string {
  const byte = new Uint8Array(1);
  random(byte);
  return ALPHABET[(byte[0] as number) % ALPHABET.length] as string;
}

/** A password of random characters, for somebody who will only ever paste it. */
export function generateCharacters(
  count: number = DEFAULT_CHARACTERS,
  random: RandomSource = browserRandom,
): string {
  if (!Number.isInteger(count) || count < 1) {
    throw new RangeError("passphrase: a password needs at least one character");
  }

  let out = "";
  for (let i = 0; i < count; i++) out += pickCharacter(random);
  return out;
}

/** What a generated password is worth, in bits, whichever style made it. */
export function bitsOf(style: Style, count: number): number {
  return style === "words" ? entropyBits(count) : count * Math.log2(ALPHABET.length);
}

/**
 * What either style produces, said the same way for both.
 *
 * The same sentence shape on purpose: two descriptions that read differently
 * invite a reader to conclude that one is better, and at these defaults they
 * are the same strength.
 */
export function describeStyle(style: Style, count: number = defaultCountFor(style)): string {
  const bits = bitsOf(style, count);
  return style === "words"
    ? `${count} words from a list of ${WORDS.length}, which is ${bits} bits of randomness.`
    : `${count} characters from an alphabet of ${ALPHABET.length}, which is ${bits} bits of randomness.`;
}

/** How many of a style make the default. */
export function defaultCountFor(style: Style): number {
  return style === "words" ? DEFAULT_WORDS : DEFAULT_CHARACTERS;
}

/** A password in the chosen style. */
export function generateStyle(
  style: Style,
  count: number = defaultCountFor(style),
  random: RandomSource = browserRandom,
): string {
  return style === "words" ? generate(count, random) : generateCharacters(count, random);
}
