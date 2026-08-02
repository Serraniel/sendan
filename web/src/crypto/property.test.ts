// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { decryptBytes, encryptBytes, HEADER_SIZE, MAX_RECORD_PLAINTEXT } from "./content.js";
import { ContentError } from "./errors.js";
import { FILE_KEY_SIZE } from "./keys.js";
import { encodeMetadata, type Metadata, openMetadata, sealMetadata } from "./metadata.js";

/**
 * Randomised property tests, the TypeScript counterpart to the Go fuzz targets.
 *
 * Go's native fuzzing has no equivalent here, so these use a seeded generator
 * instead: the iteration count is bounded so they can run as an ordinary merge
 * gate, and the seed is fixed so a failure is reproducible rather than a
 * one-off that vanishes on rerun.
 */

/** xorshift32, so a failing case can always be reproduced from its seed. */
function makeRandom(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x1_0000_0000;
  };
}

const SEED = 0x5e_5d_a1_00 >>> 0;
const fileKey = () => new Uint8Array(FILE_KEY_SIZE).fill(0x11);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function randomBytesFrom(rand: () => number, n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    b[i] = Math.floor(rand() * 256);
  }
  return b;
}

describe("content encoding properties", () => {
  it("round trips at arbitrary lengths", async () => {
    const rand = makeRandom(SEED);
    for (let i = 0; i < 40; i++) {
      // Weighted towards record boundaries, where framing errors live.
      const near = Math.floor(rand() * 3) * MAX_RECORD_PLAINTEXT;
      const jitter = Math.floor(rand() * 200) - 100;
      const size = Math.max(0, near + jitter);

      const plaintext = randomBytesFrom(rand, size);
      const stream = await encryptBytes(fileKey(), plaintext);
      expect(hex(await decryptBytes(fileKey(), stream)), `size ${size}`).toBe(hex(plaintext));
    }
  });

  it("rejects every single-bit change", async () => {
    const rand = makeRandom(SEED + 1);
    const stream = await encryptBytes(fileKey(), randomBytesFrom(rand, MAX_RECORD_PLAINTEXT + 500));

    for (let i = 0; i < 60; i++) {
      const pos = Math.floor(rand() * stream.length);
      const bit = Math.floor(rand() * 8);
      const mutated = Uint8Array.from(stream);
      // biome-ignore lint/style/noNonNullAssertion: pos is within the stream
      mutated[pos] = mutated[pos]! ^ (1 << bit);

      await expect(
        decryptBytes(fileKey(), mutated),
        `byte ${pos} bit ${bit}`,
      ).rejects.toBeInstanceOf(ContentError);
    }
  });

  it("rejects truncation at every offset sampled", async () => {
    const rand = makeRandom(SEED + 2);
    const stream = await encryptBytes(fileKey(), randomBytesFrom(rand, 2 * MAX_RECORD_PLAINTEXT));

    for (let i = 0; i < 30; i++) {
      const cut = Math.floor(rand() * stream.length);
      if (cut === stream.length) {
        continue;
      }
      await expect(
        decryptBytes(fileKey(), stream.subarray(0, cut)),
        `cut at ${cut}`,
      ).rejects.toBeInstanceOf(ContentError);
    }
  });

  it("never emits a stream shorter than its header", async () => {
    const rand = makeRandom(SEED + 3);
    for (let i = 0; i < 10; i++) {
      const stream = await encryptBytes(fileKey(), randomBytesFrom(rand, Math.floor(rand() * 50)));
      expect(stream.length).toBeGreaterThan(HEADER_SIZE);
    }
  });
});

describe("metadata properties", () => {
  it("either rejects input or round trips it unchanged", async () => {
    const rand = makeRandom(SEED + 4);
    const alphabet = [
      "a",
      "Z",
      "0",
      " ",
      ".",
      "/",
      "\\",
      '"',
      "\n",
      "\t",
      "日",
      "🔐",
      "<",
      "&",
      ">",
    ];

    const key = new Uint8Array(32).fill(0x0c);
    for (let i = 0; i < 60; i++) {
      let name = "";
      const length = Math.floor(rand() * 40);
      for (let j = 0; j < length; j++) {
        name += alphabet[Math.floor(rand() * alphabet.length)];
      }
      const m: Metadata = {
        name,
        type: rand() < 0.5 ? "text/plain" : "",
        size: Math.floor(rand() * 1_000_000),
      };

      const { nonce, envelope } = await sealMetadata(key, m);
      // Silently mangling is the failure mode that matters; rejection is fine.
      expect(await openMetadata(key, nonce, envelope), `case ${i}`).toEqual(m);
    }
  });

  it("encodes identical input to identical bytes", () => {
    const rand = makeRandom(SEED + 5);
    for (let i = 0; i < 30; i++) {
      const m: Metadata = {
        name: `f${Math.floor(rand() * 1000)}.bin`,
        type: "application/octet-stream",
        size: Math.floor(rand() * 1_000_000),
      };
      expect(hex(encodeMetadata(m))).toBe(hex(encodeMetadata(m)));
    }
  });
});
