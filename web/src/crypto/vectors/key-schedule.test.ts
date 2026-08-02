// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { deriveKeys, deriveKeysWithPassword } from "../keys.js";
import { hashPassword } from "../password.js";

/**
 * The key schedule vectors, produced by the Go implementation.
 *
 * The Argon2id cases carry the most weight. WebCrypto has no Argon2, so this
 * implementation uses hash-wasm while Go uses golang.org/x/crypto/argon2 — two
 * entirely separate implementations whose parameters are easy to interpret
 * differently. Nothing else in the project would catch a mismatch.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

interface KeyScheduleVectors {
  cases: Array<{
    name: string;
    fileIdHex: string;
    linkSecretHex: string;
    password?: string;
    saltHex?: string;
    memoryKiB?: number;
    iterations?: number;
    parallelism?: number;
    wrappingHex: string;
    metadataHex: string;
    authTokenHex: string;
  }>;
  argon2id: Array<{
    name: string;
    password: string;
    saltHex: string;
    memoryKiB: number;
    iterations: number;
    parallelism: number;
    hashHex: string;
  }>;
}

const vectors: KeyScheduleVectors = JSON.parse(
  readFileSync(join(repoRoot, "testdata", "vectors", "key-schedule.json"), "utf8"),
);

const fromHex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("spec §4 key schedule vectors", () => {
  it("has cases", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    expect(vectors.argon2id.length).toBeGreaterThan(0);
  });

  for (const c of vectors.cases) {
    it(c.name, async () => {
      const fileID = fromHex(c.fileIdHex);
      const linkSecret = fromHex(c.linkSecretHex);

      const keys =
        c.saltHex === undefined
          ? await deriveKeys(fileID, linkSecret)
          : await deriveKeysWithPassword(fileID, linkSecret, c.password ?? "", {
              salt: fromHex(c.saltHex),
              memoryKiB: c.memoryKiB ?? 0,
              iterations: c.iterations ?? 0,
              parallelism: c.parallelism ?? 0,
            });

      expect(toHex(keys.wrapping)).toBe(c.wrappingHex);
      expect(toHex(keys.metadata)).toBe(c.metadataHex);
      expect(toHex(keys.authToken)).toBe(c.authTokenHex);
    });
  }
});

describe("Argon2id vectors", () => {
  for (const c of vectors.argon2id) {
    it(c.name, async () => {
      const hash = await hashPassword(c.password, {
        salt: fromHex(c.saltHex),
        memoryKiB: c.memoryKiB,
        iterations: c.iterations,
        parallelism: c.parallelism,
      });
      expect(toHex(hash)).toBe(c.hashHex);
    });
  }
});
