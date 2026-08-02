// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { encodeMetadata } from "../metadata.js";

/**
 * The cross-language contract. These fixtures are shared with the Go
 * implementation and are the only thing mechanically preventing the CLI and the
 * browser from disagreeing about what a file means.
 *
 * The metadata plaintext is encrypted, so a divergence of one character means a
 * file sealed by one implementation cannot be opened by the other at all.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

interface JSONEncodingVectors {
  cases: Array<{
    name: string;
    input: { name: string; type: string; size: number };
    expected: string;
  }>;
}

const vectors: JSONEncodingVectors = JSON.parse(
  readFileSync(join(repoRoot, "testdata", "vectors", "json-encoding.json"), "utf8"),
);

const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe("spec §7.1 JSON encoding vectors", () => {
  it("has cases", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
  });

  for (const c of vectors.cases) {
    it(c.name, () => {
      expect(text(encodeMetadata(c.input))).toBe(c.expected);
    });
  }
});
