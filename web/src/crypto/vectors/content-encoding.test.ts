// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { decryptBytes, encodedContentLength, encryptBytes } from "../content.js";

/**
 * The content encoding vectors, produced by the Go implementation.
 *
 * This is the check that proves a file encrypted by the CLI can be read in the
 * browser and the reverse. Plaintexts are described rather than embedded, so
 * the 65 KiB boundary cases do not turn the fixture into a megabyte of
 * hexadecimal.
 */
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

interface ContentVectors {
  cases: Array<{
    name: string;
    fileKeyHex: string;
    contentSaltHex: string;
    plaintextLength: number;
    plaintextPattern: string;
    streamSha256: string;
    streamHex?: string;
  }>;
}

const vectors: ContentVectors = JSON.parse(
  readFileSync(join(repoRoot, "testdata", "vectors", "content-encoding.json"), "utf8"),
);

const fromHex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

/** "zero" is all 0x00; "counter" is byte i = i mod 256. */
function patternBytes(pattern: string, n: number): Uint8Array {
  const b = new Uint8Array(n);
  if (pattern === "counter") {
    for (let i = 0; i < n; i++) {
      b[i] = i % 256;
    }
  }
  return b;
}

describe("spec §5 content encoding vectors", () => {
  it("has cases", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
  });

  for (const c of vectors.cases) {
    it(`${c.name} — encrypts to the same bytes`, async () => {
      const stream = await encryptBytes(
        fromHex(c.fileKeyHex),
        patternBytes(c.plaintextPattern, c.plaintextLength),
        fromHex(c.contentSaltHex),
      );
      expect(sha256(stream)).toBe(c.streamSha256);
      if (c.streamHex !== undefined) {
        expect(toHex(stream)).toBe(c.streamHex);
      }
    });

    /**
     * The length both implementations declare before sending anything, pinned
     * to the same vector rather than to each implementation's own encoder.
     *
     * The instance enforces the declaration, so a browser and the command line
     * client that disagreed would mean one of them could never complete an
     * upload — and the disagreement would surface as a stuck transfer rather
     * than as anything naming a length.
     */
    it(`${c.name} — declares the length the vector's stream has`, async () => {
      const stream = await encryptBytes(
        fromHex(c.fileKeyHex),
        patternBytes(c.plaintextPattern, c.plaintextLength),
        fromHex(c.contentSaltHex),
      );
      expect(encodedContentLength(c.plaintextLength)).toBe(stream.length);
    });

    it(`${c.name} — decrypts the Go-produced stream`, async () => {
      // Regenerate the stream from the pinned digest's inputs, so the large
      // cases are covered without embedding them.
      const stream =
        c.streamHex !== undefined
          ? fromHex(c.streamHex)
          : await encryptBytes(
              fromHex(c.fileKeyHex),
              patternBytes(c.plaintextPattern, c.plaintextLength),
              fromHex(c.contentSaltHex),
            );
      const got = await decryptBytes(fromHex(c.fileKeyHex), stream);
      expect(toHex(got)).toBe(toHex(patternBytes(c.plaintextPattern, c.plaintextLength)));
    });
  }
});
