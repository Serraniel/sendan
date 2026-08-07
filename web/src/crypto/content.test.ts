// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  CONTENT_SALT_SIZE,
  decryptBytes,
  encodedContentLength,
  encryptBytes,
  encryptStream,
  HEADER_SIZE,
  MAX_RECORD_PLAINTEXT,
  RECORD_SIZE,
} from "./content.js";
import { ContentError, KeyMaterialError } from "./errors.js";
import { FILE_KEY_SIZE } from "./keys.js";

const fileKey = () => new Uint8Array(FILE_KEY_SIZE).fill(0x11);

/** Deterministic filler, so failures are reproducible. */
function filled(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    b[i] = (i * 31 + 7) % 256;
  }
  return b;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("content encoding", () => {
  it("round trips at every record boundary", async () => {
    const sizes = [
      0,
      1,
      17,
      1024,
      MAX_RECORD_PLAINTEXT - 1,
      MAX_RECORD_PLAINTEXT,
      MAX_RECORD_PLAINTEXT + 1,
      2 * MAX_RECORD_PLAINTEXT,
      2 * MAX_RECORD_PLAINTEXT + 1,
      2 * MAX_RECORD_PLAINTEXT + 12345,
    ];
    for (const size of sizes) {
      const plaintext = filled(size);
      const stream = await encryptBytes(fileKey(), plaintext);
      expect(hex(await decryptBytes(fileKey(), stream)), `size ${size}`).toBe(hex(plaintext));
    }
  });

  it("emits a specification-conforming header", async () => {
    const stream = await encryptBytes(fileKey(), filled(5));
    const view = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);
    expect(view.getUint32(CONTENT_SALT_SIZE)).toBe(RECORD_SIZE);
    expect(stream[CONTENT_SALT_SIZE + 4]).toBe(0);

    const other = await encryptBytes(fileKey(), filled(5));
    expect(hex(stream.subarray(0, CONTENT_SALT_SIZE))).not.toBe(
      hex(other.subarray(0, CONTENT_SALT_SIZE)),
    );
  });

  it("frames records at the expected sizes", async () => {
    const cases: Array<[number, number]> = [
      [0, 1],
      [1, 1],
      [MAX_RECORD_PLAINTEXT, 1],
      [MAX_RECORD_PLAINTEXT + 1, 2],
      [2 * MAX_RECORD_PLAINTEXT, 2],
      [2 * MAX_RECORD_PLAINTEXT + 1, 3],
    ];
    for (const [size, wantRecords] of cases) {
      const body = (await encryptBytes(fileKey(), filled(size))).subarray(HEADER_SIZE);
      const records = Math.ceil(body.length / RECORD_SIZE);
      expect(records, `size ${size}`).toBe(wantRecords);
    }
  });

  // Truncation must be detected. Returning the partial plaintext would let an
  // attacker silently shorten a file.
  it("detects truncation", async () => {
    const stream = await encryptBytes(fileKey(), filled(3 * MAX_RECORD_PLAINTEXT));
    const cuts: Array<[string, number]> = [
      ["header only", HEADER_SIZE],
      ["one whole record dropped", HEADER_SIZE + 2 * RECORD_SIZE],
      ["mid record", HEADER_SIZE + RECORD_SIZE + 100],
      ["one byte short", stream.length - 1],
      ["empty stream", 0],
      ["partial header", HEADER_SIZE - 1],
    ];
    for (const [name, cut] of cuts) {
      await expect(decryptBytes(fileKey(), stream.subarray(0, cut)), name).rejects.toBeInstanceOf(
        ContentError,
      );
    }
  });

  it("detects tampering", async () => {
    const stream = await encryptBytes(fileKey(), filled(2 * MAX_RECORD_PLAINTEXT + 50));
    const flip = (at: number) => {
      const s = Uint8Array.from(stream);
      // biome-ignore lint/style/noNonNullAssertion: index is within the stream
      s[at] = s[at]! ^ 0x01;
      return s;
    };
    const appended = new Uint8Array(stream.length + 1);
    appended.set(stream, 0);

    const cases: Array<[string, Uint8Array]> = [
      ["salt in header", flip(0)],
      ["record size in header", flip(CONTENT_SALT_SIZE)],
      ["idlen in header", flip(CONTENT_SALT_SIZE + 4)],
      ["first record ciphertext", flip(HEADER_SIZE + 10)],
      ["first record tag", flip(HEADER_SIZE + RECORD_SIZE - 1)],
      ["last record", flip(stream.length - 5)],
      ["trailing data appended", appended],
    ];
    for (const [name, s] of cases) {
      await expect(decryptBytes(fileKey(), s), name).rejects.toBeInstanceOf(ContentError);
    }
  });

  // Records are bound to their position by the nonce, so moving or repeating
  // one must fail even though each record is individually well formed.
  it("binds records to their position", async () => {
    const stream = await encryptBytes(fileKey(), filled(3 * MAX_RECORD_PLAINTEXT));
    const body = stream.subarray(HEADER_SIZE);

    const swapped = Uint8Array.from(stream);
    swapped.set(body.subarray(RECORD_SIZE, 2 * RECORD_SIZE), HEADER_SIZE);
    swapped.set(body.subarray(0, RECORD_SIZE), HEADER_SIZE + RECORD_SIZE);
    await expect(decryptBytes(fileKey(), swapped)).rejects.toBeInstanceOf(ContentError);

    const replayed = Uint8Array.from(stream);
    replayed.set(body.subarray(0, RECORD_SIZE), HEADER_SIZE + RECORD_SIZE);
    await expect(decryptBytes(fileKey(), replayed)).rejects.toBeInstanceOf(ContentError);
  });

  it("rejects a wrong file key", async () => {
    const stream = await encryptBytes(fileKey(), filled(64));
    await expect(
      decryptBytes(new Uint8Array(FILE_KEY_SIZE).fill(0x22), stream),
    ).rejects.toBeInstanceOf(ContentError);
  });

  // Honouring a value taken from the stream would make these negotiated
  // parameters, which spec §11 forbids.
  it("rejects non-specification header values", async () => {
    const stream = await encryptBytes(fileKey(), filled(5));

    const badRS = Uint8Array.from(stream);
    new DataView(badRS.buffer).setUint32(CONTENT_SALT_SIZE, 4096);
    await expect(decryptBytes(fileKey(), badRS)).rejects.toBeInstanceOf(ContentError);

    const badID = Uint8Array.from(stream);
    badID[CONTENT_SALT_SIZE + 4] = 4;
    await expect(decryptBytes(fileKey(), badID)).rejects.toBeInstanceOf(ContentError);
  });

  it("rejects a bad key size", async () => {
    await expect(encryptBytes(new Uint8Array(31), filled(1))).rejects.toBeInstanceOf(
      KeyMaterialError,
    );
  });

  // Record boundaries must not depend on how a caller happened to buffer its
  // input, or two clients writing the same file would produce different bytes.
  it("is unaffected by write chunking", async () => {
    const plaintext = filled(3 * MAX_RECORD_PLAINTEXT + 77);
    const salt = new Uint8Array(CONTENT_SALT_SIZE).fill(0x33);

    const run = async (chunk: number) => {
      const transform = encryptStream(fileKey(), salt);
      const writer = transform.writable.getWriter();
      const reading = (async () => {
        const parts: Uint8Array[] = [];
        const reader = transform.readable.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          parts.push(value);
        }
        const total = parts.reduce((s, p) => s + p.length, 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) {
          out.set(p, off);
          off += p.length;
        }
        return out;
      })();
      for (let off = 0; off < plaintext.length; off += chunk) {
        await writer.write(plaintext.subarray(off, Math.min(off + chunk, plaintext.length)));
      }
      await writer.close();
      return reading;
    };

    const want = hex(await run(plaintext.length));
    for (const chunk of [
      1024,
      4096,
      MAX_RECORD_PLAINTEXT - 1,
      MAX_RECORD_PLAINTEXT,
      MAX_RECORD_PLAINTEXT + 1,
    ]) {
      expect(hex(await run(chunk)), `chunk ${chunk}`).toBe(want);
    }
  });
});

/**
 * The uploader declares the total length before it has produced a single byte
 * of it, and the server enforces that declaration. So the calculation is
 * checked against the encoder itself rather than against a second copy of the
 * arithmetic, which would agree with a wrong answer just as readily.
 */
describe("encoded length", () => {
  it("is what the encoder produces, at every boundary", async () => {
    const sizes = [
      0,
      1,
      HEADER_SIZE,
      MAX_RECORD_PLAINTEXT - 1,
      MAX_RECORD_PLAINTEXT,
      MAX_RECORD_PLAINTEXT + 1,
      2 * MAX_RECORD_PLAINTEXT - 1,
      2 * MAX_RECORD_PLAINTEXT,
      2 * MAX_RECORD_PLAINTEXT + 1,
      3 * MAX_RECORD_PLAINTEXT + 4321,
    ];
    for (const size of sizes) {
      const actual = (await encryptBytes(fileKey(), filled(size))).length;
      expect(encodedContentLength(size), `plaintext of ${size} bytes`).toBe(actual);
    }
  });

  it("is what the encoder produces for arbitrary sizes", async () => {
    // Sizes nobody would have thought to enumerate. A calculation that is right
    // only at the boundaries someone wrote down is right by coincidence.
    for (let i = 0; i < 24; i++) {
      const size = Math.floor(Math.random() * 3 * MAX_RECORD_PLAINTEXT);
      const actual = (await encryptBytes(fileKey(), filled(size))).length;
      expect(encodedContentLength(size), `plaintext of ${size} bytes`).toBe(actual);
    }
  });

  it("grows by exactly one record per record", () => {
    const one = encodedContentLength(MAX_RECORD_PLAINTEXT);
    expect(encodedContentLength(2 * MAX_RECORD_PLAINTEXT) - one).toBe(RECORD_SIZE);
    expect(encodedContentLength(3 * MAX_RECORD_PLAINTEXT) - one).toBe(2 * RECORD_SIZE);
  });

  it("charges an empty file for the final record it still emits", () => {
    // The terminating delimiter is what distinguishes a complete stream from a
    // truncated one, so even nothing is encoded as something.
    expect(encodedContentLength(0)).toBe(HEADER_SIZE + 17);
    expect(encodedContentLength(0)).toBeGreaterThan(HEADER_SIZE);
  });

  it("refuses a length that is not a byte count", () => {
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(() => encodedContentLength(bad), `${bad}`).toThrow(ContentError);
    }
  });
});
