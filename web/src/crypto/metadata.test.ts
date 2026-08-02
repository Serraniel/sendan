// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { MetadataError } from "./errors.js";
import { NONCE_SIZE } from "./keys.js";
import {
  encodeMetadata,
  MAX_METADATA_SIZE,
  type Metadata,
  openMetadata,
  sealMetadata,
} from "./metadata.js";

const metadataKey = () => new Uint8Array(32).fill(0x0c);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe("metadata envelope", () => {
  it("round trips", async () => {
    const cases: Metadata[] = [
      { name: "report.pdf", type: "application/pdf", size: 1048576 },
      { name: "", type: "", size: 0 },
      { name: "日本語のファイル.txt", type: "text/plain", size: 42 },
      { name: 'quote" backslash\\ slash/', type: "text/plain", size: 1 },
      { name: "emoji 🔐.bin", type: "application/octet-stream", size: MAX_METADATA_SIZE },
      { name: "a".repeat(4096), type: "text/plain", size: 7 },
    ];
    for (const m of cases) {
      const { nonce, envelope } = await sealMetadata(metadataKey(), m);
      expect(await openMetadata(metadataKey(), nonce, envelope)).toEqual(m);
    }
  });

  it("hides the filename", async () => {
    const m = { name: "verysecretfilename.pdf", type: "application/pdf", size: 10 };
    const { envelope } = await sealMetadata(metadataKey(), m);
    expect(text(envelope)).not.toContain(m.name);
  });

  // Padding exists so ciphertext length does not disclose filename length.
  it("pads to block multiples", async () => {
    const sizes: number[] = [];
    for (const n of [1, 5, 20, 50]) {
      const { envelope } = await sealMetadata(metadataKey(), {
        name: "a".repeat(n),
        type: "text/plain",
        size: 1,
      });
      sizes.push(envelope.length);
    }
    expect(new Set(sizes).size).toBe(1);

    const small = await sealMetadata(metadataKey(), { name: "a".repeat(8), type: "", size: 1 });
    const large = await sealMetadata(metadataKey(), { name: "a".repeat(600), type: "", size: 1 });
    expect((large.envelope.length - small.envelope.length) % 256).toBe(0);
  });

  it("rejects tampering", async () => {
    const { nonce, envelope } = await sealMetadata(metadataKey(), {
      name: "a.txt",
      type: "text/plain",
      size: 3,
    });

    const corrupt = Uint8Array.from(envelope);
    corrupt[0] = (corrupt[0] ?? 0) ^ 0x01;
    const badNonce = Uint8Array.from(nonce);
    badNonce[0] = (badNonce[0] ?? 0) ^ 0x01;

    const cases: Array<[string, Uint8Array, Uint8Array, Uint8Array]> = [
      ["flipped bit", metadataKey(), nonce, corrupt],
      ["wrong nonce", metadataKey(), badNonce, envelope],
      ["wrong key", new Uint8Array(32).fill(0x0d), nonce, envelope],
      ["truncated", metadataKey(), nonce, envelope.subarray(0, envelope.length - 1)],
      ["short nonce", metadataKey(), nonce.subarray(0, NONCE_SIZE - 1), envelope],
    ];
    for (const [name, key, n, e] of cases) {
      await expect(openMetadata(key, n, e), name).rejects.toBeInstanceOf(MetadataError);
    }
  });

  it("rejects invalid input", () => {
    const cases: Array<[string, Metadata]> = [
      ["lone high surrogate", { name: "a\ud800b", type: "text/plain", size: 0 }],
      ["lone low surrogate", { name: "a\udc00b", type: "text/plain", size: 0 }],
      ["lone surrogate in type", { name: "a", type: "\ud800", size: 0 }],
      ["negative size", { name: "a", type: "", size: -1 }],
      ["size above 2^53-1", { name: "a", type: "", size: MAX_METADATA_SIZE + 1 }],
      ["fractional size", { name: "a", type: "", size: 1.5 }],
    ];
    for (const [name, m] of cases) {
      expect(() => encodeMetadata(m), name).toThrow(MetadataError);
    }
  });

  // A correctly paired surrogate is ordinary text and must be accepted.
  it("accepts paired surrogates", () => {
    expect(() => encodeMetadata({ name: "🔐", type: "", size: 0 })).not.toThrow();
  });
});

// These expectations are duplicated from the Go implementation on purpose. The
// authoritative cross-language check lives in src/crypto/vectors.
describe("deterministic JSON encoding (spec §7.1)", () => {
  const cases: Array<[string, Metadata, string]> = [
    [
      "plain",
      { name: "a.txt", type: "text/plain", size: 3 },
      '{"name":"a.txt","type":"text/plain","size":3}',
    ],
    [
      "html significant characters are not escaped",
      { name: '<a>&"b"', type: "text/plain", size: 1 },
      '{"name":"<a>&\\"b\\"","type":"text/plain","size":1}',
    ],
    [
      "line and paragraph separators are literal",
      { name: "a b c", type: "", size: 0 },
      '{"name":"a b c","type":"","size":0}',
    ],
    [
      "short control escapes",
      { name: "a\nb\tc\rd", type: "", size: 0 },
      '{"name":"a\\nb\\tc\\rd","type":"","size":0}',
    ],
    [
      "numeric control escapes are lowercase",
      { name: "ab", type: "", size: 0 },
      '{"name":"a\\u0001\\u001fb","type":"","size":0}',
    ],
    ["backslash", { name: "a\\b", type: "", size: 0 }, '{"name":"a\\\\b","type":"","size":0}'],
    [
      "non-ascii is literal utf-8",
      { name: "日本語", type: "", size: 0 },
      '{"name":"日本語","type":"","size":0}',
    ],
  ];

  for (const [name, m, want] of cases) {
    it(name, () => {
      expect(text(encodeMetadata(m))).toBe(want);
    });
  }
});
