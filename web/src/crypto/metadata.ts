// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { MetadataError } from "./errors.js";
import { NONCE_SIZE, randomBytes } from "./keys.js";
import { AAD_METADATA, aesGcmOpen, aesGcmSeal, importAesKey } from "./wrap.js";

/** Padding granularity, per spec §7. Blunts disclosure of filename length. */
const PAD_BLOCK = 256;

/**
 * Largest representable upload size, 2^53 - 1.
 *
 * JavaScript numbers are IEEE-754 doubles, so anything larger rounds silently
 * rather than failing. Go can encode any int64 faithfully, so without this
 * bound the two implementations would disagree about a size with no error
 * raised anywhere. See spec §7.
 */
export const MAX_METADATA_SIZE = Number.MAX_SAFE_INTEGER;

export interface Metadata {
  name: string;
  type: string;
  size: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Whether a string contains no unpaired surrogate.
 *
 * JavaScript strings are UTF-16 and may hold a lone surrogate, which has no
 * UTF-8 encoding. Go rejects such input outright, so accepting it here would
 * let this implementation seal metadata that Go would refuse to produce.
 *
 * Implemented by hand rather than via String.prototype.isWellFormed so the
 * behaviour does not depend on the engine's ECMAScript version.
 */
function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        return false;
      }
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Applies the escaping of spec §7.1: quote, reverse solidus, and the C0 control
 * characters. Everything else, including all non-ASCII, is emitted literally.
 *
 * JSON.stringify is deliberately not used. It happens to match for well-formed
 * input, which makes delegating to it look safe, but its edge-case output is a
 * property of whichever engine the visitor is running, and the wire format must
 * not depend on that.
 */
function encodeJSONString(s: string): string {
  let out = '"';
  for (const ch of s) {
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default: {
        const c = ch.codePointAt(0) ?? 0;
        out += c < 0x20 ? `\\u${c.toString(16).padStart(4, "0")}` : ch;
      }
    }
  }
  return `${out}"`;
}

/** The deterministic JSON encoding of spec §7.1, as UTF-8 bytes. */
export function encodeMetadata(m: Metadata): Uint8Array {
  if (!isWellFormed(m.name) || !isWellFormed(m.type)) {
    throw new MetadataError("name and type must be valid UTF-8");
  }
  if (!Number.isInteger(m.size) || m.size < 0 || m.size > MAX_METADATA_SIZE) {
    throw new MetadataError(`size must be an integer between 0 and ${MAX_METADATA_SIZE}`);
  }
  const json = `{"name":${encodeJSONString(m.name)},"type":${encodeJSONString(
    m.type,
  )},"size":${m.size}}`;
  return encoder.encode(json);
}

/**
 * ISO/IEC 7816-4 padding to a multiple of PAD_BLOCK: a single 0x80 octet
 * followed by 0x00 octets. Padding is always added, so an already aligned
 * plaintext still gains a full block.
 */
function pad(plaintext: Uint8Array): Uint8Array {
  const total = Math.ceil((plaintext.length + 1) / PAD_BLOCK) * PAD_BLOCK;
  const padded = new Uint8Array(total);
  padded.set(plaintext, 0);
  padded[plaintext.length] = 0x80;
  return padded;
}

function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length === 0 || padded.length % PAD_BLOCK !== 0) {
    throw new MetadataError("padded length is not a block multiple");
  }
  let i = padded.length - 1;
  while (i >= 0 && padded[i] === 0x00) {
    i--;
  }
  if (i < 0 || padded[i] !== 0x80) {
    throw new MetadataError("padding marker missing");
  }
  return padded.subarray(0, i);
}

export interface SealedMetadata {
  nonce: Uint8Array;
  envelope: Uint8Array;
}

/** Encrypts metadata under the metadata key (spec §7). */
export async function sealMetadata(metadataKey: Uint8Array, m: Metadata): Promise<SealedMetadata> {
  const plaintext = encodeMetadata(m);
  const key = await importAesKey(metadataKey);
  const nonce = randomBytes(NONCE_SIZE);
  return { nonce, envelope: await aesGcmSeal(key, nonce, pad(plaintext), AAD_METADATA) };
}

/** Decrypts an envelope produced by {@link sealMetadata}. */
export async function openMetadata(
  metadataKey: Uint8Array,
  nonce: Uint8Array,
  envelope: Uint8Array,
): Promise<Metadata> {
  const key = await importAesKey(metadataKey);
  if (nonce.length !== NONCE_SIZE) {
    throw new MetadataError("nonce has the wrong length");
  }

  let padded: Uint8Array;
  try {
    padded = await aesGcmOpen(key, nonce, envelope, AAD_METADATA);
  } catch {
    throw new MetadataError("envelope failed authentication");
  }

  const plaintext = unpad(padded);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new MetadataError("envelope is not valid JSON");
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new MetadataError("envelope is not an object");
  }
  const keys = Object.keys(parsed);
  if (keys.length !== 3 || !keys.every((k) => k === "name" || k === "type" || k === "size")) {
    throw new MetadataError("envelope has unexpected members");
  }

  const { name, type, size } = parsed as Record<string, unknown>;
  if (typeof name !== "string" || typeof type !== "string" || typeof size !== "number") {
    throw new MetadataError("envelope members have the wrong types");
  }
  // Reject on the way out as well as on the way in: an envelope may have been
  // produced by a different implementation, or by an older version of this one.
  if (!Number.isInteger(size) || size < 0 || size > MAX_METADATA_SIZE) {
    throw new MetadataError("size is out of range");
  }
  return { name, type, size };
}
