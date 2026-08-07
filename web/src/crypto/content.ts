// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { ContentError, KeyMaterialError } from "./errors.js";
import { FILE_KEY_SIZE, randomBytes } from "./keys.js";

/** Content encoding parameters, per spec §5. */
export const RECORD_SIZE = 65536;
export const CONTENT_SALT_SIZE = 16;

/** cSalt(16) || rs(4) || idlen(1), with an empty keyid. */
export const HEADER_SIZE = CONTENT_SALT_SIZE + 4 + 1;

/** The record size less the GCM tag and the delimiter. */
export const MAX_RECORD_PLAINTEXT = RECORD_SIZE - 16 - 1;

const DELIMITER_NON_FINAL = 0x01;
const DELIMITER_FINAL = 0x02;

/** A record's ciphertext less its plaintext: the delimiter and the GCM tag. */
const RECORD_OVERHEAD = 1 + 16;

/**
 * The encoded length of a plaintext of the given size.
 *
 * An uploader must declare the total length before sending the first byte, and
 * what it sends is the encoding rather than the file, so it has to know this
 * without having produced it. Being wrong is not a rounding error: too small
 * and the server refuses the tail, too large and the upload never completes.
 *
 * The encoding is fully determined by the length, which is what makes this
 * possible. Records hold {@link MAX_RECORD_PLAINTEXT} bytes; the final one is
 * short, and is emitted even for an empty file because the terminating
 * delimiter is what distinguishes a complete stream from a truncated one.
 */
export function encodedContentLength(plaintextLength: number): number {
  if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
    throw new ContentError(`plaintext length ${plaintextLength} is not a byte count`);
  }
  // A whole multiple of the record size fills its last record exactly, and that
  // record is the final one. Rounding up would claim a further empty record
  // that the encoder never emits.
  const nonFinal =
    plaintextLength === 0 ? 0 : Math.ceil(plaintextLength / MAX_RECORD_PLAINTEXT) - 1;
  const finalPlaintext = plaintextLength - nonFinal * MAX_RECORD_PLAINTEXT;
  return HEADER_SIZE + nonFinal * RECORD_SIZE + finalPlaintext + RECORD_OVERHEAD;
}

/**
 * Bounds the record counter well below the point at which the 96-bit nonce
 * space could wrap. Exceeding it would risk nonce reuse, which discloses the
 * GCM authentication key.
 */
const MAX_SEQUENCE = 2 ** 48;

/**
 * Info strings for content key derivation, per spec §5.1.
 *
 * The aes256gcm designation is deliberate: RFC 8188 defines only aes128gcm, and
 * Sendan uses the same framing with a 256-bit key. A distinct info string keeps
 * the two from ever deriving the same key material.
 *
 * Built with fromCharCode so no literal NUL appears in the source.
 */
const NUL = String.fromCharCode(0);
const INFO_CONTENT_KEY = `Content-Encoding: aes256gcm${NUL}`;
const INFO_CONTENT_NONCE = `Content-Encoding: nonce${NUL}`;

const encoder = new TextEncoder();

interface ContentKeys {
  key: CryptoKey;
  nonceBase: Uint8Array;
}

async function deriveContentKeys(
  fileKey: Uint8Array,
  contentSalt: Uint8Array,
): Promise<ContentKeys> {
  if (fileKey.length !== FILE_KEY_SIZE) {
    throw new KeyMaterialError(`file key is ${fileKey.length} bytes, want ${FILE_KEY_SIZE}`);
  }
  if (contentSalt.length !== CONTENT_SALT_SIZE) {
    throw new KeyMaterialError(
      `content salt is ${contentSalt.length} bytes, want ${CONTENT_SALT_SIZE}`,
    );
  }

  const base = await crypto.subtle.importKey("raw", fileKey as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const derive = async (info: string, bytes: number) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: contentSalt as BufferSource,
          info: encoder.encode(info) as BufferSource,
        },
        base,
        bytes * 8,
      ),
    );

  const [raw, nonceBase] = await Promise.all([
    derive(INFO_CONTENT_KEY, 32),
    derive(INFO_CONTENT_NONCE, 12),
  ]);
  const key = await crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  return { key, nonceBase };
}

/**
 * The nonce for a record, per spec §5.3: the nonce base exclusive-ORed with the
 * big-endian record sequence number.
 *
 * The sequence number is a strict counter and is never random. Two records of
 * one stream must never share a nonce.
 */
function recordNonce(base: Uint8Array, seq: number): Uint8Array {
  const n = Uint8Array.from(base);
  // The counter is 96-bit big-endian, but a sequence below 2^48 can only
  // occupy the low six octets.
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(seq));
  for (let i = 0; i < 8; i++) {
    // biome-ignore lint/style/noNonNullAssertion: indices 4..11 are always in range
    n[4 + i] = n[4 + i]! ^ view.getUint8(i);
  }
  return n;
}

function buildHeader(contentSalt: Uint8Array): Uint8Array {
  const header = new Uint8Array(HEADER_SIZE);
  header.set(contentSalt, 0);
  new DataView(header.buffer).setUint32(CONTENT_SALT_SIZE, RECORD_SIZE);
  header[CONTENT_SALT_SIZE + 4] = 0; // idlen: the keyid is always empty
  return header;
}

/**
 * A TransformStream encrypting plaintext into the Sendan content encoding.
 *
 * A buffered full record is never emitted eagerly, because whether it is the
 * final record is unknown until either more data arrives or the stream ends.
 * The final record carries the terminating delimiter, so a consumer that never
 * receives it correctly treats the stream as truncated.
 */
export function encryptStream(
  fileKey: Uint8Array,
  contentSalt: Uint8Array = randomBytes(CONTENT_SALT_SIZE),
): TransformStream<Uint8Array, Uint8Array> {
  let keys: ContentKeys | null = null;
  let seq = 0;
  const buf = new Uint8Array(MAX_RECORD_PLAINTEXT);
  let n = 0;
  let headerWritten = false;

  const flush = async (
    controller: TransformStreamDefaultController<Uint8Array>,
    final: boolean,
  ) => {
    if (!keys) {
      keys = await deriveContentKeys(fileKey, contentSalt);
    }
    if (!headerWritten) {
      controller.enqueue(buildHeader(contentSalt));
      headerWritten = true;
    }
    if (seq >= MAX_SEQUENCE) {
      throw new ContentError("record sequence exhausted");
    }

    const plaintext = new Uint8Array(n + 1);
    plaintext.set(buf.subarray(0, n), 0);
    plaintext[n] = final ? DELIMITER_FINAL : DELIMITER_NON_FINAL;

    const record = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: recordNonce(keys.nonceBase, seq) as BufferSource, tagLength: 128 },
        keys.key,
        plaintext as BufferSource,
      ),
    );
    controller.enqueue(record);
    seq++;
    n = 0;
  };

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      let offset = 0;
      while (offset < chunk.length) {
        if (n === MAX_RECORD_PLAINTEXT) {
          // The buffer is full and more data remains, so this record is
          // certainly not the final one.
          await flush(controller, false);
        }
        const take = Math.min(MAX_RECORD_PLAINTEXT - n, chunk.length - offset);
        buf.set(chunk.subarray(offset, offset + take), n);
        n += take;
        offset += take;
      }
    },
    async flush(controller) {
      await flush(controller, true);
    },
  });
}

/**
 * A TransformStream decrypting the Sendan content encoding.
 *
 * A stream that ends without a final record raises {@link ContentError} rather
 * than completing, so truncation can never be mistaken for a complete file.
 */
export function decryptStream(fileKey: Uint8Array): TransformStream<Uint8Array, Uint8Array> {
  let keys: ContentKeys | null = null;
  let seq = 0;
  let sawFinal = false;
  let pending = new Uint8Array(0);

  const append = (chunk: Uint8Array) => {
    const next = new Uint8Array(pending.length + chunk.length);
    next.set(pending, 0);
    next.set(chunk, pending.length);
    pending = next;
  };

  const readHeader = async () => {
    const salt = pending.subarray(0, CONTENT_SALT_SIZE);
    const view = new DataView(pending.buffer, pending.byteOffset, pending.byteLength);
    const rs = view.getUint32(CONTENT_SALT_SIZE);
    const idlen = pending[CONTENT_SALT_SIZE + 4];

    // The record size and key identifier are fixed by the specification. They
    // are validated rather than honoured: accepting a value from the stream
    // would be a negotiated parameter, which spec §11 forbids.
    if (rs !== RECORD_SIZE || idlen !== 0) {
      throw new ContentError("header does not match the specification");
    }
    try {
      keys = await deriveContentKeys(fileKey, Uint8Array.from(salt));
    } catch {
      throw new ContentError("cannot derive content keys");
    }
    pending = pending.slice(HEADER_SIZE);
  };

  const decryptRecord = async (
    record: Uint8Array,
    controller: TransformStreamDefaultController<Uint8Array>,
  ) => {
    if (!keys) {
      throw new ContentError("header has not been read");
    }
    if (seq >= MAX_SEQUENCE || sawFinal) {
      throw new ContentError("data follows the final record");
    }

    let plaintext: Uint8Array;
    try {
      plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: recordNonce(keys.nonceBase, seq) as BufferSource,
            tagLength: 128,
          },
          keys.key,
          record as BufferSource,
        ),
      );
    } catch {
      throw new ContentError("record failed authentication");
    }
    if (plaintext.length === 0) {
      throw new ContentError("record has no delimiter");
    }

    // The delimiter is the final octet. Optional zero padding, which RFC 8188
    // permits, is deliberately not accepted: it would make two distinct
    // encodings of one plaintext valid.
    const delimiter = plaintext[plaintext.length - 1];
    if (delimiter === DELIMITER_FINAL) {
      sawFinal = true;
    } else if (delimiter === DELIMITER_NON_FINAL) {
      // A non-final record must be full; otherwise a truncated stream could be
      // presented as a complete one.
      if (record.length !== RECORD_SIZE) {
        throw new ContentError("short non-final record");
      }
    } else {
      throw new ContentError("invalid record delimiter");
    }

    seq++;
    if (plaintext.length > 1) {
      controller.enqueue(plaintext.subarray(0, plaintext.length - 1));
    }
  };

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      append(chunk);
      if (!keys) {
        if (pending.length < HEADER_SIZE) {
          return;
        }
        await readHeader();
      }
      while (pending.length >= RECORD_SIZE) {
        const record = pending.subarray(0, RECORD_SIZE);
        await decryptRecord(Uint8Array.from(record), controller);
        pending = pending.slice(RECORD_SIZE);
      }
    },
    async flush(controller) {
      if (!keys) {
        // Fewer than HEADER_SIZE bytes ever arrived.
        throw new ContentError("stream ended before the header");
      }
      if (pending.length > 0) {
        await decryptRecord(pending, controller);
        pending = new Uint8Array(0);
      }
      if (!sawFinal) {
        throw new ContentError("stream ended without a final record");
      }
    },
  });
}

/**
 * Drives a whole buffer through a transform and collects the output.
 *
 * When a transform errors, **both** sides of the stream reject. Each is
 * captured rather than awaited directly, so that propagating one does not leave
 * the other as an unhandled rejection. The readable side's error is preferred,
 * because it carries the cause; the writable side merely reports that the
 * stream was torn down.
 */
async function pump(
  input: Uint8Array,
  transform: TransformStream<Uint8Array, Uint8Array>,
): Promise<Uint8Array> {
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();

  const writing: Promise<unknown> = (async () => {
    if (input.length > 0) {
      await writer.write(input);
    }
    await writer.close();
  })().then(
    () => undefined,
    (error: unknown) => error ?? new Error("crypto: stream write failed"),
  );

  type ReadResult = { ok: true; value: Uint8Array } | { ok: false; error: unknown };
  const reading: Promise<ReadResult> = (async () => {
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      chunks.push(value);
    }
    const total = chunks.reduce((sum, c) => sum + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  })().then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );

  const [writeError, readResult] = await Promise.all([writing, reading]);
  if (!readResult.ok) {
    throw readResult.error;
  }
  if (writeError !== undefined) {
    throw writeError;
  }
  return readResult.value;
}

/**
 * Encrypts a whole buffer. Convenient for small payloads and tests; use
 * {@link encryptStream} for anything that should not be held in memory.
 */
export function encryptBytes(
  fileKey: Uint8Array,
  plaintext: Uint8Array,
  contentSalt?: Uint8Array,
): Promise<Uint8Array> {
  return pump(plaintext, encryptStream(fileKey, contentSalt ?? randomBytes(CONTENT_SALT_SIZE)));
}

/** Decrypts a whole buffer produced by {@link encryptBytes}. */
export function decryptBytes(fileKey: Uint8Array, stream: Uint8Array): Promise<Uint8Array> {
  return pump(stream, decryptStream(fileKey));
}
