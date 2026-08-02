// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { KeyMaterialError, UnwrapError } from "./errors.js";
import { DERIVED_KEY_SIZE, FILE_KEY_SIZE, NONCE_SIZE, randomBytes } from "./keys.js";

/**
 * Additional authenticated data, per spec §6 and §7. These bind a ciphertext to
 * its purpose, so an envelope cannot be substituted for a wrapped key.
 */
export const AAD_WRAP = "sendan/v1/wrap";
export const AAD_METADATA = "sendan/v1/meta";

const encoder = new TextEncoder();

export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== DERIVED_KEY_SIZE) {
    throw new KeyMaterialError(`key is ${raw.length} bytes, want ${DERIVED_KEY_SIZE}`);
  }
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function aesGcmSeal(
  key: CryptoKey,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const out = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce as BufferSource,
      additionalData: encoder.encode(aad) as BufferSource,
      tagLength: 128,
    },
    key,
    plaintext as BufferSource,
  );
  return new Uint8Array(out);
}

export async function aesGcmOpen(
  key: CryptoKey,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const out = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce as BufferSource,
      additionalData: encoder.encode(aad) as BufferSource,
      tagLength: 128,
    },
    key,
    ciphertext as BufferSource,
  );
  return new Uint8Array(out);
}

export interface WrappedFileKey {
  nonce: Uint8Array;
  wrapped: Uint8Array;
}

/**
 * Encrypts a file key under the wrapping key (spec §6).
 *
 * The nonce is random. Changing a password re-derives the wrapping key and
 * re-wraps the same file key with a fresh nonce, which touches 48 bytes rather
 * than re-encrypting the content.
 */
export async function wrapFileKey(
  wrappingKey: Uint8Array,
  fileKey: Uint8Array,
): Promise<WrappedFileKey> {
  if (fileKey.length !== FILE_KEY_SIZE) {
    throw new KeyMaterialError(`file key is ${fileKey.length} bytes, want ${FILE_KEY_SIZE}`);
  }
  const key = await importAesKey(wrappingKey);
  const nonce = randomBytes(NONCE_SIZE);
  return { nonce, wrapped: await aesGcmSeal(key, nonce, fileKey, AAD_WRAP) };
}

/**
 * Recovers a file key wrapped by {@link wrapFileKey}.
 *
 * A wrong wrapping key and a corrupt container both throw {@link UnwrapError}
 * and are not distinguishable by the caller, per spec §13 invariant 5. Do not
 * add detail to the thrown error.
 */
export async function unwrapFileKey(
  wrappingKey: Uint8Array,
  nonce: Uint8Array,
  wrapped: Uint8Array,
): Promise<Uint8Array> {
  const key = await importAesKey(wrappingKey);
  if (nonce.length !== NONCE_SIZE) {
    throw new UnwrapError();
  }
  let fileKey: Uint8Array;
  try {
    fileKey = await aesGcmOpen(key, nonce, wrapped, AAD_WRAP);
  } catch {
    throw new UnwrapError();
  }
  if (fileKey.length !== FILE_KEY_SIZE) {
    throw new UnwrapError();
  }
  return fileKey;
}
