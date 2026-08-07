// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { KeyMaterialError } from "./errors.js";
import { hashPassword, type PasswordParams } from "./password.js";

/** Sizes in bytes, per spec §3. */
export const FILE_ID_SIZE = 16;
export const LINK_SECRET_SIZE = 32;
export const FILE_KEY_SIZE = 32;
export const OWNER_TOKEN_SIZE = 32;
export const NONCE_SIZE = 12;

export const DERIVED_KEY_SIZE = 32;

/**
 * Domain-separation labels, per spec §4.
 *
 * These are the version of the scheme. Changing what any of them means requires
 * a v2 label, never an edit here, and must be changed in the Go implementation
 * in the same pull request.
 */
const LABEL_WRAPPING = "sendan/v1/kek";
const LABEL_METADATA = "sendan/v1/metadata";
const LABEL_AUTH = "sendan/v1/auth";

/** The three keys derived from one upload's key material. */
export interface Keys {
  /** Encrypts the file key (spec §6). Never leaves the client. */
  wrapping: Uint8Array;
  /** Encrypts the metadata envelope (spec §7). Never leaves the client. */
  metadata: Uint8Array;
  /**
   * Presented to the server to authenticate a download (spec §8.1). Unlike the
   * other two this is transmitted, in exchange for the server storing only its
   * SHA-256 hash.
   */
  authToken: Uint8Array;
}

const encoder = new TextEncoder();

/**
 * HKDF-SHA-256 as a single extract-and-expand.
 *
 * WebCrypto performs both steps in one call. Since extraction is deterministic,
 * three calls sharing a salt and input keying material produce exactly what the
 * Go implementation's extract-once-expand-thrice arrangement produces.
 */
async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  lengthBytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: encoder.encode(info) as BufferSource,
    },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

/** Derives the key schedule for an upload with no password. */
export async function deriveKeys(fileID: Uint8Array, linkSecret: Uint8Array): Promise<Keys> {
  return deriveKeysInternal(fileID, linkSecret, new Uint8Array(0));
}

/**
 * Derives the key schedule for a password-protected upload.
 *
 * The password is stretched with Argon2id and concatenated with the link secret
 * before extraction, so it contributes to the wrapping key itself. A link
 * without its password therefore decrypts nothing, which is a cryptographic
 * property rather than a server-side policy.
 */
export async function deriveKeysWithPassword(
  fileID: Uint8Array,
  linkSecret: Uint8Array,
  password: string,
  params: PasswordParams,
): Promise<Keys> {
  const passwordHash = await hashPassword(password, params);
  return deriveKeysInternal(fileID, linkSecret, passwordHash);
}

async function deriveKeysInternal(
  fileID: Uint8Array,
  linkSecret: Uint8Array,
  passwordHash: Uint8Array,
): Promise<Keys> {
  if (fileID.length !== FILE_ID_SIZE) {
    throw new KeyMaterialError(`file id is ${fileID.length} bytes, want ${FILE_ID_SIZE}`);
  }
  if (linkSecret.length !== LINK_SECRET_SIZE) {
    throw new KeyMaterialError(
      `link secret is ${linkSecret.length} bytes, want ${LINK_SECRET_SIZE}`,
    );
  }

  // IKM = LS || pwHash, with pwHash empty when no password is set (spec §4).
  const ikm = new Uint8Array(linkSecret.length + passwordHash.length);
  ikm.set(linkSecret, 0);
  ikm.set(passwordHash, linkSecret.length);

  const [wrapping, metadata, authToken] = await Promise.all([
    hkdf(ikm, fileID, LABEL_WRAPPING, DERIVED_KEY_SIZE),
    hkdf(ikm, fileID, LABEL_METADATA, DERIVED_KEY_SIZE),
    hkdf(ikm, fileID, LABEL_AUTH, DERIVED_KEY_SIZE),
  ]);
  return { wrapping, metadata, authToken };
}

/** The value a server stores in order to verify a download token (spec §8.1). */
export async function authTokenHash(authToken: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", authToken as BufferSource));
}

/** The value a server stores in order to verify an owner token (spec §8.2). */
export async function ownerTokenHash(ownerToken: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", ownerToken as BufferSource));
}

export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * A random file identifier.
 *
 * The client generates it, and must do so before anything else: it is the salt
 * of the key schedule, so every key an upload has derives from it and none can
 * exist until it does. See spec §3.
 */
export function newFileID(): Uint8Array {
  return randomBytes(FILE_ID_SIZE);
}

/**
 * A random link secret.
 *
 * 32 bytes rather than 16 because it is the sole credential protecting an
 * upload, and Grover's algorithm halves effective symmetric security. See
 * docs/design.md §2.4.
 */
export function newLinkSecret(): Uint8Array {
  return randomBytes(LINK_SECRET_SIZE);
}

export function newFileKey(): Uint8Array {
  return randomBytes(FILE_KEY_SIZE);
}

/**
 * A random owner token.
 *
 * Independent of the link secret, so an upload can be revoked by someone who
 * cannot read it.
 */
export function newOwnerToken(): Uint8Array {
  return randomBytes(OWNER_TOKEN_SIZE);
}
