// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { argon2id } from "hash-wasm";
import { KeyMaterialError } from "./errors.js";
import { randomBytes } from "./keys.js";

/** Length of an Argon2id salt, per spec §3. */
export const PASSWORD_SALT_SIZE = 16;

/**
 * Default Argon2id parameters, per spec §4.
 *
 * Chosen to stay tolerable on a low-end phone, since the browser performs this
 * work. They are stored per upload so they can be raised later without
 * invalidating existing links.
 */
export const DEFAULT_MEMORY_KIB = 64 * 1024;
export const DEFAULT_ITERATIONS = 3;
export const DEFAULT_PARALLELISM = 1;

const HASH_LENGTH = 32;

/**
 * Argon2id parameters for one upload.
 *
 * Stored unencrypted alongside the upload, because a client must know them
 * before it can derive anything. They disclose only that a password exists.
 */
export interface PasswordParams {
  salt: Uint8Array;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/** The default parameters with a fresh random salt. */
export function newPasswordParams(): PasswordParams {
  return {
    salt: randomBytes(PASSWORD_SALT_SIZE),
    memoryKiB: DEFAULT_MEMORY_KIB,
    iterations: DEFAULT_ITERATIONS,
    parallelism: DEFAULT_PARALLELISM,
  };
}

function validate(password: string, p: PasswordParams): void {
  // An empty password is rejected by both implementations, per spec §4. It is a
  // meaningless state - an upload marked password-protected that any link
  // holder can open - and hash-wasm refuses it outright, so accepting it in Go
  // would make the two implementations disagree.
  if (password.length === 0) {
    throw new KeyMaterialError("password must not be empty");
  }
  if (p.salt.length !== PASSWORD_SALT_SIZE) {
    throw new KeyMaterialError(
      `password salt is ${p.salt.length} bytes, want ${PASSWORD_SALT_SIZE}`,
    );
  }
  if (p.memoryKiB <= 0 || p.iterations <= 0 || p.parallelism <= 0) {
    throw new KeyMaterialError("argon2id parameters must all be non-zero");
  }
}

/**
 * Stretches a password with Argon2id.
 *
 * WebCrypto offers no Argon2, so this uses hash-wasm. The password is taken as
 * its UTF-8 encoding with no normalisation, matching spec §4 and the Go
 * implementation: normalising would silently change which passwords open which
 * files, and would do so differently in each implementation.
 */
export async function hashPassword(password: string, p: PasswordParams): Promise<Uint8Array> {
  validate(password, p);
  // Encode explicitly rather than passing a string, so the bytes fed to Argon2id
  // are ours and not whatever hash-wasm chooses internally.
  return argon2id({
    password: new TextEncoder().encode(password),
    salt: p.salt,
    parallelism: p.parallelism,
    iterations: p.iterations,
    memorySize: p.memoryKiB,
    hashLength: HASH_LENGTH,
    outputType: "binary",
  });
}
