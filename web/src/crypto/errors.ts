// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/** Malformed input to the key schedule. Mirrors Go's ErrKeyMaterial. */
export class KeyMaterialError extends Error {
  constructor(message: string) {
    super(`crypto: ${message}`);
    this.name = "KeyMaterialError";
  }
}

/**
 * A wrapped file key could not be recovered.
 *
 * This carries no detail on purpose. A wrong password and a corrupt container
 * must be indistinguishable (spec §13 invariant 5): reporting which occurred
 * would let an attacker holding only the ciphertext confirm a guessed password
 * offline. Do not add context to this error.
 */
export class UnwrapError extends Error {
  constructor() {
    super("crypto: cannot unwrap file key");
    this.name = "UnwrapError";
  }
}

/** A malformed or unopenable metadata envelope. Mirrors Go's ErrMetadata. */
export class MetadataError extends Error {
  constructor(message: string) {
    super(`crypto: ${message}`);
    this.name = "MetadataError";
  }
}

/** A malformed, truncated, or tampered content stream. Mirrors Go's ErrContent. */
export class ContentError extends Error {
  constructor(message: string) {
    super(`crypto: ${message}`);
    this.name = "ContentError";
  }
}
