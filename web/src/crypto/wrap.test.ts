// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { KeyMaterialError, UnwrapError } from "./errors.js";
import {
  deriveKeys,
  deriveKeysWithPassword,
  FILE_ID_SIZE,
  FILE_KEY_SIZE,
  LINK_SECRET_SIZE,
  NONCE_SIZE,
} from "./keys.js";
import { sealMetadata } from "./metadata.js";
import { PASSWORD_SALT_SIZE, type PasswordParams } from "./password.js";
import { unwrapFileKey, wrapFileKey } from "./wrap.js";

const fixedFileID = () => new Uint8Array(FILE_ID_SIZE).fill(0x01);
const fixedLinkSecret = () => new Uint8Array(LINK_SECRET_SIZE).fill(0x02);
const fileKey = () => new Uint8Array(FILE_KEY_SIZE).fill(0x09);

const fixedParams = (): PasswordParams => ({
  salt: new Uint8Array(PASSWORD_SALT_SIZE).fill(0x03),
  memoryKiB: 64,
  iterations: 1,
  parallelism: 1,
});

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("file key wrapping", () => {
  it("round trips", async () => {
    const keys = await deriveKeys(fixedFileID(), fixedLinkSecret());
    const { nonce, wrapped } = await wrapFileKey(keys.wrapping, fileKey());
    expect(hex(wrapped)).not.toContain(hex(fileKey()));
    expect(hex(await unwrapFileKey(keys.wrapping, nonce, wrapped))).toBe(hex(fileKey()));
  });

  it("uses a fresh nonce each time", async () => {
    const keys = await deriveKeys(fixedFileID(), fixedLinkSecret());
    const a = await wrapFileKey(keys.wrapping, fileKey());
    const b = await wrapFileKey(keys.wrapping, fileKey());
    expect(hex(a.nonce)).not.toBe(hex(b.nonce));
    expect(hex(a.wrapped)).not.toBe(hex(b.wrapped));
  });

  // A wrong password and a corrupt container must be indistinguishable
  // (spec §13 invariant 5). Distinguishing them would let an attacker holding
  // only the ciphertext confirm a guessed password offline.
  it("fails indistinguishably", async () => {
    const params = fixedParams();
    const right = await deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "right", params);
    const wrong = await deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "wrong", params);
    const { nonce, wrapped } = await wrapFileKey(right.wrapping, fileKey());

    const corrupt = Uint8Array.from(wrapped);
    corrupt[0] = (corrupt[0] ?? 0) ^ 0x01;
    const badNonce = Uint8Array.from(nonce);
    badNonce[0] = (badNonce[0] ?? 0) ^ 0x01;

    const cases: Array<[string, Uint8Array, Uint8Array, Uint8Array]> = [
      ["wrong password", wrong.wrapping, nonce, wrapped],
      ["corrupt ciphertext", right.wrapping, nonce, corrupt],
      ["wrong nonce", right.wrapping, badNonce, wrapped],
      ["truncated", right.wrapping, nonce, wrapped.subarray(0, wrapped.length - 1)],
      ["empty", right.wrapping, nonce, new Uint8Array(0)],
      ["short nonce", right.wrapping, nonce.subarray(0, NONCE_SIZE - 1), wrapped],
    ];

    const messages = new Set<string>();
    for (const [name, key, n, w] of cases) {
      const err = await unwrapFileKey(key, n, w).then(
        () => null,
        (e: unknown) => e,
      );
      expect(err, name).toBeInstanceOf(UnwrapError);
      messages.add((err as Error).message);
    }
    // Every failure must carry the identical message, not merely the same type.
    expect(messages.size).toBe(1);
  });

  it("re-wraps the same file key after a password change", async () => {
    const params = fixedParams();
    const oldKeys = await deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "old", params);
    const first = await wrapFileKey(oldKeys.wrapping, fileKey());
    const recovered = await unwrapFileKey(oldKeys.wrapping, first.nonce, first.wrapped);

    const newKeys = await deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "new", params);
    const second = await wrapFileKey(newKeys.wrapping, recovered);

    expect(hex(await unwrapFileKey(newKeys.wrapping, second.nonce, second.wrapped))).toBe(
      hex(fileKey()),
    );
    await expect(
      unwrapFileKey(oldKeys.wrapping, second.nonce, second.wrapped),
    ).rejects.toBeInstanceOf(UnwrapError);
  });

  it("rejects malformed input", async () => {
    await expect(wrapFileKey(new Uint8Array(31), fileKey())).rejects.toBeInstanceOf(
      KeyMaterialError,
    );
    await expect(
      wrapFileKey(new Uint8Array(32).fill(0x0a), new Uint8Array(FILE_KEY_SIZE - 1)),
    ).rejects.toBeInstanceOf(KeyMaterialError);
  });

  // The additional authenticated data binds a ciphertext to its purpose, so a
  // metadata envelope must not open as a wrapped key even under the same key.
  it("does not interchange with a metadata envelope", async () => {
    const key = new Uint8Array(32).fill(0x0b);
    const { nonce, envelope } = await sealMetadata(key, { name: "a", type: "text/plain", size: 1 });
    await expect(unwrapFileKey(key, nonce, envelope)).rejects.toBeInstanceOf(UnwrapError);
  });
});
