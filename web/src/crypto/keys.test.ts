// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { KeyMaterialError } from "./errors.js";
import {
  authTokenHash,
  deriveKeys,
  deriveKeysWithPassword,
  FILE_ID_SIZE,
  LINK_SECRET_SIZE,
  newLinkSecret,
  newOwnerToken,
  ownerTokenHash,
} from "./keys.js";
import { newPasswordParams, PASSWORD_SALT_SIZE, type PasswordParams } from "./password.js";

const fixedFileID = () => new Uint8Array(FILE_ID_SIZE).fill(0x01);
const fixedLinkSecret = () => new Uint8Array(LINK_SECRET_SIZE).fill(0x02);

/** Deliberately weak so tests stay fast. Never use these for real. */
const fixedParams = (): PasswordParams => ({
  salt: new Uint8Array(PASSWORD_SALT_SIZE).fill(0x03),
  memoryKiB: 64,
  iterations: 1,
  parallelism: 1,
});

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("key schedule", () => {
  it("is deterministic", async () => {
    const a = await deriveKeys(fixedFileID(), fixedLinkSecret());
    const b = await deriveKeys(fixedFileID(), fixedLinkSecret());
    expect(hex(a.wrapping)).toBe(hex(b.wrapping));
    expect(hex(a.metadata)).toBe(hex(b.metadata));
    expect(hex(a.authToken)).toBe(hex(b.authToken));
  });

  // If a label were duplicated or dropped, two keys would collide and
  // compromising one would compromise another.
  it("derives three distinct 32-byte keys", async () => {
    const k = await deriveKeys(fixedFileID(), fixedLinkSecret());
    expect(new Set([hex(k.wrapping), hex(k.metadata), hex(k.authToken)]).size).toBe(3);
    for (const key of [k.wrapping, k.metadata, k.authToken]) {
      expect(key.length).toBe(32);
    }
  });

  it("varies with the file id and the link secret", async () => {
    const base = await deriveKeys(fixedFileID(), fixedLinkSecret());

    const otherID = fixedFileID();
    otherID[0] = (otherID[0] ?? 0) ^ 0xff;
    expect(hex((await deriveKeys(otherID, fixedLinkSecret())).wrapping)).not.toBe(
      hex(base.wrapping),
    );

    const otherSecret = fixedLinkSecret();
    otherSecret[0] = (otherSecret[0] ?? 0) ^ 0xff;
    expect(hex((await deriveKeys(fixedFileID(), otherSecret)).wrapping)).not.toBe(
      hex(base.wrapping),
    );
  });

  it("rejects malformed inputs", async () => {
    const cases: Array<[string, Uint8Array, Uint8Array]> = [
      ["short file id", new Uint8Array(FILE_ID_SIZE - 1), fixedLinkSecret()],
      ["long file id", new Uint8Array(FILE_ID_SIZE + 1), fixedLinkSecret()],
      ["short link secret", fixedFileID(), new Uint8Array(LINK_SECRET_SIZE - 1)],
      ["16 byte link secret", fixedFileID(), new Uint8Array(16)],
    ];
    for (const [name, fileID, linkSecret] of cases) {
      await expect(deriveKeys(fileID, linkSecret), name).rejects.toBeInstanceOf(KeyMaterialError);
    }
  });
});

describe("password contribution", () => {
  // A password must change the wrapping key itself. If it did not, it would be
  // server-enforced policy rather than a cryptographic property, which is the
  // weakness this scheme exists to avoid.
  it("changes the wrapping and metadata keys", async () => {
    const without = await deriveKeys(fixedFileID(), fixedLinkSecret());
    const with_ = await deriveKeysWithPassword(
      fixedFileID(),
      fixedLinkSecret(),
      "correct horse",
      fixedParams(),
    );
    expect(hex(with_.wrapping)).not.toBe(hex(without.wrapping));
    // Without this, filenames would leak from a password-protected upload.
    expect(hex(with_.metadata)).not.toBe(hex(without.metadata));
  });

  it("distinguishes different passwords", async () => {
    const a = await deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "a", fixedParams());
    const b = await deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "b", fixedParams());
    expect(hex(a.wrapping)).not.toBe(hex(b.wrapping));
  });

  // An empty password denotes a meaningless state: an upload marked
  // password-protected that any link holder can open. Both implementations
  // reject it, so the state cannot arise at all.
  it("rejects an empty password", async () => {
    await expect(
      deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "", fixedParams()),
    ).rejects.toBeInstanceOf(KeyMaterialError);
  });

  it("rejects bad parameters", async () => {
    const mutations: Array<[string, (p: PasswordParams) => void]> = [
      ["short salt", (p) => (p.salt = new Uint8Array(PASSWORD_SALT_SIZE - 1))],
      ["zero memory", (p) => (p.memoryKiB = 0)],
      ["zero iterations", (p) => (p.iterations = 0)],
      ["zero parallelism", (p) => (p.parallelism = 0)],
    ];
    for (const [name, mutate] of mutations) {
      const p = fixedParams();
      mutate(p);
      await expect(
        deriveKeysWithPassword(fixedFileID(), fixedLinkSecret(), "pw", p),
        name,
      ).rejects.toBeInstanceOf(KeyMaterialError);
    }
  });
});

describe("random values and hashes", () => {
  it("produces the specified sizes and does not repeat", () => {
    expect(newLinkSecret().length).toBe(LINK_SECRET_SIZE);
    expect(hex(newLinkSecret())).not.toBe(hex(newLinkSecret()));
    expect(hex(newOwnerToken())).not.toBe(hex(newOwnerToken()));
  });

  it("uses the spec default Argon2id parameters", () => {
    const p = newPasswordParams();
    expect(p.salt.length).toBe(PASSWORD_SALT_SIZE);
    expect(p.memoryKiB).toBe(65536);
    expect(p.iterations).toBe(3);
    expect(p.parallelism).toBe(1);
    expect(hex(p.salt)).not.toBe(hex(newPasswordParams().salt));
  });

  it("hashes tokens stably to 32 bytes", async () => {
    const token = new Uint8Array(32).fill(0x07);
    expect(hex(await authTokenHash(token))).toBe(hex(await authTokenHash(token)));
    expect((await authTokenHash(token)).length).toBe(32);
    expect((await ownerTokenHash(token)).length).toBe(32);
  });
});
