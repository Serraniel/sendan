// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  aesGcmOpen,
  DEFAULT_ITERATIONS,
  DEFAULT_MEMORY_KIB,
  DEFAULT_PARALLELISM,
  hashPassword,
  importAesKey,
} from "../crypto/index.js";
import { BackupError, explainBackup, exportUploads, importUploads } from "./backup";
import { toBase64Url } from "./link.js";
import type { StoredUpload } from "./vault";

/** Where each header field starts. Spelled out so a change to the layout has
 *  to be made here too, rather than silently going untested. */
const AT_SALT = 8 + 1;
const AT_MEMORY = AT_SALT + 16;
const AT_ITERATIONS = AT_MEMORY + 4;
const AT_PARALLELISM = AT_ITERATIONS + 4;
const AT_NONCE = AT_PARALLELISM + 1;
const HEADER_SIZE = AT_NONCE + 12;

const passphrase = "correct horse battery staple";

const records: StoredUpload[] = [
  {
    id: "aaaaaaaaaaaaaaaaaaaaaa",
    link: "https://files.example.org/d/aaaaaaaaaaaaaaaaaaaaaa#thesecret",
    ownerToken: "b3duZXItdG9rZW4",
    name: "report.pdf",
    size: 1024,
    createdAt: 1_700_000_000_000,
    expiresAt: 1_700_086_400_000,
  },
  {
    id: "bbbbbbbbbbbbbbbbbbbbbb",
    link: "https://files.example.org/d/bbbbbbbbbbbbbbbbbbbbbb#another",
    ownerToken: "YW5vdGhlci10b2tlbg",
    name: "notes.txt",
    size: 12,
    createdAt: 1_700_000_001_000,
    expiresAt: null,
  },
];

async function faultOf(work: Promise<unknown>): Promise<string> {
  try {
    await work;
    return "no error";
  } catch (error) {
    // Distinguishing these matters: a test that treated an unexpected throw as
    // the expected fault would pass while proving nothing.
    return error instanceof BackupError ? error.fault : `other: ${String(error)}`;
  }
}

describe("exporting and importing the list", () => {
  it("round-trips every record", async () => {
    const file = await exportUploads(records, passphrase);
    expect(await importUploads(file, passphrase)).toEqual(records);
  });

  // The whole point of the file: it is the copy that leaves this machine.
  it("writes nothing readable to somebody without the passphrase", async () => {
    const file = await exportUploads(records, passphrase);
    const text = new TextDecoder().decode(file);

    expect(text).not.toContain("thesecret");
    expect(text).not.toContain("report.pdf");
    expect(text).not.toContain("b3duZXItdG9rZW4");
  });

  it("refuses a wrong passphrase", async () => {
    const file = await exportUploads(records, passphrase);
    expect(await faultOf(importUploads(file, "not the passphrase"))).toBe("wrong-passphrase");
  });

  it("refuses an empty passphrase rather than writing an unprotected file", async () => {
    expect(await faultOf(exportUploads(records, ""))).toMatch(/^other:/);
  });

  // The header carries the derivation parameters, so it has to be authenticated:
  // otherwise somebody could rewrite them to something cheap and hand the file
  // back, and the next import would derive with what they chose.
  // The requirement this feature exists to meet. Every other test here passes
  // just as well against an export written at a tenth of the cost, because the
  // parameters travel with the file and a round trip only proves they are
  // self-consistent. This is the one that reads what was actually written.
  it("stretches the passphrase with the project's parameters, not cheaper ones", async () => {
    const file = await exportUploads(records, passphrase);
    const view = new DataView(file.buffer, file.byteOffset, file.byteLength);

    expect(view.getUint32(AT_MEMORY)).toBe(DEFAULT_MEMORY_KIB);
    expect(view.getUint32(AT_ITERATIONS)).toBe(DEFAULT_ITERATIONS);
    expect(view.getUint8(AT_PARALLELISM)).toBe(DEFAULT_PARALLELISM);
  });

  // Every header field except the magic and the version feeds either the key
  // derivation or the cipher, so altering one already breaks decryption on its
  // own. That makes the additional-data binding invisible to a round trip: it
  // has to be read at the level it happens on, or it can be dropped and no
  // test here would notice.
  it("binds the body to the header it was written with", async () => {
    const file = await exportUploads(records, passphrase);
    const header = file.subarray(0, HEADER_SIZE);
    const view = new DataView(file.buffer, file.byteOffset, file.byteLength);

    const key = await importAesKey(
      await hashPassword(passphrase, {
        salt: file.slice(AT_SALT, AT_SALT + 16),
        memoryKiB: view.getUint32(AT_MEMORY),
        iterations: view.getUint32(AT_ITERATIONS),
        parallelism: view.getUint8(AT_PARALLELISM),
      }),
    );
    const nonce = file.slice(AT_NONCE, HEADER_SIZE);
    const body = file.subarray(HEADER_SIZE);

    await expect(aesGcmOpen(key, nonce, body, toBase64Url(header))).resolves.toBeDefined();
    await expect(aesGcmOpen(key, nonce, body, "")).rejects.toThrow();
  });

  it("refuses a file whose parameters were rewritten", async () => {
    const file = await exportUploads(records, passphrase);

    const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
    view.setUint32(AT_MEMORY, 8);

    expect(await faultOf(importUploads(file, passphrase))).toBe("wrong-passphrase");
  });

  it("refuses a file whose body was altered", async () => {
    const file = await exportUploads(records, passphrase);
    const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
    const last = file.length - 1;
    view.setUint8(last, view.getUint8(last) ^ 0x01);
    expect(await faultOf(importUploads(file, passphrase))).toBe("wrong-passphrase");
  });

  it("refuses something that is not an export at all", async () => {
    const notOurs = new Uint8Array(200).fill(0x41);
    expect(await faultOf(importUploads(notOurs, passphrase))).toBe("not-a-backup");
  });

  it("refuses a truncated file", async () => {
    const file = await exportUploads(records, passphrase);
    expect(await faultOf(importUploads(file.subarray(0, 20), passphrase))).toBe("not-a-backup");
  });

  it("refuses a version it does not read", async () => {
    const file = await exportUploads(records, passphrase);
    file[8] = 99;
    expect(await faultOf(importUploads(file, passphrase))).toBe("unsupported-version");
  });

  // A file asking for a gigabyte of memory would otherwise be a way to hang
  // whoever opens it, before any authentication has happened.
  it("refuses parameters no export of ours would write", async () => {
    const file = await exportUploads(records, passphrase);
    const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
    view.setUint32(8 + 1 + 16, 4 * 1024 * 1024);

    expect(await faultOf(importUploads(file, passphrase))).toBe("damaged");
  });

  it("exports an empty list without complaint", async () => {
    const file = await exportUploads([], passphrase);
    expect(await importUploads(file, passphrase)).toEqual([]);
  });

  it("explains every fault it can report", () => {
    for (const fault of [
      "not-a-backup",
      "unsupported-version",
      "wrong-passphrase",
      "damaged",
    ] as const) {
      expect(explainBackup(fault).length).toBeGreaterThan(20);
    }
  });
});
