// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Exporting and importing the list of uploads this browser made.
 *
 * The list lives in one browser and cannot be recovered when that browser is
 * gone. An export is the only thing that changes: losing access becomes a
 * choice somebody made rather than an accident of clearing site data.
 *
 * What it contains is what the list contains - the whole link, secret included,
 * and the owner token for every upload. Anybody who can read the plaintext can
 * open and delete every file in it, which is why the file is never written
 * unencrypted and why the passphrase is stretched with the same Argon2id
 * parameters the rest of this project uses. A weaker derivation here would make
 * the export the easiest way in, and the export is the copy that ends up in
 * cloud storage and on memory sticks.
 *
 * ## The file
 *
 * ```
 * magic    8   "SENDANBK"
 * version  1   1
 * salt    16   Argon2id salt
 * memory   4   Argon2id memory, KiB, big-endian
 * passes   4   Argon2id iterations, big-endian
 * lanes    1   Argon2id parallelism
 * nonce   12   AES-256-GCM nonce
 * body     …   AES-256-GCM(JSON of the records), tag included
 * ```
 *
 * The parameters travel with the file because whoever imports it has to derive
 * the same key, and cannot be told them any other way. They disclose only that
 * a passphrase was used, which the magic bytes already say.
 *
 * The header is authenticated: its base64url encoding is passed to AES-GCM as
 * additional data, so altering the parameters to something cheap invalidates
 * the tag rather than quietly weakening the derivation for whoever imports it
 * next. Base64url because the project's AES-GCM helpers take their additional
 * data as a string, and encoding the bytes is better than adding a second way
 * to call them.
 */

import {
  aesGcmOpen,
  aesGcmSeal,
  DEFAULT_ITERATIONS,
  DEFAULT_MEMORY_KIB,
  DEFAULT_PARALLELISM,
  hashPassword,
  importAesKey,
  KeyMaterialError,
  PASSWORD_SALT_SIZE,
  type PasswordParams,
  randomBytes,
} from "../crypto/index.js";
import { toBase64Url } from "./link.js";
import type { StoredUpload } from "./vault.js";

const MAGIC = new TextEncoder().encode("SENDANBK");
const VERSION = 1;
const NONCE_SIZE = 12;
const HEADER_SIZE = MAGIC.length + 1 + PASSWORD_SALT_SIZE + 4 + 4 + 1 + NONCE_SIZE;

/** Why an import did not happen. */
export type BackupFault =
  /** Not a file this understands at all. */
  | "not-a-backup"
  /** A version this build does not read. */
  | "unsupported-version"
  /** The passphrase is wrong, or the file has been altered. */
  | "wrong-passphrase"
  /** It decrypted, but what came out is not a list. */
  | "damaged";

export class BackupError extends Error {
  readonly fault: BackupFault;

  constructor(fault: BackupFault, message: string) {
    super(message);
    this.name = "BackupError";
    this.fault = fault;
  }
}

/** Turns the list into an encrypted file. */
export async function exportUploads(
  uploads: StoredUpload[],
  passphrase: string,
): Promise<Uint8Array> {
  if (passphrase.length === 0) {
    // The same rule the rest of the project applies: an empty passphrase would
    // produce a file that claims to be protected and is not.
    throw new KeyMaterialError("passphrase must not be empty");
  }

  const params: PasswordParams = {
    salt: randomBytes(PASSWORD_SALT_SIZE),
    memoryKiB: DEFAULT_MEMORY_KIB,
    iterations: DEFAULT_ITERATIONS,
    parallelism: DEFAULT_PARALLELISM,
  };
  const nonce = randomBytes(NONCE_SIZE);
  const header = buildHeader(params, nonce);

  const key = await importAesKey(await hashPassword(passphrase, params));
  const body = await aesGcmSeal(
    key,
    nonce,
    new TextEncoder().encode(JSON.stringify(uploads)),
    toBase64Url(header),
  );

  const file = new Uint8Array(header.length + body.length);
  file.set(header, 0);
  file.set(body, header.length);
  return file;
}

/** Reads an encrypted file back into a list. */
export async function importUploads(file: Uint8Array, passphrase: string): Promise<StoredUpload[]> {
  if (file.length <= HEADER_SIZE) {
    throw new BackupError("not-a-backup", "This is not a Sendan export.");
  }

  const header = file.subarray(0, HEADER_SIZE);
  const { params, nonce } = readHeader(header);

  const key = await importAesKey(await hashPassword(passphrase, params));

  let plaintext: Uint8Array;
  try {
    plaintext = await aesGcmOpen(key, nonce, file.subarray(HEADER_SIZE), toBase64Url(header));
  } catch {
    // One answer for a wrong passphrase and for a file somebody altered. The
    // tag cannot tell them apart, and neither can anybody else.
    throw new BackupError(
      "wrong-passphrase",
      "That passphrase does not open this file, or the file has been altered.",
    );
  }

  return parseRecords(plaintext);
}

function buildHeader(params: PasswordParams, nonce: Uint8Array): Uint8Array {
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  let at = 0;

  header.set(MAGIC, at);
  at += MAGIC.length;
  view.setUint8(at++, VERSION);
  header.set(params.salt, at);
  at += PASSWORD_SALT_SIZE;
  view.setUint32(at, params.memoryKiB);
  at += 4;
  view.setUint32(at, params.iterations);
  at += 4;
  view.setUint8(at++, params.parallelism);
  header.set(nonce, at);

  return header;
}

function readHeader(header: Uint8Array): { params: PasswordParams; nonce: Uint8Array } {
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  for (let i = 0; i < MAGIC.length; i++) {
    if (view.getUint8(i) !== MAGIC[i]) {
      throw new BackupError("not-a-backup", "This is not a Sendan export.");
    }
  }

  const version = view.getUint8(MAGIC.length);
  if (version !== VERSION) {
    throw new BackupError(
      "unsupported-version",
      `This export is version ${version} and this client reads version ${VERSION}.`,
    );
  }

  let at = MAGIC.length + 1;

  const salt = header.slice(at, at + PASSWORD_SALT_SIZE);
  at += PASSWORD_SALT_SIZE;
  const memoryKiB = view.getUint32(at);
  at += 4;
  const iterations = view.getUint32(at);
  at += 4;
  const parallelism = view.getUint8(at);
  at += 1;
  const nonce = header.slice(at, at + NONCE_SIZE);

  // Parameters are checked before they are used, not after: a file asking for
  // a gigabyte of memory would otherwise be a way to hang whoever opens it,
  // and one asking for zero would be a way to weaken the derivation.
  if (memoryKiB <= 0 || iterations <= 0 || parallelism <= 0) {
    throw new BackupError("damaged", "This export names impossible parameters.");
  }
  if (memoryKiB > 1024 * 1024) {
    throw new BackupError(
      "damaged",
      "This export asks for more memory than any export this client writes.",
    );
  }

  return { params: { salt, memoryKiB, iterations, parallelism }, nonce };
}

/**
 * Reads the decrypted body.
 *
 * Checked field by field. The plaintext is authenticated, so this is not about
 * an attacker - it is about an export written by a different version, or by
 * something else entirely, becoming a list of half-formed records that fail
 * much later when somebody tries to use one.
 */
function parseRecords(plaintext: Uint8Array): StoredUpload[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new BackupError("damaged", "This export decrypted but is not readable.");
  }
  if (!Array.isArray(parsed)) {
    throw new BackupError("damaged", "This export does not contain a list.");
  }

  const records: StoredUpload[] = [];
  for (const value of parsed) {
    if (typeof value !== "object" || value === null) continue;
    const v = value as Record<string, unknown>;

    if (
      typeof v.id !== "string" ||
      typeof v.link !== "string" ||
      typeof v.ownerToken !== "string" ||
      typeof v.name !== "string" ||
      typeof v.size !== "number" ||
      typeof v.createdAt !== "number"
    ) {
      continue;
    }
    const expiresAt =
      v.expiresAt === null || v.expiresAt === undefined
        ? null
        : typeof v.expiresAt === "number"
          ? v.expiresAt
          : null;

    records.push({
      id: v.id,
      link: v.link,
      ownerToken: v.ownerToken,
      name: v.name,
      size: v.size,
      createdAt: v.createdAt,
      expiresAt,
    });
  }
  return records;
}

/** What to show somebody when an import fails. */
export function explainBackup(fault: BackupFault): string {
  switch (fault) {
    case "not-a-backup":
      return "That file is not a Sendan export.";
    case "unsupported-version":
      return "That export was written by a newer version of this client.";
    case "wrong-passphrase":
      return "That passphrase does not open the file, or the file has been altered.";
    case "damaged":
      return "That export opened but its contents are not a usable list.";
  }
}
