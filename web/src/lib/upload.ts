// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Encrypting and sending a file.
 *
 * Everything secret is generated here and nothing secret leaves: the server
 * receives ciphertext, two digests, and the parameters needed to derive again.
 * The order is fixed by the key schedule — the identifier is the salt, so it
 * comes first and everything else derives from it (spec §3, §4).
 */

import {
  authTokenHash,
  deriveKeys,
  deriveKeysWithPassword,
  encodedContentLength,
  encryptStream,
  type Keys,
  newFileID,
  newFileKey,
  newLinkSecret,
  newOwnerToken,
  newPasswordParams,
  ownerTokenHash,
  type PasswordParams,
  sealMetadata,
  wrapFileKey,
} from "../crypto/index.js";
import { createUpload, type MetadataValue, patchChunk, type Transport } from "./tus.js";

/** What the sender chose. Every field is optional; the defaults are the instance's. */
export interface UploadOptions {
  /** Contributes to the key, so the server cannot open the file without it. */
  password?: string;
  /** Requested lifetime. Zero, or absent, selects the instance default. */
  ttlSeconds?: number;
  /** Zero, or absent, means no limit. */
  maxDownloads?: number;
}

/**
 * Where an upload has got to.
 *
 * `deriving` covers key derivation, which is not instant when a password is
 * set: Argon2id at the default parameters is a visible pause, and a progress
 * bar that sits at zero through it looks like a hang.
 *
 * Encryption has no stage of its own because it does not happen in one. Records
 * are encrypted as they are sent, so `sent` already accounts for the work, and
 * a large file advances from the first chunk rather than after a silent wait.
 */
export type UploadStage = "deriving" | "sending" | "done";

export interface UploadProgress {
  stage: UploadStage;
  /** Encoded bytes the server has acknowledged. */
  sent: number;
  /** Encoded bytes in total. Known before the first byte is sent. */
  total: number;
}

/**
 * The secrets an upload produced.
 *
 * These exist only here. The link secret opens the file and the owner token
 * revokes it; the server holds neither, and cannot reissue either.
 */
export interface UploadResult {
  fileID: Uint8Array;
  linkSecret: Uint8Array;
  ownerToken: Uint8Array;
  /**
   * The password parameters this upload was created with, or null if none.
   *
   * Returned because only this function knows them: they are generated here,
   * and asking for them again would produce a different salt. An interface
   * reporting what protected the file has to have the values that were used.
   */
  passwordParams: PasswordParams | null;
}

export interface UploadRequest {
  file: File;
  options?: UploadOptions;
  transport?: Transport;
  onProgress?: (progress: UploadProgress) => void;
  /**
   * Bytes per PATCH. Smaller means finer progress and cheaper resumption after
   * an interruption; larger means fewer round trips.
   */
  chunkSize?: number;
  /**
   * Where uploads are created. Relative by default, which is what a page served
   * by the instance wants; an absolute URL lets this run outside a browser,
   * where there is no document to resolve against.
   */
  endpoint?: string;
}

/** Four mebibytes: a few seconds on a slow connection, which is the useful unit of progress. */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

/**
 * Encrypts a file and sends it, resolving to the secrets needed to share it.
 *
 * The plaintext is never held whole. It is read as a stream, encrypted record
 * by record, and accumulated only up to one chunk, so the memory used does not
 * depend on the size of the file.
 */
export async function uploadFile(req: UploadRequest): Promise<UploadResult> {
  const { file, options = {}, transport = {}, onProgress } = req;
  const chunkSize = req.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new TypeError(`upload: chunk size ${chunkSize} is not a byte count`);
  }

  const total = encodedContentLength(file.size);
  const report = (stage: UploadStage, sent: number) => onProgress?.({ stage, sent, total });
  report("deriving", 0);

  // The identifier first: it is the salt, so nothing below can be computed
  // before it exists. See spec §3, and do not reorder this.
  const fileID = newFileID();
  const linkSecret = newLinkSecret();
  const fileKey = newFileKey();
  const ownerToken = newOwnerToken();

  const password = options.password ?? "";
  const passwordParams = password === "" ? null : newPasswordParams();

  let keys: Keys;
  if (passwordParams === null) {
    keys = await deriveKeys(fileID, linkSecret);
  } else {
    keys = await deriveKeysWithPassword(fileID, linkSecret, password, passwordParams);
  }

  const wrapped = await wrapFileKey(keys.wrapping, fileKey);
  const sealed = await sealMetadata(keys.metadata, {
    name: file.name,
    // A browser leaves this empty for a type it does not recognise, and the
    // envelope must still say something a recipient can hand to a save dialog.
    type: file.type === "" ? "application/octet-stream" : file.type,
    size: file.size,
  });

  const metadata: Record<string, MetadataValue> = {
    fileID,
    wrappedFileKey: wrapped.wrapped,
    wrapNonce: wrapped.nonce,
    metadataEnvelope: sealed.envelope,
    metadataNonce: sealed.nonce,
    authTokenHash: await authTokenHash(keys.authToken),
    ownerTokenHash: await ownerTokenHash(ownerToken),
    ttlSeconds: options.ttlSeconds ?? 0,
    maxDownloads: options.maxDownloads ?? 0,
  };
  if (passwordParams !== null) {
    // Necessarily public: a recipient cannot derive anything without them. They
    // disclose only that a password exists, which the recipient must be told
    // anyway (spec §9).
    metadata.passwordSalt = passwordParams.salt;
    metadata.argon2MemoryKiB = passwordParams.memoryKiB;
    metadata.argon2Iterations = passwordParams.iterations;
    metadata.argon2Parallelism = passwordParams.parallelism;
  }

  const location = await createUpload(
    { length: total, metadata, ...(req.endpoint ? { endpoint: req.endpoint } : {}) },
    transport,
  );

  report("sending", 0);
  const sent = await sendEncrypted(file, fileKey, location, chunkSize, transport, (n) =>
    report("sending", n),
  );

  // The declared length is what the server enforces, so a disagreement means
  // the length calculation and the encoder have diverged. Saying so beats
  // leaving an upload that can never complete and a link that never resolves.
  if (sent !== total) {
    throw new Error(`upload: sent ${sent} bytes but declared ${total}`);
  }

  report("done", total);
  return { fileID, linkSecret, ownerToken, passwordParams };
}

/**
 * Streams the file through the encoder, sending whole chunks as they fill.
 *
 * Encryption and transmission are interleaved deliberately. Encrypting first
 * would mean holding the whole ciphertext, and would leave progress at zero for
 * as long as it took.
 */
async function sendEncrypted(
  file: File,
  fileKey: Uint8Array,
  location: string,
  chunkSize: number,
  transport: Transport,
  onSent: (sent: number) => void,
): Promise<number> {
  const encrypted = file
    .stream()
    .pipeThrough(encryptStream(fileKey), transport.signal ? { signal: transport.signal } : {});
  const reader = encrypted.getReader();

  const buffer = new Uint8Array(chunkSize);
  let held = 0;
  let offset = 0;

  const send = async (chunk: Uint8Array) => {
    offset = await patchChunk(location, offset, chunk, transport);
    onSent(offset);
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;

      let taken = 0;
      while (taken < value.length) {
        const take = Math.min(chunkSize - held, value.length - taken);
        buffer.set(value.subarray(taken, taken + take), held);
        held += take;
        taken += take;
        if (held === chunkSize) {
          await send(buffer);
          held = 0;
        }
      }
    }
    // The tail, and for a file smaller than one chunk the only send. An empty
    // stream cannot occur - the encoder always emits a header and a final
    // record - but sending nothing would be wrong rather than harmless, since
    // the server would never see the upload complete.
    if (held > 0) {
      await send(buffer.subarray(0, held));
    }
  } finally {
    // Releasing the lock lets the stream be cancelled by the caller's signal
    // rather than held open by a reader nobody owns.
    reader.releaseLock();
  }

  return offset;
}
