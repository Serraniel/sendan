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
import {
  canStreamRequests,
  createUpload,
  type MetadataValue,
  patchChunk,
  patchStream,
  type Transport,
} from "./tus.js";

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
  /**
   * Encoded bytes sent so far.
   *
   * On the chunked path these have been acknowledged by the instance. On the
   * streamed path the response does not arrive until the body has been sent,
   * so they are bytes handed to the network - which may still be in a buffer.
   * The distinction is not worth showing a person, but it is worth not
   * pretending about.
   */
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
  /**
   * Whether to try sending the body as one stream.
   *
   * Defaults to whatever the browser supports. Set false to require the
   * chunked path - which is what a test of the fallback needs, and the reason
   * this is here at all: the fallback is the path that would otherwise rot
   * unnoticed.
   */
  stream?: boolean;
}

/**
 * The largest chunk sent when the caller names no size. Also the size a fast
 * connection settles on.
 */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

/**
 * How the chunk size finds itself when the caller names none.
 *
 * Progress is reported per chunk, because a chunk is one request and `fetch`
 * has nothing to say until it finishes. A fixed four mebibytes is a second on a
 * fast link and fifteen on a slow one - which is what was reported: a bar that
 * stood still and then jumped to 37%.
 *
 * So the size aims at a duration instead of a number of bytes. It starts small
 * enough that the first wait is short even on a bad link, and grows to
 * {@link DEFAULT_CHUNK_SIZE} where the connection can carry it, which is where
 * it was all along.
 *
 * This makes the bar move often. It does not make it continuous: that needs
 * upload progress events, which only XMLHttpRequest has, and this transport is
 * a `fetch` the caller can substitute.
 */
export const CHUNK_TARGET_MS = 2000;
/** Small enough that a first chunk on a bad link is a short wait, not a stall. */
export const FIRST_CHUNK_SIZE = 512 * 1024;
/** Below this the request overhead starts to cost more than the finer bar buys. */
export const MIN_CHUNK_SIZE = 256 * 1024;

/** The clock the adaptation reads. A monotonic one, so a system clock stepping
 *  backwards cannot make a chunk look instantaneous. */
const now = (): number =>
  typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();

/**
 * The size to send next, from how long the last one took.
 *
 * Bounded to a halving or a doubling per step, so one slow request does not
 * collapse the size and one fast one does not undo the collapse. A send too
 * quick to measure is treated as room to grow rather than as infinite speed.
 */
export function nextChunkSize(sent: number, elapsedMs: number): number {
  const scaled = elapsedMs <= 0 ? sent * 2 : sent * (CHUNK_TARGET_MS / elapsedMs);
  const bounded = Math.min(Math.max(scaled, sent / 2), sent * 2);
  return Math.min(Math.max(Math.round(bounded), MIN_CHUNK_SIZE), DEFAULT_CHUNK_SIZE);
}

/**
 * Encrypts a file and sends it, resolving to the secrets needed to share it.
 *
 * The plaintext is never held whole. It is read as a stream, encrypted record
 * by record, and accumulated only up to one chunk, so the memory used does not
 * depend on the size of the file.
 */
export async function uploadFile(req: UploadRequest): Promise<UploadResult> {
  const { file, options = {}, transport = {}, onProgress } = req;
  // A caller who named a size gets it, unchanged, every time. Only the default
  // adapts, because only the default is a guess about a connection nobody has
  // measured yet.
  const adapt = req.chunkSize === undefined;
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
  const sent = await sendEncrypted(
    file,
    fileKey,
    location,
    chunkSize,
    adapt,
    transport,
    (n) => report("sending", n),
    req.stream ?? canStreamRequests(),
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
  adapt: boolean,
  transport: Transport,
  onSent: (sent: number) => void,
  tryStreaming: boolean,
): Promise<number> {
  if (tryStreaming) {
    const streamed = await sendAsOneStream(file, fileKey, location, transport, onSent);
    if (!streamed.refusedOutright) return streamed.offset;
    // The browser would not send it: no HTTP/2 between here and the instance,
    // which is an ordinary deployment rather than a fault. Nothing was written,
    // so the chunked path starts from the beginning as usual.
  }
  return sendInChunks(file, fileKey, location, chunkSize, adapt, transport, onSent);
}

/**
 * Sends the whole encoding as one request body.
 *
 * One round trip instead of one per chunk, and no buffer to fill. What it
 * cannot do is report acknowledged bytes: the response arrives only when the
 * body has been sent, so progress here counts what has been handed to the
 * network. See {@link UploadProgress.sent}.
 */
async function sendAsOneStream(
  file: File,
  fileKey: Uint8Array,
  location: string,
  transport: Transport,
  onSent: (sent: number) => void,
): Promise<{ offset: number; refusedOutright: boolean }> {
  let handed = 0;
  const counting = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      handed += chunk.length;
      controller.enqueue(chunk);
      onSent(handed);
    },
  });

  const body = file
    .stream()
    .pipeThrough(encryptStream(fileKey), transport.signal ? { signal: transport.signal } : {})
    .pipeThrough(counting, transport.signal ? { signal: transport.signal } : {});

  const result = await patchStream(location, 0, body, transport);
  if (result.refusedOutright) {
    // Progress advanced against a request that never left. Putting it back
    // stops a bar that walked forwards from walking backwards when the chunked
    // path starts again from zero.
    onSent(0);
  }
  return result;
}

/**
 * Streams the file through the encoder, sending whole chunks as they fill.
 *
 * Encryption and transmission are interleaved deliberately. Encrypting first
 * would mean holding the whole ciphertext, and would leave progress at zero for
 * as long as it took.
 */
async function sendInChunks(
  file: File,
  fileKey: Uint8Array,
  location: string,
  chunkSize: number,
  adapt: boolean,
  transport: Transport,
  onSent: (sent: number) => void,
): Promise<number> {
  const encrypted = file
    .stream()
    .pipeThrough(encryptStream(fileKey), transport.signal ? { signal: transport.signal } : {});
  const reader = encrypted.getReader();

  // The buffer is the largest a chunk may become; `target` is how much of it is
  // filled before sending, and moves with what the connection turns out to do.
  // A caller who named a size gets exactly that, every time: a test that fixes
  // the size is testing chunking, not the network it is not on.
  const buffer = new Uint8Array(adapt ? DEFAULT_CHUNK_SIZE : chunkSize);
  let target = adapt ? Math.min(FIRST_CHUNK_SIZE, buffer.length) : chunkSize;
  let held = 0;
  let offset = 0;

  const send = async (chunk: Uint8Array) => {
    const started = now();
    offset = await patchChunk(location, offset, chunk, transport);
    onSent(offset);
    if (adapt) target = Math.min(nextChunkSize(chunk.length, now() - started), buffer.length);
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;

      let taken = 0;
      while (taken < value.length) {
        const take = Math.min(target - held, value.length - taken);
        buffer.set(value.subarray(taken, taken + take), held);
        held += take;
        taken += take;
        if (held === target) {
          await send(buffer.subarray(0, held));
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
