// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Opening a link and recovering the file behind it.
 *
 * Everything needed comes from the link: the identifier addresses the upload
 * and the fragment secret derives every key. The instance contributes
 * ciphertext and the parameters needed to derive again, and could not decrypt
 * what it holds.
 */

import {
  decryptStream,
  deriveKeys,
  deriveKeysWithPassword,
  type Keys,
  type Metadata,
  openMetadata,
  type PasswordParams,
  unwrapFileKey,
} from "../crypto/index.js";
import { fromBase64Url, toBase64Url } from "./link.js";
import type { Transport } from "./tus.js";

/**
 * Why a download did not happen.
 *
 * The distinctions here are exactly those that can be drawn honestly, and no
 * others. Two are deliberately absent:
 *
 * The instance answers `404` for expired, exhausted, revoked, unknown, and
 * still-being-written alike, and it is right to - telling a stranger which one
 * applies confirms that an upload existed. So `unavailable` covers all of them
 * and the interface must not guess between them.
 *
 * A wrong password and a corrupt wrapped key are indistinguishable by
 * construction (spec §13 invariant 5); distinguishing them would let anyone
 * holding the ciphertext confirm a guessed password offline. Which of
 * `password-wrong` and `damaged` is reported turns on whether a password was
 * asked for at all, which the instance already publishes - not on the failure.
 */
export type DownloadFault =
  | "link-incomplete"
  | "link-damaged"
  | "unavailable"
  | "password-wrong"
  | "damaged"
  | "corrupt"
  | "too-many-attempts"
  | "unreachable";

export class DownloadError extends Error {
  readonly fault: DownloadFault;
  /** Seconds to wait, where the instance said. */
  readonly retryAfter: number | null;

  constructor(fault: DownloadFault, message: string, retryAfter: number | null = null) {
    super(message);
    this.name = "DownloadError";
    this.fault = fault;
    this.retryAfter = retryAfter;
  }
}

/** What the instance publishes about an upload, before anything is decrypted. */
export interface UploadMetadata {
  id: string;
  wrappedFileKey: Uint8Array;
  wrapNonce: Uint8Array;
  metadataEnvelope: Uint8Array;
  metadataNonce: Uint8Array;
  passwordRequired: boolean;
  /** Present only when a password is required. */
  kdf: PasswordParams | null;
  /** Absent when the upload never expires. */
  expiresAt: Date | null;
  /** Absent when there is no limit. */
  downloadsRemaining: number | null;
}

/**
 * Reads what the instance publishes about an upload.
 *
 * Unauthenticated by necessity: producing a token requires the password, and
 * this is where a client learns whether there is one. Nothing is disclosed by
 * that - every value is ciphertext under a key the instance does not hold.
 *
 * Reading this does not consume a download.
 */
export async function fetchMetadata(
  id: string,
  transport: Transport = {},
  origin = "",
): Promise<UploadMetadata> {
  const doFetch = transport.fetch ?? fetch;

  let response: Response;
  try {
    response = await doFetch(`${origin}/api/uploads/${encodeURIComponent(id)}/metadata`, {
      headers: { accept: "application/json" },
      ...(transport.signal ? { signal: transport.signal } : {}),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new DownloadError("unreachable", "The instance could not be reached.");
  }

  if (response.status === 404) {
    throw new DownloadError("unavailable", "This upload is no longer available.");
  }
  if (response.status === 429) {
    throw new DownloadError("too-many-attempts", "Too many attempts.", retryAfter(response));
  }
  if (!response.ok) {
    throw new DownloadError("unreachable", `The instance answered ${response.status}.`);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new DownloadError("unreachable", "The instance sent something unreadable.");
  }

  const parsed = parseMetadata(body);
  if (parsed === null) {
    throw new DownloadError("unreachable", "The instance sent something unreadable.");
  }
  return parsed;
}

function retryAfter(response: Response): number | null {
  const header = response.headers.get("Retry-After");
  if (header === null) return null;
  const seconds = Number(header);
  return header.trim() !== "" && Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}

/**
 * Validates the response before anything acts on it.
 *
 * The shape is checked rather than assumed because the instance is the party
 * this client is protecting the file from. A missing field that reached the key
 * schedule as `undefined` would fail somewhere far from the cause.
 */
export function parseMetadata(value: unknown): UploadMetadata | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;

  if (typeof v.id !== "string" || v.id === "") return null;
  if (typeof v.passwordRequired !== "boolean") return null;

  const binary: Record<string, Uint8Array> = {};
  for (const key of ["wrappedFileKey", "wrapNonce", "metadataEnvelope", "metadataNonce"]) {
    if (typeof v[key] !== "string") return null;
    const bytes = fromBase64Url(v[key] as string);
    if (bytes === null) return null;
    binary[key] = bytes;
  }

  let kdf: PasswordParams | null = null;
  if (v.passwordRequired) {
    // Required when a password is set: without them no key can be derived, so
    // an upload missing them is one nobody could ever open.
    kdf = parseKdf(v.kdf);
    if (kdf === null) return null;
  }

  let expiresAt: Date | null = null;
  if (v.expiresAt !== undefined && v.expiresAt !== null) {
    if (typeof v.expiresAt !== "string") return null;
    const when = new Date(v.expiresAt);
    if (Number.isNaN(when.getTime())) return null;
    expiresAt = when;
  }

  let downloadsRemaining: number | null = null;
  if (v.downloadsRemaining !== undefined && v.downloadsRemaining !== null) {
    if (typeof v.downloadsRemaining !== "number" || !Number.isFinite(v.downloadsRemaining)) {
      return null;
    }
    downloadsRemaining = v.downloadsRemaining;
  }

  return {
    id: v.id,
    wrappedFileKey: binary.wrappedFileKey as Uint8Array,
    wrapNonce: binary.wrapNonce as Uint8Array,
    metadataEnvelope: binary.metadataEnvelope as Uint8Array,
    metadataNonce: binary.metadataNonce as Uint8Array,
    passwordRequired: v.passwordRequired,
    kdf,
    expiresAt,
    downloadsRemaining,
  };
}

function parseKdf(value: unknown): PasswordParams | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;

  if (typeof v.salt !== "string") return null;
  const salt = fromBase64Url(v.salt);
  if (salt === null) return null;

  const numbers: Record<string, number> = {};
  for (const key of ["memoryKiB", "iterations", "parallelism"]) {
    // Zero would mean a derivation that does no work, which is not a parameter
    // choice but a broken upload.
    if (typeof v[key] !== "number" || !Number.isInteger(v[key]) || (v[key] as number) <= 0) {
      return null;
    }
    numbers[key] = v[key] as number;
  }

  return {
    salt,
    memoryKiB: numbers.memoryKiB as number,
    iterations: numbers.iterations as number,
    parallelism: numbers.parallelism as number,
  };
}

/** An upload that has been opened: its keys recovered and its description read. */
export interface OpenedUpload {
  keys: Keys;
  fileKey: Uint8Array;
  file: Metadata;
}

/**
 * Recovers the keys and reads what the file is.
 *
 * Nothing here touches the network. Succeeding proves the link, and the
 * password where there is one, are right - the wrapped key is authenticated, so
 * a wrong key cannot open it. That is why a password is checked locally rather
 * than by asking the instance: a check the instance performed would be one it
 * could be lied about, and one that spent an attempt allowance.
 */
export async function openUpload(
  fileID: Uint8Array,
  linkSecret: Uint8Array,
  metadata: UploadMetadata,
  password = "",
): Promise<OpenedUpload> {
  let keys: Keys;
  try {
    keys =
      metadata.kdf === null
        ? await deriveKeys(fileID, linkSecret)
        : await deriveKeysWithPassword(fileID, linkSecret, password, metadata.kdf);
  } catch {
    // The schedule refuses an empty password outright (spec §4), which is the
    // ordinary case of somebody pressing the button with the field untouched.
    // Left unhandled it would surface as a crash rather than as the answer,
    // which is that the password did not work.
    throw metadata.passwordRequired
      ? new DownloadError("password-wrong", "That password did not open the file.")
      : new DownloadError("link-damaged", "This link is not a usable one.");
  }

  let fileKey: Uint8Array;
  try {
    fileKey = await unwrapFileKey(keys.wrapping, metadata.wrapNonce, metadata.wrappedFileKey);
  } catch {
    // The failure itself says nothing about which of the two occurred, and must
    // not: see spec §13 invariant 5. What is reported turns on whether a
    // password was asked for, which the instance already published.
    throw metadata.passwordRequired
      ? new DownloadError("password-wrong", "That password did not open the file.")
      : new DownloadError("damaged", "This link or the stored file is damaged.");
  }

  let file: Metadata;
  try {
    file = await openMetadata(keys.metadata, metadata.metadataNonce, metadata.metadataEnvelope);
  } catch {
    // The wrapped key opened, so the keys are right and the envelope is not.
    // Saying so is safe precisely because the key already worked.
    throw new DownloadError("corrupt", "The file's description is damaged.");
  }

  return { keys, fileKey, file };
}

export interface DownloadProgress {
  /** Plaintext bytes recovered so far. */
  received: number;
  /** Plaintext bytes expected, from the envelope. */
  total: number;
}

export interface DownloadRequest {
  id: string;
  opened: OpenedUpload;
  transport?: Transport;
  onProgress?: (progress: DownloadProgress) => void;
  origin?: string;
}

/**
 * Fetches and decrypts the content.
 *
 * Decryption is streamed, so a modified or truncated stream fails rather than
 * yielding partial plaintext (spec §13 invariant 3). The result is assembled in
 * memory, which bounds what can be downloaded; streaming it to disk instead is
 * issue #38, and the Service Worker fallback for browsers without that API is
 * issue #37.
 */
export async function downloadContent(req: DownloadRequest): Promise<Uint8Array> {
  const { id, opened, transport = {}, onProgress, origin = "" } = req;
  const doFetch = transport.fetch ?? fetch;

  let response: Response;
  try {
    response = await doFetch(`${origin}/api/uploads/${encodeURIComponent(id)}/content`, {
      headers: { Authorization: `Bearer ${toBase64Url(opened.keys.authToken)}` },
      ...(transport.signal ? { signal: transport.signal } : {}),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new DownloadError("unreachable", "The instance could not be reached.");
  }

  if (response.status === 404) {
    throw new DownloadError("unavailable", "This upload is no longer available.");
  }
  if (response.status === 429) {
    throw new DownloadError("too-many-attempts", "Too many attempts.", retryAfter(response));
  }
  if (response.status === 401) {
    // The token derives from the same schedule that just unwrapped the key, so
    // reaching here means the upload changed underneath rather than that the
    // password was wrong.
    throw new DownloadError("unavailable", "This upload is no longer available.");
  }
  if (!response.ok || response.body === null) {
    throw new DownloadError("unreachable", `The instance answered ${response.status}.`);
  }

  return collect(response.body, opened, onProgress, transport.signal);
}

async function collect(
  body: ReadableStream<Uint8Array>,
  opened: OpenedUpload,
  onProgress: ((progress: DownloadProgress) => void) | undefined,
  signal: AbortSignal | undefined,
): Promise<Uint8Array> {
  const total = opened.file.size;
  const plaintext = new Uint8Array(total);
  let received = 0;

  const reader = body
    .pipeThrough(decryptStream(opened.fileKey), signal ? { signal } : {})
    .getReader();

  onProgress?.({ received: 0, total });

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      // The envelope declares the size, and the envelope is authenticated. More
      // plaintext than it declares means the two disagree, which is a fault
      // rather than something to grow a buffer for.
      if (received + value.length > total) {
        throw new DownloadError("corrupt", "The file is longer than its description says.");
      }
      plaintext.set(value, received);
      received += value.length;
      onProgress?.({ received, total });
    }
  } catch (error) {
    if (error instanceof DownloadError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    // A truncated, reordered or modified stream lands here, which is invariant
    // 3 holding rather than an unexpected condition.
    throw new DownloadError("corrupt", "The file failed its integrity check.");
  } finally {
    reader.releaseLock();
  }

  if (received !== total) {
    throw new DownloadError("corrupt", "The file is shorter than its description says.");
  }
  return plaintext;
}

/**
 * What to tell the person holding the link.
 *
 * Kept apart from the faults themselves so the wording is one thing to review.
 * Each of these has to be true without being more specific than is safe.
 */
export function explain(fault: DownloadFault): string {
  switch (fault) {
    case "link-incomplete":
      return (
        "This link is missing the part after the #, which is the key. " +
        "It cannot be recovered - ask the sender for the whole link."
      );
    case "link-damaged":
      return "This link is not complete or was altered in transit. Ask the sender for it again.";
    case "unavailable":
      return (
        "This upload is no longer available. It may have expired, reached its " +
        "download limit, been deleted by the sender, or never have existed. " +
        "The instance does not say which, so that a stranger holding a link " +
        "cannot learn whether it was ever real."
      );
    case "password-wrong":
      return "That password did not open the file. Check it and try again.";
    case "damaged":
      return (
        "The file could not be opened with this link. Either the link was " +
        "altered in transit or what the instance holds is damaged; these " +
        "cannot be told apart, by design."
      );
    case "corrupt":
      return (
        "The file did not pass its integrity check. What arrived is not what " +
        "was sent, so none of it is shown rather than part of it."
      );
    case "too-many-attempts":
      return "Too many attempts have been made against this upload. Wait, then try again.";
    case "unreachable":
      return "The instance could not be reached, or did not answer as expected.";
  }
}
