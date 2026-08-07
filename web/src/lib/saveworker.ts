// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The Service Worker's half of the streaming save path.
 *
 * Browsers without the File System Access API - Firefox and Safari - cannot be
 * handed a file to write, so the only way to save without holding the whole
 * thing in memory is to make the browser think it is downloading one. A Service
 * Worker answers a request the page never sends over the network, and its
 * response is a stream of plaintext with a length and a filename. The browser's
 * own download machinery does the writing.
 *
 * The logic lives here rather than in the worker entry point so it can be
 * tested without a Service Worker, which no test runner has.
 */

import { decryptStream, type Metadata } from "../crypto/index.js";

/**
 * The path the worker answers.
 *
 * Under a reserved prefix so it can never collide with a route the client
 * serves, and so the worker can decline everything else without a list.
 */
export const SAVE_PATH = "/_sendan/save/";

/** How long an unclaimed handover is kept, in milliseconds. */
export const HANDOVER_TTL = 60_000;

/**
 * Everything the worker needs to produce one file.
 *
 * The file key is here, which is the whole reason this is deleted the moment it
 * is used and expires if it is not. It is held in memory only: writing it
 * anywhere a Service Worker can persist would outlive the tab that produced it.
 */
export interface Handover {
  /** The upload to fetch. */
  id: string;
  /** Bearer credential for the content endpoint. */
  authToken: string;
  fileKey: Uint8Array;
  file: Metadata;
  /** Where the instance is. Empty means same origin. */
  origin?: string;
}

interface Held {
  handover: Handover;
  expires: number;
}

/**
 * Handovers waiting to be claimed.
 *
 * One-time and expiring, both for the same reason: each holds a file key, and a
 * key that outlives the download it was for is a key sitting in memory for no
 * purpose. A Service Worker is not reloaded between downloads, so nothing else
 * would ever clear it.
 */
export class HandoverStore {
  private held = new Map<string, Held>();
  private now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  put(token: string, handover: Handover, ttl = HANDOVER_TTL): void {
    this.sweep();
    this.held.set(token, { handover, expires: this.now() + ttl });
  }

  /** Returns the handover and forgets it. A second claim gets nothing. */
  take(token: string): Handover | null {
    this.sweep();
    const found = this.held.get(token);
    if (found === undefined) return null;
    this.held.delete(token);
    return found.handover;
  }

  get size(): number {
    this.sweep();
    return this.held.size;
  }

  private sweep(): void {
    const now = this.now();
    for (const [token, held] of this.held) {
      if (held.expires <= now) this.held.delete(token);
    }
  }
}

/** The token in a save URL, or null if this is not one. */
export function tokenOf(url: string): string | null {
  let path: string;
  try {
    path = new URL(url).pathname;
  } catch {
    return null;
  }
  if (!path.startsWith(SAVE_PATH)) return null;

  const token = path.slice(SAVE_PATH.length);
  // One segment of the token alphabet and nothing else, so a crafted path
  // cannot reach anything but a lookup that will fail.
  return /^[A-Za-z0-9_-]{16,64}$/.test(token) ? token : null;
}

/**
 * Encodes a filename for Content-Disposition.
 *
 * The name came from whoever uploaded the file and is not trusted. A carriage
 * return or newline in a header value would end the header and begin another,
 * which is why nothing outside a conservative set is ever emitted literally:
 * the ASCII form keeps only unreserved characters and the RFC 5987 form is
 * percent-encoded, so no input can produce a delimiter.
 */
export function contentDisposition(name: string): string {
  const ascii = name.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 200) || "download";

  // RFC 5987. encodeURIComponent leaves !'()* alone, and they are not valid in
  // the token, so they are encoded by hand.
  const encoded = encodeURIComponent(name.slice(0, 200)).replace(
    /['()!*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );

  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

/**
 * Builds the response the browser saves.
 *
 * The plaintext is a stream and is never assembled, so the browser writes it as
 * it arrives and back-pressure reaches the network: a slow disk slows the
 * fetch rather than filling memory. That is the entire point of this path.
 *
 * The length is the one from the envelope, which is authenticated, so the
 * browser can show real progress and can tell a complete download from a
 * truncated one without trusting the instance's framing.
 */
export async function buildSaveResponse(
  handover: Handover,
  doFetch: typeof fetch = fetch,
): Promise<Response> {
  const origin = handover.origin ?? "";
  const upstream = await doFetch(
    `${origin}/api/uploads/${encodeURIComponent(handover.id)}/content`,
    { headers: { Authorization: `Bearer ${handover.authToken}` } },
  );

  if (!upstream.ok || upstream.body === null) {
    // Plain text and no detail. This response is rendered by the browser as a
    // failed download, and there is nothing here a person could act on that the
    // page has not already told them.
    return new Response("The download could not be completed.", {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  return new Response(upstream.body.pipeThrough(decryptStream(handover.fileKey)), {
    status: 200,
    headers: {
      // Deliberately not the envelope's media type. This response exists to be
      // saved, and a type the browser would rather display - text/html above
      // all - would be an upload rendering itself inside this origin.
      "Content-Type": "application/octet-stream",
      "Content-Length": `${handover.file.size}`,
      "Content-Disposition": contentDisposition(handover.file.name),
      // Nothing here may be stored: it is plaintext of a file the instance is
      // not allowed to read, reachable at a URL that is about to stop existing.
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
