// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The tus 1.0.0 client side, as far as Sendan uses it.
 *
 * A protocol library is not used because the parts needed are small and the
 * parts not needed are the ones with the surface: this speaks creation, PATCH
 * and HEAD, and nothing else. `docs/api.md` is the server's half.
 */

export const TUS_VERSION = "1.0.0";

/** A value carried in `Upload-Metadata`. Numbers travel as decimal text. */
export type MetadataValue = Uint8Array | string | number;

/**
 * An HTTP response the API did not promise.
 *
 * The status is kept separate from the message because it is what a caller
 * branches on. The message is for a person: it is server-supplied text and is
 * never parsed.
 */
export class TusError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "TusError";
    this.status = status;
  }
}

const encoder = new TextEncoder();

function toBase64(bytes: Uint8Array): string {
  // Chunked so a large value cannot exceed the argument limit of apply. No
  // value here is large, but a metadata encoder that breaks above some size is
  // the kind of limit found in production rather than in a test.
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/**
 * Encodes `Upload-Metadata`.
 *
 * The format is `key base64(value)`, comma-separated. The base64 is the
 * protocol's own and is padded standard alphabet, not the base64url the wire
 * format uses elsewhere: the server decodes this header before Sendan sees it.
 *
 * A key containing a space or a comma would be silently reinterpreted as a
 * different key, or as two, so it is refused rather than encoded.
 */
export function encodeMetadata(values: Record<string, MetadataValue>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(values)) {
    if (key === "" || /[\s,]/.test(key)) {
      throw new TypeError(`tus: metadata key ${JSON.stringify(key)} is not encodable`);
    }
    const bytes =
      value instanceof Uint8Array
        ? value
        : encoder.encode(typeof value === "number" ? `${value}` : value);
    parts.push(`${key} ${toBase64(bytes)}`);
  }
  return parts.join(",");
}

/** The pieces of the environment a caller may substitute, so tests need no server. */
export interface Transport {
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

/**
 * Reads whatever explanation a failed response carries.
 *
 * The API answers in JSON and the protocol handler in text, and a client that
 * assumed either would show an empty error for half of what can go wrong.
 */
/**
 * The signal, as a spreadable fragment of a request.
 *
 * Spread rather than assigned because an explicit `signal: undefined` is not
 * the same as an absent one under exactOptionalPropertyTypes, and some runtimes
 * treat the two differently.
 */
function abortable(transport: Transport): { signal?: AbortSignal } {
  return transport.signal ? { signal: transport.signal } : {};
}

async function describe(response: Response): Promise<string> {
  let body = "";
  try {
    body = (await response.text()).trim();
  } catch {
    // A body that cannot be read is not worth failing over; the status is the
    // part that matters.
  }
  if (body === "") return `HTTP ${response.status}`;

  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed === "object" && parsed !== null) {
      const message = (parsed as Record<string, unknown>).message;
      if (typeof message === "string" && message !== "") return message;
    }
  } catch {
    // Not JSON, so the text is the message.
  }
  return body.slice(0, 200);
}

/**
 * Reads an offset the server reported.
 *
 * The emptiness check is not redundant with the rest: `Number("")` is zero, so
 * a header that arrived empty - stripped by a proxy, or written by a server
 * with a formatting fault - would otherwise be read as "you are at the start",
 * and the client would resend the whole file over what it had already stored.
 */
function parseOffset(response: Response, reported: string): number {
  const offset = Number(reported);
  if (reported.trim() === "" || !Number.isSafeInteger(offset) || offset < 0) {
    throw new TusError(response.status, `the server reported the offset as ${reported}`);
  }
  return offset;
}

export interface CreateRequest {
  /** Total bytes to be sent. Sendan refuses a deferred length; see `docs/api.md`. */
  length: number;
  metadata: Record<string, MetadataValue>;
  /** Where creation is posted. Relative by default, so the client works on any origin. */
  endpoint?: string;
}

/**
 * Creates an upload and returns the URL that identifies it.
 *
 * The returned value comes from `Location` and is resolved against the request
 * URL, because the header may be relative.
 */
export async function createUpload(req: CreateRequest, transport: Transport = {}): Promise<string> {
  const endpoint = req.endpoint ?? "/api/uploads";
  const doFetch = transport.fetch ?? fetch;

  const response = await doFetch(endpoint, {
    method: "POST",
    headers: {
      "Tus-Resumable": TUS_VERSION,
      "Upload-Length": `${req.length}`,
      "Upload-Metadata": encodeMetadata(req.metadata),
    },
    ...abortable(transport),
  });

  if (response.status !== 201) {
    throw new TusError(response.status, await describe(response));
  }

  const location = response.headers.get("Location");
  if (location === null || location === "") {
    throw new TusError(response.status, "the server created an upload without saying where");
  }
  // A base is supplied for the relative case; in a browser there is always a
  // document URL, but tests run without one.
  return new URL(location, response.url || "http://localhost/").toString();
}

/**
 * Writes bytes at an offset, returning the offset the server then holds.
 *
 * The server's reported offset is returned rather than the one that was
 * computed locally. They agree in every ordinary case, and where they do not it
 * is the server that decides what has been stored.
 */
export async function patchChunk(
  location: string,
  offset: number,
  chunk: Uint8Array,
  transport: Transport = {},
): Promise<number> {
  const doFetch = transport.fetch ?? fetch;

  const response = await doFetch(location, {
    method: "PATCH",
    headers: {
      "Tus-Resumable": TUS_VERSION,
      "Content-Type": "application/offset+octet-stream",
      "Upload-Offset": `${offset}`,
    },
    // A view is copied into a fresh buffer: the chunk may be a subarray of a
    // larger, reused buffer, and sending the view would send the whole of it.
    body: chunk.slice().buffer as ArrayBuffer,
    ...abortable(transport),
  });

  if (response.status !== 204) {
    throw new TusError(response.status, await describe(response));
  }

  const reported = response.headers.get("Upload-Offset");
  if (reported === null) {
    throw new TusError(response.status, "the server accepted a chunk without reporting an offset");
  }
  return parseOffset(response, reported);
}

/**
 * Asks where an interrupted upload left off.
 *
 * A completed upload answers 404, which is not an error here but the answer:
 * there is nothing left to resume.
 */
export async function currentOffset(
  location: string,
  transport: Transport = {},
): Promise<number | null> {
  const doFetch = transport.fetch ?? fetch;

  const response = await doFetch(location, {
    method: "HEAD",
    headers: { "Tus-Resumable": TUS_VERSION },
    ...abortable(transport),
  });

  if (response.status === 404) return null;
  if (!response.ok) {
    throw new TusError(response.status, await describe(response));
  }

  const reported = response.headers.get("Upload-Offset");
  if (reported === null) {
    throw new TusError(response.status, "the server reported no offset to resume from");
  }
  return parseOffset(response, reported);
}
