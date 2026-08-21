// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * What the instance will accept, as far as it says so.
 *
 * At present that is one number: the largest upload it takes. It is not fetched
 * from a configuration endpoint - there is none - but from the transfer
 * protocol itself, which advertises `Tus-Max-Size` in answer to an `OPTIONS`
 * request. The server passes `SENDAN_MAX_UPLOAD_SIZE` to the tus handler, and
 * this is where that value surfaces.
 *
 * Knowing it early is the point. Without it a file that cannot be sent is only
 * discovered after uploading enough of it to be refused, and the refusal cannot
 * say what would have been small enough.
 *
 * It is a hint, not a guarantee. An instance can be reconfigured between this
 * page loading and an upload finishing, so the refusal path stays.
 */

import type { Transport } from "$lib/tus";

/** Bytes, or null when the instance does not say. */
export type MaxUploadSize = number | null;

/**
 * Asks the instance for its limit.
 *
 * Never throws: an instance that cannot be reached, or one that answers without
 * the header, leaves the interface exactly as it was before this existed. A
 * page that refused to work because it could not learn a limit would be worse
 * than one that does not know it.
 */
export async function fetchMaxUploadSize(
  transport: Transport = {},
  origin = "",
): Promise<MaxUploadSize> {
  const doFetch = transport.fetch ?? fetch;

  try {
    const response = await doFetch(`${origin}/api/uploads`, {
      method: "OPTIONS",
      ...(transport.signal ? { signal: transport.signal } : {}),
    });
    return parseMaxSize(response.headers.get("tus-max-size"));
  } catch {
    return null;
  }
}

/**
 * Reads the advertised limit.
 *
 * Anything that is not a positive whole number of bytes is treated as no
 * answer. Zero in particular: the protocol uses it for "no limit", and
 * reporting a limit of zero bytes would refuse every file.
 */
export function parseMaxSize(header: string | null): MaxUploadSize {
  if (header === null) return null;

  // Decimal digits only, checked before conversion. Number() would otherwise
  // read "0x10" as 16 and "1e9" as a billion, neither of which the protocol
  // permits - and a limit misread as larger than it is puts the refusal back
  // where this exists to remove it.
  const text = header.trim();
  if (!/^\d+$/.test(text)) return null;

  const value = Number(text);
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  return value;
}

/**
 * A size somebody can read.
 *
 * Powers of ten rather than of two, because that is what a file manager shows
 * and this number is compared against one.
 */
export function formatSize(bytes: number): string {
  const units = ["B", "kB", "MB", "GB", "TB"];
  let n = bytes;
  let unit = 0;
  while (n >= 1000 && unit < units.length - 1) {
    n /= 1000;
    unit++;
  }
  return `${unit === 0 ? n : n.toFixed(1)} ${units[unit]}`;
}

/** Whether a file can be sent, and if not, what to say about it. */
export function tooLargeMessage(size: number, limit: MaxUploadSize): string | null {
  if (limit === null || size <= limit) return null;
  return `That file is ${formatSize(size)}. This instance accepts up to ` + `${formatSize(limit)}.`;
}
