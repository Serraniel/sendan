// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Download links, per spec §10.
 *
 * The secret lives in the fragment, which browsers do not transmit. That is
 * what keeps it out of server logs, proxy logs and CDN access logs, and it is
 * also what makes a truncated link silently useless: the part most likely to be
 * lost in copying is the only part that cannot be recovered.
 */

import { FILE_ID_SIZE, LINK_SECRET_SIZE } from "../crypto/index.js";

/** Unpadded base64url, the wire format's encoding for binary values (spec §1). */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** The inverse of {@link toBase64Url}. Returns null for anything malformed. */
export function fromBase64Url(text: string): Uint8Array | null {
  // Checked rather than left to atob, which accepts the standard alphabet and
  // ignores some malformed input. A link is attacker-supplied text.
  if (text === "" || !/^[A-Za-z0-9_-]+$/.test(text)) return null;

  const padded = text
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(text.length + ((4 - (text.length % 4)) % 4), "=");
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/**
 * Builds the link a recipient opens.
 *
 * `origin` is passed in rather than read from `location` so that the value is
 * visible to the caller that displays it: a link built from an origin nobody
 * chose is how a client ends up handing out `http://localhost` links.
 */
export function downloadLink(origin: string, fileID: Uint8Array, linkSecret: Uint8Array): string {
  if (fileID.length !== FILE_ID_SIZE) {
    throw new TypeError(`link: file id is ${fileID.length} bytes, want ${FILE_ID_SIZE}`);
  }
  if (linkSecret.length !== LINK_SECRET_SIZE) {
    throw new TypeError(
      `link: link secret is ${linkSecret.length} bytes, want ${LINK_SECRET_SIZE}`,
    );
  }
  const base = origin.replace(/\/+$/, "");
  return `${base}/d/${toBase64Url(fileID)}#${toBase64Url(linkSecret)}`;
}

/** What a link resolves to. */
export interface ParsedLink {
  fileID: Uint8Array;
  linkSecret: Uint8Array;
}

/**
 * Recovers the identifier and secret from a link.
 *
 * Sizes are checked, so a link that lost characters in transit is reported as
 * broken rather than carried forward into a derivation that produces keys which
 * merely fail to open anything. Which of the two happened is the difference
 * between "this link is damaged" and "this file is corrupt".
 */
export function parseLink(link: string): ParsedLink | null {
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    return null;
  }

  const match = /^\/d\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
  if (match === null) return null;

  // A fragment that is present but empty is a link that was copied up to and
  // including the separator, which is exactly the failure this guards.
  const fragment = url.hash.startsWith("#") ? url.hash.slice(1) : "";

  const fileID = fromBase64Url(match[1] as string);
  const linkSecret = fromBase64Url(fragment);
  if (fileID === null || linkSecret === null) return null;
  if (fileID.length !== FILE_ID_SIZE || linkSecret.length !== LINK_SECRET_SIZE) return null;

  return { fileID, linkSecret };
}

/**
 * Whether the link is complete.
 *
 * Offered separately so an interface can say *what* is wrong. A link whose
 * fragment was dropped parses as far as the identifier, and telling the person
 * holding it that the secret is missing is actionable; "invalid link" is not.
 */
export function fragmentIsPresent(link: string): boolean {
  const hash = link.indexOf("#");
  return hash !== -1 && hash !== link.length - 1;
}
