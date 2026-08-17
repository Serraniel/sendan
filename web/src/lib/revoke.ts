// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Removing an upload before it would otherwise expire.
 *
 * Authorised by the owner token, which this browser kept and the instance holds
 * only as a hash. There is no account to authenticate against: possession is
 * the proof, which is also why an instance cannot remove an upload on somebody
 * else's behalf and cannot help when the token is lost.
 *
 * The instance takes the same path it takes when an upload expires - the row,
 * the blob and the at-rest key all go - so this is not a second, weaker way of
 * deleting something.
 */

import type { Transport } from "$lib/tus";

/** Why a revocation did not happen. */
export type RevokeFault =
  /** The token did not match, or the upload is already gone. The instance
   *  answers alike for both so that asking about identifiers reveals nothing. */
  | "not-owner"
  /** The instance could not be reached at all. */
  | "unreachable"
  /** It answered, but not in a way this client can act on. */
  | "instance-error";

export class RevokeError extends Error {
  readonly fault: RevokeFault;

  constructor(fault: RevokeFault, message: string) {
    super(message);
    this.name = "RevokeError";
    this.fault = fault;
  }
}

/**
 * Removes an upload.
 *
 * The token goes in the Authorization header rather than the path, so it does
 * not reach an access log on the way.
 */
export async function revokeUpload(
  id: string,
  ownerToken: string,
  transport: Transport = {},
  origin = "",
): Promise<void> {
  const doFetch = transport.fetch ?? fetch;

  let response: Response;
  try {
    response = await doFetch(`${origin}/api/uploads/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${ownerToken}` },
      ...(transport.signal ? { signal: transport.signal } : {}),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new RevokeError("unreachable", "The instance could not be reached.");
  }

  if (response.ok) return;

  // 403 and 404 mean the same thing here by design, and 401 arrives when the
  // stored token is not a credential at all. None of them is worth telling
  // apart for somebody looking at their own list: the file is not theirs to
  // remove, or it is already gone.
  if (response.status === 401 || response.status === 403 || response.status === 404) {
    throw new RevokeError(
      "not-owner",
      "This upload is already gone, or the owner token no longer matches it.",
    );
  }

  throw new RevokeError("instance-error", "The instance refused to remove this upload.");
}

/** What to show somebody when a revocation fails. */
export function explainRevoke(fault: RevokeFault): string {
  switch (fault) {
    case "not-owner":
      return (
        "This upload is already gone, or the token stored here no longer matches " +
        "it. The record has been removed from this list."
      );
    case "unreachable":
      return "The instance could not be reached. The upload has not been removed.";
    case "instance-error":
      return "The instance refused to remove this upload. It is still there.";
  }
}
