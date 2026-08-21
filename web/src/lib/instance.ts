// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * What an instance says it permits.
 *
 * Everything an instance would refuse was previously discoverable only by
 * trying: the size it accepts, how long an upload may live, whether it may live
 * forever, whether a limit is compulsory. Somebody deciding whether to use an
 * instance at all - a stranger's instance in particular - should be able to see
 * the rules rather than discover them by being refused.
 *
 * ## What this is worth
 *
 * An instance can state whatever it likes here, and nothing binds it to the
 * truth. This is a convenience rather than a guarantee, and the interface says
 * so where it shows it. The properties that do not depend on the instance being
 * honest are the cryptographic ones: the key is derived and used in this
 * browser whatever this endpoint claims.
 *
 * ## Absent values
 *
 * Every field can be absent, and absent means "not said" rather than a default
 * invented here. An interface that filled in a plausible number would be making
 * exactly the claim this module exists to avoid.
 */

import type { Transport } from "$lib/tus";

/** The policy an instance reports. Any field may be absent. */
export interface InstancePolicy {
  maxUploadSize: number | null;
  defaultTtlSeconds: number | null;
  maxTtlSeconds: number | null;
  allowInfiniteTtl: boolean | null;
  requireLimit: boolean | null;
  defaultMaxDownloads: number | null;
  compatEnabled: boolean | null;
}

/** What is known when the instance has said nothing. */
export const nothingKnown: InstancePolicy = {
  maxUploadSize: null,
  defaultTtlSeconds: null,
  maxTtlSeconds: null,
  allowInfiniteTtl: null,
  requireLimit: null,
  defaultMaxDownloads: null,
  compatEnabled: null,
};

/**
 * Asks the instance for its policy.
 *
 * Never throws. An instance that cannot be reached, or that answers with
 * something else entirely, leaves the interface exactly as it was: a page that
 * refused to work because it could not read a policy would be worse than one
 * that does not know it.
 */
export async function fetchInstancePolicy(
  transport: Transport = {},
  origin = "",
): Promise<InstancePolicy> {
  const doFetch = transport.fetch ?? fetch;

  try {
    const response = await doFetch(`${origin}/api/instance`, {
      ...(transport.signal ? { signal: transport.signal } : {}),
    });
    if (!response.ok) return nothingKnown;
    return parsePolicy(await response.json());
  } catch {
    return nothingKnown;
  }
}

/**
 * Reads a policy out of whatever arrived.
 *
 * Field by field, because this is a value from the network and an instance is
 * free to send anything. A field of the wrong type is treated as unsaid rather
 * than coerced: "3 days" coerced to a number is not a mistake worth passing on
 * to somebody choosing a retention period.
 */
export function parsePolicy(value: unknown): InstancePolicy {
  if (typeof value !== "object" || value === null) return nothingKnown;
  const v = value as Record<string, unknown>;

  return {
    maxUploadSize: positive(v.maxUploadSize),
    defaultTtlSeconds: positive(v.defaultTtlSeconds),
    maxTtlSeconds: positive(v.maxTtlSeconds),
    allowInfiniteTtl: boolean(v.allowInfiniteTtl),
    requireLimit: boolean(v.requireLimit),
    // Zero is meaningful here - it is how "no limit" is expressed - so this one
    // admits it while the durations above do not.
    defaultMaxDownloads: whole(v.defaultMaxDownloads),
    compatEnabled: boolean(v.compatEnabled),
  };
}

function positive(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

function whole(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

function boolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** A duration somebody can read, from seconds. */
export function formatDuration(seconds: number): string {
  const units: Array<[number, string]> = [
    [86400, "day"],
    [3600, "hour"],
    [60, "minute"],
  ];

  for (const [size, name] of units) {
    if (seconds >= size) {
      const n = Math.round(seconds / size);
      return `${n} ${name}${n === 1 ? "" : "s"}`;
    }
  }
  return `${seconds} second${seconds === 1 ? "" : "s"}`;
}
