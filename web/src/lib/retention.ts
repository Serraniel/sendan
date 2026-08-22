// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Which retention options to offer, and what to say about the one chosen.
 *
 * Separated from the page so it can be tested without a browser: what an
 * instance may be asked for is a decision, and the form around it is plumbing.
 * It also lets the cases an instance does not permit be exercised at all - the
 * test instance forbids unlimited retention, so the branch that offers it would
 * otherwise never run.
 *
 * The wire values are the server's, not invented here: zero asks for the
 * instance default and a negative value asks for no expiry at all, which
 * `Service.ResolveExpiry` refuses unless the instance permits it.
 */

// Relative rather than through the $lib alias: the alias is resolved by the
// bundler and not by the test runner, so a value imported through it is a
// module that cannot be found the moment anything imports this outside a build.
// A type import survives only because it is erased.
import { formatDuration, type InstancePolicy } from "./instance.js";

/** Asks the instance to apply its own default. */
export const USE_DEFAULT = 0;

/** Asks for an upload that never expires. Refused unless the instance allows it. */
export const NEVER = -1;

export interface Choice<T> {
  value: T;
  label: string;
}

/**
 * The lifetimes to offer.
 *
 * Anything beyond what the instance accepts is dropped rather than shown and
 * rejected: an option that is present and then refused invites a choice and
 * takes it back.
 */
export function expiryChoices(policy: InstancePolicy): Array<Choice<number>> {
  const defaultLabel =
    policy.defaultTtlSeconds === null
      ? "This instance's default"
      : `${formatDuration(policy.defaultTtlSeconds)} (this instance's default)`;

  const offered: Array<Choice<number>> = [
    { value: USE_DEFAULT, label: defaultLabel },
    { value: 3600, label: "1 hour" },
    { value: 86400, label: "1 day" },
    { value: 7 * 86400, label: "7 days" },
    { value: 30 * 86400, label: "30 days" },
  ];

  const max = policy.maxTtlSeconds;
  const within = max === null ? offered : offered.filter((c) => c.value <= max);

  // Last, and only where permitted: it is the option with the most
  // consequences, and on most instances it is not available at all.
  if (policy.allowInfiniteTtl === true) {
    within.push({ value: NEVER, label: "Never" });
  }
  return within;
}

/** The download limits to offer, with the instance's own default named. */
export function downloadChoices(policy: InstancePolicy): Array<Choice<number>> {
  const mark = (count: number, label: string) =>
    count === policy.defaultMaxDownloads ? `${label} (this instance's default)` : label;

  return [
    { value: 0, label: mark(0, "No limit") },
    ...[1, 5, 20, 100].map((count) => ({
      value: count,
      label: mark(count, `${count} download${count === 1 ? "" : "s"}`),
    })),
  ];
}

/** What was applied, and whether nothing will remove it. */
export interface Retention {
  text: string;
  neverRemoved: boolean;
}

/**
 * Describes what an upload was given.
 *
 * An earlier version said nothing at all unless a deadline had been chosen
 * explicitly, so an upload taking the instance's default was described by
 * silence - and so was one set never to expire, which is the choice that most
 * needs stating.
 */
export function describeRetention(
  ttlSeconds: number,
  maxDownloads: number,
  policy: InstancePolicy,
): Retention {
  const applied = ttlSeconds === USE_DEFAULT ? (policy.defaultTtlSeconds ?? 0) : ttlSeconds;
  const downloads =
    maxDownloads > 0 ? `${maxDownloads} download${maxDownloads === 1 ? "" : "s"}` : null;

  if (applied < 0) {
    // The one combination nothing in the system will ever clean up.
    if (downloads === null) {
      return {
        text: "This upload never expires and has no download limit. Nothing removes it but you.",
        neverRemoved: true,
      };
    }
    return {
      text: `This upload never expires, and allows ${downloads}. It is removed once they are spent.`,
      neverRemoved: false,
    };
  }

  if (applied === 0) {
    // The instance did not say what its default is, so neither can this.
    return {
      text:
        downloads === null
          ? "This upload expires on the instance's own schedule."
          : `This upload allows ${downloads}, and expires on the instance's own schedule.`,
      neverRemoved: false,
    };
  }

  const after = formatDuration(applied);
  return {
    text:
      downloads === null
        ? `This upload expires after ${after}.`
        : `This upload expires after ${after}, and allows ${downloads}. Whichever comes first removes it.`,
    neverRemoved: false,
  };
}
