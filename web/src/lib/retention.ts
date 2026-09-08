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
  // A ladder of round lifetimes, plus whatever the instance itself named. Both
  // of the instance's values belong in the list as real numbers rather than as
  // an entry meaning "you decide": that entry carries no lifetime, so this side
  // cannot say what the file got, and it reported no deadline for a file that
  // had one (#251).
  const ladder = [3600, 86400, 7 * 86400, 30 * 86400];
  const max = policy.maxTtlSeconds;
  const preferred = policy.defaultTtlSeconds;

  const values = new Set(max === null ? ladder : ladder.filter((v) => v <= max));

  // The longest the instance permits. Without this a maximum that misses the
  // ladder cannot be chosen at all - 72h sits between two rungs, so both higher
  // ones are filtered away and nothing takes their place. Raising the ceiling
  // to three days then *lowered* the visible maximum from seven days to one.
  if (max !== null) values.add(max);

  if (preferred !== null && (max === null || preferred <= max)) values.add(preferred);

  const offered: Array<Choice<number>> = [...values]
    .sort((a, b) => a - b)
    .map((value) => ({ value, label: formatDuration(value) }));

  for (const choice of offered) {
    const isDefault = choice.value === preferred;
    const isMax = choice.value === max;
    if (isDefault && isMax) {
      choice.label = `${choice.label} (this instance's default, and the longest it allows)`;
    } else if (isDefault) {
      choice.label = `${choice.label} (this instance's default)`;
    } else if (isMax) {
      choice.label = `${choice.label} (the longest this instance allows)`;
    }
  }

  if (preferred === null) {
    // The instance did not say what it applies, so there is no real lifetime to
    // preselect and asking it to decide is the only way to get its default.
    offered.unshift({ value: USE_DEFAULT, label: "This instance's default" });
  }

  // Last, and only where permitted: it is the option with the most
  // consequences, and on most instances it is not available at all.
  if (policy.allowInfiniteTtl === true) {
    offered.push({ value: NEVER, label: "Never" });
  }
  return offered;
}

/**
 * The lifetime to start on.
 *
 * The instance's own default where it published one, so the form shows what
 * would happen anyway and the request carries the number rather than asking the
 * instance to fill it in. Where it published none, the request has to ask.
 */
export function defaultExpiry(policy: InstancePolicy): number {
  const choices = expiryChoices(policy);
  const preferred = policy.defaultTtlSeconds;
  if (preferred !== null && choices.some((c) => c.value === preferred)) {
    return preferred;
  }
  // Either nothing was published, or the default is longer than this instance
  // now accepts. Asking it to decide is the honest answer to both.
  return USE_DEFAULT;
}

/** The download limits to offer, with the instance's own default named. */
export function downloadChoices(policy: InstancePolicy): Array<Choice<number>> {
  const counts = [1, 5, 20, 100];
  // A default this list does not otherwise carry - seven, say - belongs in it
  // as a real number, in place. Without this the list marks nothing and the
  // form starts somewhere the instance did not choose.
  const preferred = policy.defaultMaxDownloads;
  if (preferred !== null && preferred > 0 && !counts.includes(preferred)) {
    counts.push(preferred);
    counts.sort((a, b) => a - b);
  }

  const mark = (count: number, label: string) =>
    count === preferred ? `${label} (this instance's default)` : label;

  return [
    { value: 0, label: mark(0, "No limit") },
    ...counts.map((count) => ({
      value: count,
      label: mark(count, `${count} download${count === 1 ? "" : "s"}`),
    })),
  ];
}

/**
 * The download limit to start on.
 *
 * The instance's own default, so the form shows what would happen anyway. This
 * is not the same failure the lifetime had - a limit of zero means no limit on
 * both sides, so nothing was ever misdescribed - but a list that marks one
 * entry as the default and starts on another is its own small lie.
 */
export function defaultDownloads(policy: InstancePolicy): number {
  // No limit where the instance published none: zero means the same thing on
  // both sides, so nothing is misdescribed by starting there.
  return policy.defaultMaxDownloads ?? 0;
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
