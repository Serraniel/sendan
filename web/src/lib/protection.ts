// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * What actually protected a file.
 *
 * Every value here is read from what was used rather than written down, which
 * is the difference between a report and a label. A card that named AES-256-GCM
 * because somebody typed it would keep naming it after the code stopped using
 * it, and would be worth less than nothing: a reassurance that cannot become
 * wrong is a reassurance that means nothing.
 *
 * It reports what the delivered client code did. That is a transparency measure
 * for an instance behaving itself, and not a defence against one that is not -
 * a hostile instance serves the code that draws this card. See {@link CAVEAT},
 * which must accompany it wherever it is shown.
 */

import { FILE_KEY_SIZE, type PasswordParams, RECORD_SIZE } from "../crypto/index.js";
import type { UploadMetadata } from "./download.js";

/**
 * The sentence the card cannot be shown without.
 *
 * Kept here rather than in markup so it is one thing to review, and so a second
 * place that shows this cannot quietly omit it.
 */
export const CAVEAT =
  "This describes what the code running in this tab did. That code came from " +
  "this instance, so it is a report from a well-behaved instance rather than " +
  "proof against a hostile one. The command line client is the reliable " +
  "trust anchor; the threat model explains why.";

export interface ContentProtection {
  cipher: string;
  keyBits: number;
  framing: string;
  recordBytes: number;
}

export interface PasswordProtection {
  /** Argon2id. The scheme fixes it; see the note on {@link describePassword}. */
  function: string;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  saltBits: number;
}

export interface LifetimeProtection {
  /** Absent means the upload does not expire on a deadline. */
  expiresAt: Date | null;
  /** Absent means no limit. */
  downloadsRemaining: number | null;
  /** Whether the sender can remove it early. */
  revocable: boolean;
}

export interface Protection {
  content: ContentProtection;
  keySchedule: string;
  wrapping: string;
  /** Null when no password contributed to the key. */
  password: PasswordProtection | null;
  metadataEncrypted: boolean;
  lifetime: LifetimeProtection;
  /**
   * Which endpoints carried it. Compatibility uploads use a weaker,
   * server-enforced password model and must say so (`docs/design.md` §5).
   */
  endpoints: "native" | "compatibility";
}

/**
 * The content encoding, described from the constants it actually uses.
 *
 * Sourced from the crypto module rather than restated, so a change to the key
 * size or the record size changes what the card says.
 */
function describeContent(): ContentProtection {
  return {
    cipher: "AES-GCM",
    keyBits: FILE_KEY_SIZE * 8,
    framing: "RFC 8188 encrypted-content-encoding",
    recordBytes: RECORD_SIZE,
  };
}

/**
 * The password stretching, from the parameters that were used.
 *
 * Not from the defaults. They are stored per upload so they can be raised
 * later, so an old link opened by a new client is protected by the parameters
 * it was created with - and saying otherwise would overstate it.
 *
 * There is one function and no choice of function. The wire format fixes
 * Argon2id (spec §4), and it must: a client that accepted a key derivation
 * function named in metadata would be a client whose password strength the
 * instance could weaken by naming a weaker one.
 */
export function describePassword(params: PasswordParams): PasswordProtection {
  return {
    function: "Argon2id",
    memoryKiB: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    saltBits: params.salt.length * 8,
  };
}

export interface UploadProtectionInput {
  password: PasswordParams | null;
  expiresAt?: Date | null | undefined;
  maxDownloads?: number | null | undefined;
  endpoints?: "native" | "compatibility";
}

/** What protected a file this client has just sent. */
export function describeUpload(input: UploadProtectionInput): Protection {
  return {
    content: describeContent(),
    keySchedule: "HKDF-SHA256",
    wrapping: "AES-256-GCM",
    password: input.password === null ? null : describePassword(input.password),
    metadataEncrypted: true,
    lifetime: {
      expiresAt: input.expiresAt ?? null,
      // Zero means no limit, and must not be shown as "0 downloads remaining".
      downloadsRemaining:
        input.maxDownloads === undefined || input.maxDownloads === null || input.maxDownloads === 0
          ? null
          : input.maxDownloads,
      revocable: true,
    },
    endpoints: input.endpoints ?? "native",
  };
}

/**
 * What protects a file this client is about to receive.
 *
 * Taken from what the instance published and this client then used, so a
 * password-protected upload reports the parameters its own derivation ran with.
 */
export function describeDownload(
  metadata: UploadMetadata,
  endpoints: "native" | "compatibility" = "native",
): Protection {
  return {
    content: describeContent(),
    keySchedule: "HKDF-SHA256",
    wrapping: "AES-256-GCM",
    // passwordRequired without parameters cannot occur: parsing refuses it,
    // because it is an upload nobody could open.
    password: metadata.kdf === null ? null : describePassword(metadata.kdf),
    metadataEncrypted: true,
    lifetime: {
      expiresAt: metadata.expiresAt,
      downloadsRemaining: metadata.downloadsRemaining,
      // The sender holds the owner token; a recipient does not.
      revocable: false,
    },
    endpoints,
  };
}

/** One line per fact, for an interface that shows them as a list. */
export interface ProtectionLine {
  label: string;
  value: string;
  /** A caution about this line specifically, where one is warranted. */
  caution?: string;
}

/**
 * Counts a thing.
 *
 * The plural is given rather than guessed. Appending "s" turned one pass into
 * "5 passs", which is the sort of thing that makes a careful report look
 * careless - and the report is the whole point here.
 */
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const capitalise = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);

/**
 * The card, as lines.
 *
 * Built here rather than in markup so the wording is one thing to review and
 * cannot differ between the two places it is shown.
 */
export function protectionLines(protection: Protection): ProtectionLine[] {
  const lines: ProtectionLine[] = [
    {
      label: "Content",
      value:
        `${protection.content.cipher} with a ${protection.content.keyBits}-bit key, ` +
        `in ${protection.content.framing} records of ${protection.content.recordBytes} bytes`,
    },
    { label: "Key derivation", value: protection.keySchedule },
    { label: "File key", value: `wrapped with ${protection.wrapping}` },
    {
      label: "Password",
      value:
        protection.password === null
          ? "None. Anyone with the link can open this file."
          : `${protection.password.function}, ` +
            `${protection.password.memoryKiB} KiB memory, ` +
            `${plural(protection.password.iterations, "pass", "passes")}, ` +
            `parallelism ${protection.password.parallelism}, ` +
            `${protection.password.saltBits}-bit salt`,
    },
    {
      label: "Filename and size",
      value: protection.metadataEncrypted
        ? "Encrypted and padded. The instance cannot read either."
        : "Not encrypted. The instance can read both.",
    },
  ];

  // Revocability is not an expiry condition and is kept out of the list. Folded
  // in, it produced "can be deleted with the management secret. Whichever comes
  // first removes it." for an upload that has no deadline and no limit - a
  // sentence that is both ungrammatical and untrue.
  const conditions: string[] = [];
  if (protection.lifetime.expiresAt !== null) {
    conditions.push(`expires ${protection.lifetime.expiresAt.toLocaleString()}`);
  }
  if (protection.lifetime.downloadsRemaining !== null) {
    conditions.push(`${plural(protection.lifetime.downloadsRemaining, "download")} remaining`);
  }

  let lifetime: string;
  if (conditions.length === 0) {
    lifetime = "No deadline and no download limit.";
  } else if (conditions.length === 1) {
    lifetime = `${capitalise(conditions[0] as string)}.`;
  } else {
    // Only with more than one condition is there a "first" to come.
    lifetime = `${capitalise(conditions.join("; "))}. Whichever comes first removes it.`;
  }
  if (protection.lifetime.revocable) {
    lifetime += " The sender can delete it earlier with the management secret.";
  }
  lines.push({ label: "Lifetime", value: lifetime });

  lines.push({
    label: "Endpoints",
    value: protection.endpoints === "native" ? "Native" : "Third-party compatibility",
    // Not a footnote. An upload made through the compatibility endpoints is
    // protected by a weaker, server-enforced password model, and an interface
    // that showed it beside a native one without saying so would be claiming
    // protection the file does not have.
    ...(protection.endpoints === "compatibility"
      ? {
          caution:
            "These use another protocol's password model, which the instance " +
            "enforces rather than the key. This file is less protected than a " +
            "native upload.",
        }
      : {}),
  });

  return lines;
}
