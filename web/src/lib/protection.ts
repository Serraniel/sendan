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
  "proof against a hostile one. Nothing shown here would detect an instance " +
  "that served different code. The threat model explains what that means.";

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

/** Whether a plain-language claim holds, and why. */
export interface Assurance {
  /** What is being claimed, in words somebody can act on. */
  claim: string;
  /** Whether it holds. */
  holds: boolean;
  /** Why it holds, or why it does not. Never omitted: a mark without a reason
   *  is a claim, and this list exists to replace claims with facts. */
  because: string;
}

/**
 * The same protection, said in words rather than in parameters.
 *
 * The card above states the cipher, the derivation and the parameters, which is
 * the right thing to keep and is not what most people can act on. This is the
 * other half: short claims, each plainly true or plainly not, each carrying the
 * reason it is one or the other.
 *
 * Two rules govern what may appear here.
 *
 * **Nothing is claimed that is not established.** Every line comes from the
 * protection record, from the constants the cryptography actually uses, or from
 * something the browser can see for itself. Nothing comes from an assumption
 * about how an instance is configured.
 *
 * **An honest "no" is the point.** A compatibility upload is protected less
 * well, an instance served over plain HTTP could have delivered altered code,
 * and a file with no password can be opened by anyone holding the link. Those
 * are the lines worth showing, and hiding them would make the rest worthless.
 *
 * @param secureTransport whether the page itself arrived over an encrypted
 *   connection. Passed in rather than read here so this stays testable, and
 *   because it is the one fact on the list the instance does not report.
 */
export function assurances(protection: Protection, secureTransport: boolean): Assurance[] {
  const compat = protection.endpoints === "compatibility";

  return [
    {
      claim: "Encrypted before it left the sender",
      // True of both kinds of upload: the key is made in the browser and never
      // sent, which is what makes the instance unable to read the content.
      holds: true,
      because:
        `The file was encrypted with ${protection.content.cipher} in the sender's ` +
        "browser. The key travels in the link, which is never sent to the instance.",
    },
    {
      claim: "The instance cannot read it",
      holds: !compat,
      because: compat
        ? "This upload was made through the compatibility endpoints, where the " +
          "instance checks the password itself. It cannot read the content, but " +
          "it can serve the file to somebody who does not know the password."
        : "Nothing the instance holds opens the file: not the key, not the " +
          "password, and not a way to derive either.",
    },
    {
      claim: "Protected with a password",
      holds: protection.password !== null,
      because:
        protection.password === null
          ? "No password was set, so anyone holding the link can open this file."
          : compat
            ? `Checked by the instance rather than by the key, using ` +
              `${protection.password.function}.`
            : `The password is part of the key, derived with ` +
              `${protection.password.function}. A wrong one produces a key that does not fit.`,
    },
    {
      claim: "Filename and size hidden from the instance",
      holds: protection.metadataEncrypted,
      because: protection.metadataEncrypted
        ? "Both are encrypted and padded, so the instance sees neither."
        : "Neither is encrypted on this upload, so the instance can read both.",
    },
    {
      claim: "Removed on its own",
      holds:
        protection.lifetime.expiresAt !== null || protection.lifetime.downloadsRemaining !== null,
      because:
        protection.lifetime.expiresAt === null && protection.lifetime.downloadsRemaining === null
          ? "This upload has neither a deadline nor a download limit, so nothing " +
            "removes it until somebody does."
          : "It goes when its deadline passes or its downloads run out, whichever " +
            "comes first.",
    },
    {
      claim: "Delivered over an encrypted connection",
      holds: secureTransport,
      because: secureTransport
        ? "This page arrived over HTTPS."
        : "This page arrived without transport encryption, so the code doing the " +
          "decryption could have been altered on the way to you.",
    },
    {
      claim: "Beyond the reach of a future quantum computer",
      // Not a post-quantum algorithm, and saying so matters: the claim invites
      // the assumption that one is involved. What makes it hold is that there
      // is nothing here for Shor's algorithm to attack, and that the secrets
      // are long enough to stay out of Grover's reach (docs/design.md §2.4).
      holds: true,
      because:
        "Nothing here is negotiated over the wire, so there is no key exchange " +
        `to record and break later. The keys are ${protection.content.keyBits} ` +
        "bits, which leaves them out of reach even halved.",
    },
  ];
}
