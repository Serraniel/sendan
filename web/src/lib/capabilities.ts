// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * What this browser must be able to do, checked before anything is attempted.
 *
 * Without this the first thing a person sees on a browser that cannot do it is
 * the exception: "Cannot read properties of undefined (reading 'importKey')".
 * That is what an instance served over plain HTTP produces, on every browser,
 * for every upload - `crypto.subtle` does not exist outside a secure context.
 * It blames the software for the operator's configuration and gives neither of
 * them anything to act on.
 *
 * Nothing here is a fallback. Each of these is required by the scheme, and a
 * browser missing one cannot encrypt or decrypt at all. The capabilities that
 * *do* have fallbacks - the file picker, the service worker - are detected
 * where they are used and are deliberately not part of this.
 */

/** One thing the browser cannot do, and what that means. */
export interface MissingCapability {
  /** Stable, for branching. */
  code: "insecure-context" | "webcrypto" | "streams" | "file-streams" | "webassembly";
  /** What is missing, for a person. */
  summary: string;
  /** Whose problem it is, and what would fix it. */
  remedy: string;
}

/**
 * The subset of the platform this checks. Substituted in tests.
 *
 * Every field admits undefined explicitly, because that is the state being
 * looked for: a browser that lacks one of these has the property absent, and
 * exactOptionalPropertyTypes would otherwise make the absent case unwritable.
 */
export interface Platform {
  isSecureContext?: boolean | undefined;
  crypto?: { subtle?: unknown; getRandomValues?: unknown } | undefined;
  TransformStream?: unknown;
  ReadableStream?: unknown;
  WritableStream?: unknown;
  File?: { prototype?: { stream?: unknown } | undefined } | undefined;
  WebAssembly?: unknown;
}

/**
 * Everything this browser cannot do, in the order worth reading.
 *
 * An insecure context comes first and stands alone: it is the cause of the
 * WebCrypto check failing too, and reporting both would bury the one that can
 * be acted on under one that cannot.
 */
export function missingCapabilities(
  platform: Platform = globalThis as Platform,
): MissingCapability[] {
  const missing: MissingCapability[] = [];

  // Checked first and returned alone. Every browser withholds crypto.subtle
  // outside a secure context, so the WebCrypto check below would also fail and
  // would say "this browser is too old" about a browser that is fine.
  if (platform.isSecureContext === false) {
    return [
      {
        code: "insecure-context",
        summary: "This page is not being served over a secure connection.",
        remedy:
          "Browsers withhold the cryptography this needs outside a secure " +
          "context, so nothing can be encrypted here. Whoever runs this " +
          "instance has to serve it over HTTPS. Nothing was sent.",
      },
    ];
  }

  if (
    typeof platform.crypto?.subtle !== "object" ||
    typeof platform.crypto?.getRandomValues !== "function"
  ) {
    missing.push({
      code: "webcrypto",
      summary: "This browser does not offer the cryptography this needs.",
      remedy:
        "Files are encrypted here, in this tab, using WebCrypto. A browser " +
        "without it cannot send or receive a file at all.",
    });
  }

  if (
    typeof platform.TransformStream !== "function" ||
    typeof platform.ReadableStream !== "function" ||
    typeof platform.WritableStream !== "function"
  ) {
    missing.push({
      code: "streams",
      summary: "This browser does not support streams.",
      remedy:
        "Files are encrypted and decrypted as they move, rather than being " +
        "held whole. Without streams a file of any size would have to fit in " +
        "this tab, and the code that does the work cannot run.",
    });
  }

  if (typeof platform.File?.prototype?.stream !== "function") {
    missing.push({
      code: "file-streams",
      summary: "This browser cannot read a file as a stream.",
      remedy: "A file has to be read piece by piece in order to be encrypted piece by piece.",
    });
  }

  if (typeof platform.WebAssembly !== "object") {
    missing.push({
      code: "webassembly",
      summary: "This browser does not support WebAssembly.",
      remedy:
        "Only password-protected files need it: the password stretching has " +
        "no equivalent in WebCrypto. Files without a password are unaffected.",
    });
  }

  return missing;
}

/**
 * Whether what is missing stops everything, or only passwords.
 *
 * WebAssembly is the one degradation worth allowing. Without it a
 * password-protected file cannot be opened, and everything else works - so
 * refusing to run at all would withhold a service the browser can perform.
 */
export function isFatal(missing: MissingCapability[]): boolean {
  return missing.some((m) => m.code !== "webassembly");
}
