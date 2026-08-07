// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { isFatal, missingCapabilities, type Platform } from "./capabilities.js";

/** A browser that can do everything. Fields are removed from this, not added to it. */
const capable = (): Platform => ({
  isSecureContext: true,
  crypto: { subtle: {}, getRandomValues: () => {} },
  TransformStream: () => {},
  ReadableStream: () => {},
  WritableStream: () => {},
  File: { prototype: { stream: () => {} } },
  WebAssembly: {},
});

const codes = (platform: Platform) => missingCapabilities(platform).map((m) => m.code);

describe("a browser that can do it", () => {
  it("is reported as missing nothing", () => {
    expect(missingCapabilities(capable())).toEqual([]);
  });

  /**
   * The check runs on every page load, so it must agree with the browsers the
   * suite actually runs in. If this fails in a real browser, the check is
   * wrong rather than the browser.
   */
  it("includes the one running these tests", () => {
    const here = missingCapabilities();
    // Node has no File.prototype.stream in every version, so only the ones
    // that are genuinely universal are asserted here; the browser test covers
    // the rest.
    expect(here.map((m) => m.code)).not.toContain("webcrypto");
    expect(here.map((m) => m.code)).not.toContain("streams");
  });
});

describe("an insecure context", () => {
  /**
   * The likely case by far, and the operator's to fix. Every browser withholds
   * crypto.subtle outside a secure context, so this is reported alone: listing
   * WebCrypto beside it would say "this browser is too old" about a browser
   * that is fine, and bury the one thing anybody can act on.
   */
  it("is reported alone, whatever else appears missing as a result", () => {
    const insecure: Platform = { ...capable(), isSecureContext: false, crypto: {} };

    expect(codes(insecure)).toEqual(["insecure-context"]);
  });

  it("says whose problem it is and that nothing was sent", () => {
    const [only] = missingCapabilities({ ...capable(), isSecureContext: false });

    expect(only?.remedy).toContain("HTTPS");
    expect(only?.remedy.toLowerCase()).toContain("nothing was sent");
    // Not blamed on the browser: a browser doing this is behaving correctly.
    expect(only?.summary.toLowerCase()).not.toContain("browser");
  });

  it("does not fire where the context is secure or unknown", () => {
    // Undefined rather than false: something that is not a browser, and not a
    // reason to refuse.
    expect(codes({ ...capable(), isSecureContext: undefined })).toEqual([]);
    expect(codes(capable())).toEqual([]);
  });
});

describe("what is missing", () => {
  it("names WebCrypto when it is absent or incomplete", () => {
    expect(codes({ ...capable(), crypto: undefined })).toContain("webcrypto");
    expect(codes({ ...capable(), crypto: {} })).toContain("webcrypto");
    // Present but without a random source is still unusable: keys come from it.
    expect(codes({ ...capable(), crypto: { subtle: {} } })).toContain("webcrypto");
  });

  it("names streams when any of the three is absent", () => {
    for (const absent of ["TransformStream", "ReadableStream", "WritableStream"] as const) {
      const platform = { ...capable(), [absent]: undefined };
      expect(codes(platform), absent).toContain("streams");
    }
  });

  it("names file streams separately from streams", () => {
    // A browser can have the Streams API and still not read a File through it,
    // and the two are fixed by different things.
    const platform: Platform = { ...capable(), File: { prototype: {} } };
    expect(codes(platform)).toEqual(["file-streams"]);
  });

  it("names WebAssembly, and says it only affects passwords", () => {
    const found = missingCapabilities({ ...capable(), WebAssembly: undefined });

    expect(found.map((m) => m.code)).toEqual(["webassembly"]);
    expect(found[0]?.remedy.toLowerCase()).toContain("password");
  });

  it("reports everything missing rather than only the first", () => {
    const bare: Platform = { isSecureContext: true };
    expect(codes(bare)).toEqual(["webcrypto", "streams", "file-streams", "webassembly"]);
  });

  it("gives every one of them something to read", () => {
    for (const found of missingCapabilities({ isSecureContext: true })) {
      expect(found.summary.length, found.code).toBeGreaterThan(20);
      expect(found.remedy.length, found.code).toBeGreaterThan(20);
    }
  });
});

describe("whether it is fatal", () => {
  /**
   * Missing WebAssembly costs password-protected files and nothing else.
   * Refusing to run at all would withhold a service the browser can perform.
   */
  it("is not, for WebAssembly alone", () => {
    expect(isFatal(missingCapabilities({ ...capable(), WebAssembly: undefined }))).toBe(false);
  });

  it("is, for anything else", () => {
    for (const platform of [
      { ...capable(), isSecureContext: false },
      { ...capable(), crypto: {} },
      { ...capable(), TransformStream: undefined },
      { ...capable(), File: { prototype: {} } },
    ] as Platform[]) {
      expect(isFatal(missingCapabilities(platform))).toBe(true);
    }
  });

  it("is not, when nothing is missing", () => {
    expect(isFatal([])).toBe(false);
  });

  it("is, when WebAssembly is missing alongside something that matters", () => {
    expect(isFatal(missingCapabilities({ isSecureContext: true }))).toBe(true);
  });
});
