// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { fetchMaxUploadSize, formatSize, parseMaxSize, tooLargeMessage } from "./limits.js";

describe("reading the advertised limit", () => {
  it("takes a size in bytes", () => {
    expect(parseMaxSize("1073741824")).toBe(1073741824);
  });

  it("tolerates surrounding space", () => {
    expect(parseMaxSize(" 42 ")).toBe(42);
  });

  it("treats a missing header as no answer", () => {
    expect(parseMaxSize(null)).toBeNull();
  });

  it("treats zero as no answer rather than as a limit", () => {
    // The protocol uses zero for "no limit". Reporting a limit of zero bytes
    // would refuse every file, including the ones the instance would take.
    expect(parseMaxSize("0")).toBeNull();
  });

  it("refuses anything that is not a whole positive number of bytes", () => {
    for (const value of ["-1", "1.5", "lots", "", "1e9999", "0x10"]) {
      expect(parseMaxSize(value), value).toBeNull();
    }
  });
});

describe("asking the instance", () => {
  it("reads the header from an OPTIONS request", async () => {
    let seen: { url: string; method: string | undefined } | null = null;
    const size = await fetchMaxUploadSize({
      fetch: async (url, init) => {
        seen = { url: String(url), method: init?.method };
        return new Response(null, { headers: { "tus-max-size": "500" } });
      },
    });

    expect(size).toBe(500);
    expect(seen).toEqual({ url: "/api/uploads", method: "OPTIONS" });
  });

  it("says nothing rather than failing when the instance cannot be reached", async () => {
    // A page that refused to work because it could not learn a limit would be
    // worse than one that does not know it.
    const size = await fetchMaxUploadSize({
      fetch: async () => {
        throw new TypeError("network");
      },
    });
    expect(size).toBeNull();
  });

  it("says nothing when the instance answers without the header", async () => {
    const size = await fetchMaxUploadSize({ fetch: async () => new Response(null) });
    expect(size).toBeNull();
  });
});

describe("what to tell somebody", () => {
  it("says nothing while the file fits", () => {
    expect(tooLargeMessage(100, 200)).toBeNull();
    expect(tooLargeMessage(200, 200)).toBeNull();
  });

  it("says nothing when there is no limit to compare against", () => {
    expect(tooLargeMessage(Number.MAX_SAFE_INTEGER, null)).toBeNull();
  });

  it("names both sizes, so the next attempt is not a guess", () => {
    const message = tooLargeMessage(2_000_000_000, 1_073_741_824);
    expect(message).toContain("2.0 GB");
    expect(message).toContain("1.1 GB");
  });
});

describe("formatting a size", () => {
  it("stays in bytes below a thousand", () => {
    expect(formatSize(0)).toBe("0 B");
    expect(formatSize(999)).toBe("999 B");
  });

  it("climbs a unit at a time", () => {
    expect(formatSize(1000)).toBe("1.0 kB");
    expect(formatSize(1_500_000)).toBe("1.5 MB");
    expect(formatSize(1_073_741_824)).toBe("1.1 GB");
  });

  it("stops at the largest unit it knows", () => {
    expect(formatSize(10 ** 18)).toBe("1000000.0 TB");
  });
});
