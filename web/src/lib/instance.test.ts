// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { fetchInstancePolicy, formatDuration, nothingKnown, parsePolicy } from "./instance.js";

const full = {
  maxUploadSize: 1073741824,
  defaultTtlSeconds: 86400,
  maxTtlSeconds: 604800,
  allowInfiniteTtl: true,
  requireLimit: true,
  defaultMaxDownloads: 3,
  compatEnabled: false,
  banner: null,
};

describe("reading what an instance says", () => {
  it("takes a complete answer", () => {
    expect(parsePolicy(full)).toEqual(full);
  });

  it("treats anything that is not an object as nothing said", () => {
    for (const value of [null, undefined, 3, "policy", []]) {
      expect(parsePolicy(value)).toEqual(nothingKnown);
    }
  });

  it("treats a field of the wrong type as unsaid rather than coercing it", () => {
    // "3 days" coerced to a number is not a mistake worth passing on to
    // somebody choosing a retention period.
    const policy = parsePolicy({ ...full, maxTtlSeconds: "3 days", requireLimit: "yes" });
    expect(policy.maxTtlSeconds).toBeNull();
    expect(policy.requireLimit).toBeNull();
    // The fields either side of a bad one are still read.
    expect(policy.defaultTtlSeconds).toBe(86400);
  });

  it("keeps a download limit of zero, which means no limit", () => {
    // Unlike the durations, zero is meaningful here, so it must survive.
    expect(parsePolicy({ ...full, defaultMaxDownloads: 0 }).defaultMaxDownloads).toBe(0);
  });

  it("discards a duration of zero, which means nothing was set", () => {
    expect(parsePolicy({ ...full, defaultTtlSeconds: 0 }).defaultTtlSeconds).toBeNull();
  });

  it("discards impossible numbers", () => {
    for (const value of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(parsePolicy({ ...full, maxUploadSize: value }).maxUploadSize).toBeNull();
    }
  });
});

describe("asking the instance", () => {
  it("reads the policy it reports", async () => {
    const policy = await fetchInstancePolicy({
      fetch: async () => new Response(JSON.stringify(full)),
    });
    expect(policy).toEqual(full);
  });

  it("knows nothing when the instance cannot be reached", async () => {
    // A page that refused to work because it could not read a policy would be
    // worse than one that does not know it.
    const policy = await fetchInstancePolicy({
      fetch: async () => {
        throw new TypeError("network");
      },
    });
    expect(policy).toEqual(nothingKnown);
  });

  it("knows nothing when the instance refuses", async () => {
    const policy = await fetchInstancePolicy({
      fetch: async () => new Response("nope", { status: 404 }),
    });
    expect(policy).toEqual(nothingKnown);
  });

  it("knows nothing when the answer is not JSON", async () => {
    const policy = await fetchInstancePolicy({
      fetch: async () => new Response("<html>an error page</html>"),
    });
    expect(policy).toEqual(nothingKnown);
  });
});

describe("an operator's notice", () => {
  it("is read when one is set", () => {
    const policy = parsePolicy({ ...full, banner: { text: "Demo", severity: "warning" } });
    expect(policy.banner).toEqual({ text: "Demo", severity: "warning" });
  });

  it("takes an unrecognised severity as the quiet one", () => {
    // A typo in configuration should not shout at every visitor.
    const policy = parsePolicy({ ...full, banner: { text: "Demo", severity: "catastrophe" } });
    expect(policy.banner?.severity).toBe("info");
  });

  it("is absent when the text is empty or missing", () => {
    for (const banner of [null, {}, { text: "   " }, { severity: "warning" }, "a banner"]) {
      expect(parsePolicy({ ...full, banner }).banner).toBeNull();
    }
  });

  it("does not alter the text it was given", () => {
    // The operator's words reach the interface as written; what stops them
    // being markup is that they are rendered as text, not that they are
    // sanitised here.
    const hostile = "<script>alert(1)</script>";
    expect(parsePolicy({ ...full, banner: { text: hostile } }).banner?.text).toBe(hostile);
  });
});

describe("saying a duration out loud", () => {
  it("uses the largest unit that fits", () => {
    expect(formatDuration(86400)).toBe("1 day");
    expect(formatDuration(604800)).toBe("7 days");
    expect(formatDuration(3600)).toBe("1 hour");
    expect(formatDuration(7200)).toBe("2 hours");
    expect(formatDuration(300)).toBe("5 minutes");
    expect(formatDuration(30)).toBe("30 seconds");
  });

  it("keeps the singular for one", () => {
    expect(formatDuration(60)).toBe("1 minute");
    expect(formatDuration(1)).toBe("1 second");
  });
});
