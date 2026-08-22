// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { BANNER_KEY, type BannerStore, digest, markSeen, unseen } from "./banner.js";

function fakeStore(initial: Record<string, string> = {}) {
  const data = { ...initial };
  return {
    data,
    getItem: (k: string) => data[k] ?? null,
    setItem: (k: string, v: string) => {
      data[k] = v;
    },
  };
}

const hostile: BannerStore = {
  getItem() {
    throw new DOMException("denied", "SecurityError");
  },
  setItem() {
    throw new DOMException("denied", "SecurityError");
  },
};

describe("showing a notice", () => {
  it("shows one nobody has dismissed", () => {
    expect(unseen("Maintenance on Friday", fakeStore())).toBe(true);
  });

  it("stops showing one that was dismissed", () => {
    const store = fakeStore();
    markSeen("Maintenance on Friday", store);
    expect(unseen("Maintenance on Friday", store)).toBe(false);
  });

  it("shows a changed notice again", () => {
    // The reason a digest is stored rather than a flag: a flag saying
    // "dismissed" would silence every future notice, including the one that
    // matters.
    const store = fakeStore();
    markSeen("Maintenance on Friday", store);
    expect(unseen("Shutting down on Monday", store)).toBe(true);
  });

  it("shows it when storage refuses to answer", () => {
    // Showing a notice twice is better than never showing one.
    expect(unseen("anything", hostile)).toBe(true);
    expect(unseen("anything", null)).toBe(true);
  });

  it("does not throw when storage refuses to be written", () => {
    expect(() => markSeen("anything", hostile)).not.toThrow();
    expect(() => markSeen("anything", null)).not.toThrow();
  });

  it("finds storage for itself when none is passed", () => {
    // The path the interface actually takes: every other test here hands in a
    // store, so without this the lookup is never exercised. There is no
    // localStorage in this environment, which is the same situation as a
    // browser that has taken it away.
    expect(unseen("anything")).toBe(true);
    expect(() => markSeen("anything")).not.toThrow();
  });
});

describe("the stored value", () => {
  it("is a digest rather than the operator's words", () => {
    const store = fakeStore();
    markSeen("Shutting down on Monday", store);

    const stored = store.data[BANNER_KEY] ?? "";
    expect(stored).not.toContain("Shutting");
    expect(stored.length).toBeLessThan(16);
  });

  it("is stable for the same text and different for different text", () => {
    expect(digest("one")).toBe(digest("one"));
    expect(digest("one")).not.toBe(digest("two"));
    // Whitespace is trimmed upstream, so these are genuinely different notices.
    expect(digest("a")).not.toBe(digest("a "));
  });

  it("survives text a hash written carelessly would choke on", () => {
    for (const text of ["", "🙂 unicode", "x".repeat(10000)]) {
      expect(typeof digest(text)).toBe("string");
      expect(digest(text).length).toBeGreaterThan(0);
    }
  });
});
