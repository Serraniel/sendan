// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { canShare, type Sharer, share } from "./share.js";

const link = "https://example.test/d/abc#key";

describe("whether to offer the sheet at all", () => {
  it("does not, where the platform cannot share", () => {
    // Firefox on a desktop, today. Offering a control that does nothing is
    // worse than not offering one: Copy link is already the answer there.
    expect(canShare({ url: link }, {})).toBe(false);
  });

  it("does, where the platform accepts this payload", () => {
    const sharer: Sharer = { share: async () => {}, canShare: () => true };
    expect(canShare({ url: link }, sharer)).toBe(true);
  });

  it("does not, where the platform refuses this payload", () => {
    // Asked with the payload rather than in the abstract: a platform can
    // support sharing and refuse this particular shape.
    const sharer: Sharer = { share: async () => {}, canShare: () => false };
    expect(canShare({ url: link }, sharer)).toBe(false);
  });

  it("accepts a platform that shares without a canShare to ask", () => {
    expect(canShare({ url: link }, { share: async () => {} })).toBe(true);
  });

  it("treats a canShare that throws as a no", () => {
    const sharer: Sharer = {
      share: async () => {},
      canShare: () => {
        throw new TypeError("nope");
      },
    };
    expect(canShare({ url: link }, sharer)).toBe(false);
  });
});

describe("finding the platform for itself", () => {
  // The path the interface actually takes: every other test here hands one in,
  // so without these the lookup is never exercised.
  it("asks the environment when none is passed", () => {
    expect(canShare({ url: link })).toBe(false);
  });

  it("reports unavailable rather than throwing when there is nothing there", async () => {
    expect(await share({ url: link })).toBe("unavailable");
  });
});

describe("what is handed over", () => {
  it("is the link, and nothing beside it", async () => {
    // No warning travels in `text`: it would ride along into whatever message
    // the person is about to send, which puts our sentence in their
    // conversation. The page says it instead.
    let given: ShareData | null = null;
    const sharer: Sharer = {
      share: async (data) => {
        given = data;
      },
      canShare: () => true,
    };

    await share({ url: link }, sharer);
    expect(given).toEqual({ url: link });
  });

  it("carries a title when one is given", async () => {
    let given: ShareData | null = null;
    const sharer: Sharer = {
      share: async (data) => {
        given = data;
      },
    };

    await share({ url: link, title: "a file" }, sharer);
    expect(given).toEqual({ url: link, title: "a file" });
  });
});

describe("closing the sheet without choosing", () => {
  it("is not an error", async () => {
    // The platform rejects with AbortError either way, so a caller cannot tell
    // a person changing their mind from a failure unless this does.
    const sharer: Sharer = {
      share: async () => {
        throw new DOMException("cancelled", "AbortError");
      },
    };
    expect(await share({ url: link }, sharer)).toBe("dismissed");
  });

  it("is told apart from a platform that could not", async () => {
    const sharer: Sharer = {
      share: async () => {
        throw new TypeError("no transport");
      },
    };
    expect(await share({ url: link }, sharer)).toBe("unavailable");
  });

  it("reports unavailable where there is nothing to ask", async () => {
    expect(await share({ url: link }, {})).toBe("unavailable");
  });
});
