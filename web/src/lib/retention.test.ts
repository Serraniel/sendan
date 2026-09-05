// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { nothingKnown } from "./instance.js";
import {
  defaultDownloads,
  defaultExpiry,
  describeRetention,
  downloadChoices,
  expiryChoices,
  NEVER,
  USE_DEFAULT,
} from "./retention.js";

const policy = {
  ...nothingKnown,
  defaultTtlSeconds: 86400,
  maxTtlSeconds: 7 * 86400,
  allowInfiniteTtl: false,
  defaultMaxDownloads: 0,
};

describe("the lifetimes offered", () => {
  it("marks the instance's default rather than offering it twice", () => {
    // An entry meaning "whatever the instance does" sits beside the lifetime it
    // resolves to, so the list offered the same thing twice - and the two were
    // not interchangeable. The request that asks the instance to decide carries
    // no lifetime, so this side could not say what the file got and reported no
    // deadline for a file that had one.
    const choices = expiryChoices(policy);
    expect(choices.filter((c) => c.value === USE_DEFAULT)).toEqual([]);
    expect(choices.filter((c) => c.label.includes("this instance's default"))).toEqual([
      { value: 86400, label: "1 day (this instance's default)" },
    ]);
  });

  it("offers a default this list does not otherwise carry, in place", () => {
    // Twelve hours is a lifetime an operator may set and this list does not
    // name. It belongs between the two it sits between, as a real number.
    const choices = expiryChoices({ ...policy, defaultTtlSeconds: 12 * 3600 });
    expect(choices.map((c) => c.value)).toEqual([3600, 12 * 3600, 86400, 7 * 86400]);
    expect(choices[1]?.label).toBe("12 hours (this instance's default)");
  });

  it("falls back to asking the instance when it did not say", () => {
    // With nothing published there is no real lifetime to preselect, so the
    // request has to ask - which is the one case the vague entry is for.
    const [first] = expiryChoices(nothingKnown);
    expect(first?.value).toBe(USE_DEFAULT);
    expect(first?.label).toBe("This instance's default");
  });

  it("offers nothing the instance would refuse", () => {
    // Present and then rejected is worse than absent: it invites a choice and
    // takes it back.
    const values = expiryChoices(policy).map((c) => c.value);
    expect(values).toContain(7 * 86400);
    expect(values).not.toContain(30 * 86400);
  });

  it("offers everything when the instance names no maximum", () => {
    const values = expiryChoices({ ...policy, maxTtlSeconds: null }).map((c) => c.value);
    expect(values).toContain(30 * 86400);
  });

  it("offers never only where the instance allows it", () => {
    // The branch the test instance cannot reach: it forbids unlimited
    // retention, so without this the option would never be exercised at all.
    expect(expiryChoices(policy).map((c) => c.value)).not.toContain(NEVER);

    const permissive = expiryChoices({ ...policy, allowInfiniteTtl: true });
    expect(permissive.map((c) => c.value)).toContain(NEVER);
    // Last, because it is the option with the most consequences.
    expect(permissive.at(-1)?.value).toBe(NEVER);
  });
});

describe("where the form starts", () => {
  it("starts on the instance's own default", () => {
    // A number rather than USE_DEFAULT, so the upload carries the lifetime and
    // this side knows the deadline it will get.
    expect(defaultExpiry(policy)).toBe(86400);
  });

  it("asks the instance when it published nothing", () => {
    expect(defaultExpiry(nothingKnown)).toBe(USE_DEFAULT);
  });

  it("asks the instance when its default is longer than it now accepts", () => {
    // An operator can lower the maximum below the default, and the option is
    // then filtered out. Preselecting a value that is not in the list would
    // leave the control showing nothing.
    const narrowed = { ...policy, defaultTtlSeconds: 30 * 86400, maxTtlSeconds: 86400 };
    expect(defaultExpiry(narrowed)).toBe(USE_DEFAULT);
    expect(expiryChoices(narrowed).map((c) => c.value)).not.toContain(30 * 86400);
  });
});

describe("the download limits offered", () => {
  it("starts on the instance's own default", () => {
    // Not the failure the lifetime had - zero means no limit on both sides, so
    // nothing was ever misdescribed - but a list that marks one entry as the
    // default and starts on another is its own small lie.
    expect(defaultDownloads({ ...policy, defaultMaxDownloads: 5 })).toBe(5);
    expect(defaultDownloads({ ...policy, defaultMaxDownloads: null })).toBe(0);
  });

  it("offers a default this list does not otherwise carry, in place", () => {
    const values = downloadChoices({ ...policy, defaultMaxDownloads: 7 }).map((c) => c.value);
    expect(values).toEqual([0, 1, 5, 7, 20, 100]);
  });

  it("marks whichever one the instance applies by default", () => {
    const none = downloadChoices({ ...policy, defaultMaxDownloads: 0 });
    expect(none[0]?.label).toBe("No limit (this instance's default)");

    const one = downloadChoices({ ...policy, defaultMaxDownloads: 1 });
    expect(one[0]?.label).toBe("No limit");
    expect(one[1]?.label).toBe("1 download (this instance's default)");
  });

  it("marks nothing when the instance did not say", () => {
    for (const choice of downloadChoices(nothingKnown)) {
      expect(choice.label).not.toContain("default");
    }
  });
});

describe("describing what was applied", () => {
  it("resolves the default to the instance's own value", () => {
    // Silence was the old answer here, because no deadline had been chosen
    // explicitly.
    const { text } = describeRetention(USE_DEFAULT, 0, policy);
    expect(text).toBe("This upload expires after 1 day.");
  });

  it("says so plainly when nothing will remove the upload", () => {
    const { text, neverRemoved } = describeRetention(NEVER, 0, policy);
    expect(neverRemoved).toBe(true);
    expect(text).toContain("never expires");
    expect(text).toContain("Nothing removes it but you");
  });

  it("does not call it permanent when downloads will still spend it", () => {
    const { text, neverRemoved } = describeRetention(NEVER, 3, policy);
    expect(neverRemoved).toBe(false);
    expect(text).toContain("allows 3 downloads");
    expect(text).toContain("once they are spent");
  });

  it("falls back to the instance's schedule when it named no default", () => {
    const { text } = describeRetention(USE_DEFAULT, 0, nothingKnown);
    expect(text).toBe("This upload expires on the instance's own schedule.");
  });

  it("names both bounds when both apply", () => {
    const { text } = describeRetention(3600, 5, policy);
    expect(text).toBe(
      "This upload expires after 1 hour, and allows 5 downloads. Whichever comes first removes it.",
    );
  });

  it("keeps the singular for one download", () => {
    expect(describeRetention(3600, 1, policy).text).toContain("allows 1 download.");
  });
});
