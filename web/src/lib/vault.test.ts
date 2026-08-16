// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { partition, type StoredUpload } from "./vault";

function record(id: string, createdAt: number, expiresAt: number | null): StoredUpload {
  return {
    id,
    link: `https://files.example.org/d/${id}#secret`,
    ownerToken: "token",
    name: `${id}.bin`,
    size: 1024,
    createdAt,
    expiresAt,
  };
}

describe("what belongs in the list", () => {
  const now = 1_000_000;

  it("keeps uploads that have not expired", () => {
    const { live, expired } = partition([record("a", 1, now + 1)], now);
    expect(live.map((u) => u.id)).toEqual(["a"]);
    expect(expired).toEqual([]);
  });

  // A record naming a file that is gone is worse than a shorter list: it
  // suggests something is still there to send somebody.
  it("drops uploads that have expired", () => {
    const { live, expired } = partition([record("a", 1, now - 1)], now);
    expect(live).toEqual([]);
    expect(expired.map((u) => u.id)).toEqual(["a"]);
  });

  // An upload whose deadline is exactly now has passed it. Off by one here
  // would show a file that the instance has already stopped serving.
  it("treats a deadline of exactly now as expired", () => {
    const { live } = partition([record("a", 1, now)], now);
    expect(live).toEqual([]);
  });

  // An upload with no deadline is bounded by its download count instead, and
  // this side does not know how many are left.
  it("keeps uploads that never expire", () => {
    const { live } = partition([record("a", 1, null)], now);
    expect(live.map((u) => u.id)).toEqual(["a"]);
  });

  it("shows the newest first", () => {
    const { live } = partition(
      [record("older", 1, null), record("newest", 3, null), record("middle", 2, null)],
      now,
    );
    expect(live.map((u) => u.id)).toEqual(["newest", "middle", "older"]);
  });

  it("handles an empty list", () => {
    expect(partition([], now)).toEqual({ live: [], expired: [] });
  });
});
