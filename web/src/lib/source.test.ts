// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { type Build, fetchBuild, parseBuild, shortCommit, sourceIsExact } from "./source";

const valid = {
  version: "0.1.0",
  commit: "e98f80ced3ab68f139a39fb6e62cf90867b28268",
  modified: false,
  source: "https://github.com/Serraniel/sendan",
  license: "AGPL-3.0-or-later",
};

function respondWith(body: unknown, ok = true): typeof fetch {
  return (async () => ({ ok, json: async () => body })) as unknown as typeof fetch;
}

describe("parseBuild", () => {
  it("accepts a complete report", () => {
    expect(parseBuild(valid)).toEqual(valid);
  });

  // The response comes from the server, which is the party this report is
  // about. A footer rendering `undefined` because a field was missing would be
  // worse than one rendering nothing.
  it.each([
    ["not an object", "nope"],
    ["null", null],
    ["a missing version", { ...valid, version: undefined }],
    ["a missing commit", { ...valid, commit: undefined }],
    ["a missing source", { ...valid, source: undefined }],
    ["a missing licence", { ...valid, license: undefined }],
    ["a numeric version", { ...valid, version: 1 }],
    ["modified as a string", { ...valid, modified: "false" }],
  ])("rejects %s", (_name, value) => {
    expect(parseBuild(value)).toBeNull();
  });
});

describe("fetchBuild", () => {
  it("returns the report", async () => {
    expect(await fetchBuild(respondWith(valid))).toEqual(valid);
  });

  // An instance that cannot answer this should still serve a page that works.
  it("returns null on a failed response", async () => {
    expect(await fetchBuild(respondWith(valid, false))).toBeNull();
  });

  it("returns null when the request throws", async () => {
    const failing = (async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    expect(await fetchBuild(failing)).toBeNull();
  });

  it("returns null on a malformed report", async () => {
    expect(await fetchBuild(respondWith({ version: 1 }))).toBeNull();
  });
});

describe("shortCommit", () => {
  it("shortens a revision to what a person compares", () => {
    expect(shortCommit(valid.commit)).toBe("e98f80c");
  });

  it.each([
    ["", "unknown"],
    ["unknown", "unknown"],
    ["abc", "abc"],
  ])("renders %s as %s", (input, want) => {
    expect(shortCommit(input)).toBe(want);
  });
});

describe("sourceIsExact", () => {
  it("is true for a clean, stamped build", () => {
    expect(sourceIsExact(valid)).toBe(true);
  });

  // A build from a modified tree has no commit that describes it, so no link
  // can be exact. The footer says so, and this is what decides that.
  it("is false for a modified build", () => {
    expect(sourceIsExact({ ...valid, modified: true } as Build)).toBe(false);
  });

  it.each([[""], ["unknown"]])("is false when the commit is %s", (commit) => {
    expect(sourceIsExact({ ...valid, commit } as Build)).toBe(false);
  });
});
