// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The plain-language list, checked for the thing that makes it worth having:
 * that it never claims more than it can establish.
 */

import { describe, expect, it } from "vitest";
import { assurances, type Protection } from "./protection.js";

/** A native upload with a password, a deadline and encrypted metadata. */
const strong: Protection = {
  content: {
    cipher: "AES-GCM",
    keyBits: 256,
    framing: "RFC 8188 encrypted-content-encoding",
    recordBytes: 65536,
  },
  keySchedule: "HKDF-SHA256",
  wrapping: "AES-KW",
  password: {
    function: "Argon2id",
    memoryKiB: 65536,
    iterations: 3,
    parallelism: 1,
    saltBits: 128,
  },
  metadataEncrypted: true,
  lifetime: {
    expiresAt: new Date("2026-01-01T00:00:00Z"),
    downloadsRemaining: 3,
    revocable: false,
  },
  endpoints: "native",
};

const claim = (list: ReturnType<typeof assurances>, needle: string) => {
  const found = list.find((a) => a.claim.includes(needle));
  if (!found) throw new Error(`no claim matching ${needle}: ${list.map((a) => a.claim)}`);
  return found;
};

describe("every line", () => {
  const list = assurances(strong, true);

  it("says why, whether it holds or not", () => {
    // A mark without a reason is a claim, and this list exists to replace
    // claims with facts.
    for (const item of list) {
      expect(item.because.length, item.claim).toBeGreaterThan(20);
    }
  });

  it("is a claim somebody could act on, not a parameter", () => {
    for (const item of list) {
      expect(item.claim).not.toMatch(/AES|Argon2|HKDF|\d+-bit/);
    }
  });
});

describe("a native upload", () => {
  const list = assurances(strong, true);

  it("says the instance cannot read it", () => {
    expect(claim(list, "instance cannot read").holds).toBe(true);
  });

  it("counts a password as protection", () => {
    const password = claim(list, "Protected with a password");
    expect(password.holds).toBe(true);
    expect(password.because).toContain("part of the key");
  });
});

describe("a compatibility upload", () => {
  // The case the whole list exists for: it must say no, in words, rather than
  // leaving the difference buried in the parameters.
  const list = assurances({ ...strong, endpoints: "compatibility" }, true);

  it("does not claim the instance is unable to serve it", () => {
    const readable = claim(list, "instance cannot read");
    expect(readable.holds).toBe(false);
    expect(readable.because).toContain("does not know the password");
  });

  it("still counts the password, but says who checks it", () => {
    const password = claim(list, "Protected with a password");
    expect(password.holds).toBe(true);
    expect(password.because).toContain("Checked by the instance");
  });
});

describe("an upload with nothing set", () => {
  const bare = assurances(
    {
      ...strong,
      password: null,
      metadataEncrypted: false,
      lifetime: { expiresAt: null, downloadsRemaining: null, revocable: false },
    },
    true,
  );

  it("says plainly that anyone with the link can open it", () => {
    const password = claim(bare, "Protected with a password");
    expect(password.holds).toBe(false);
    expect(password.because).toContain("anyone holding the link");
  });

  it("says nothing will remove it", () => {
    const removed = claim(bare, "Removed on its own");
    expect(removed.holds).toBe(false);
    expect(removed.because).toContain("until somebody does");
  });

  it("says the instance can read the filename", () => {
    expect(claim(bare, "Filename and size").holds).toBe(false);
  });
});

describe("the connection", () => {
  it("is reported as it is, not as it should be", () => {
    const insecure = claim(assurances(strong, false), "encrypted connection");
    expect(insecure.holds).toBe(false);
    // The consequence, not just the fact: without transport encryption the
    // code doing the decryption is what could have been replaced.
    expect(insecure.because).toContain("could have been altered");

    expect(claim(assurances(strong, true), "encrypted connection").holds).toBe(true);
  });
});

describe("quantum resistance", () => {
  // Shown as satisfied, which is the honest answer: the design is symmetric
  // only, so there is nothing for Shor's algorithm to attack, and the secrets
  // are sized for Grover's (docs/design.md §2.4).
  const quantum = claim(assurances(strong, true), "quantum computer");

  it("holds", () => {
    expect(quantum.holds).toBe(true);
  });

  it("says what makes it hold, since no post-quantum algorithm is involved", () => {
    // Without the reason, the line invites the assumption that one is - which
    // would be the list making a claim it cannot support.
    expect(quantum.because).toContain("negotiated");
    expect(quantum.because).toContain("256");
  });
});
