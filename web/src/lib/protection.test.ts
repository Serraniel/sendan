// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_ITERATIONS,
  DEFAULT_MEMORY_KIB,
  FILE_KEY_SIZE,
  newPasswordParams,
  type PasswordParams,
  RECORD_SIZE,
} from "../crypto/index.js";
import type { UploadMetadata } from "./download.js";
import {
  CAVEAT,
  describeDownload,
  describePassword,
  describeUpload,
  protectionLines,
} from "./protection.js";

const params = (over: Partial<PasswordParams> = {}): PasswordParams => ({
  ...newPasswordParams(),
  ...over,
});

const metadata = (over: Partial<UploadMetadata> = {}): UploadMetadata =>
  ({
    id: "AAAAAAAAAAAAAAAAAAAAAA",
    wrappedFileKey: new Uint8Array(48),
    wrapNonce: new Uint8Array(12),
    metadataEnvelope: new Uint8Array(272),
    metadataNonce: new Uint8Array(12),
    passwordRequired: false,
    kdf: null,
    expiresAt: null,
    downloadsRemaining: null,
    ...over,
  }) as UploadMetadata;

const lineFor = (lines: ReturnType<typeof protectionLines>, label: string) =>
  lines.find((line) => line.label === label)?.value ?? "";

describe("what the card reports", () => {
  /**
   * The property the whole card depends on. Values are read from what was used,
   * not written down: a card that named a key size because somebody typed it
   * would keep naming it after the code stopped using it, and a reassurance
   * that cannot become wrong means nothing.
   */
  it("takes the content parameters from the code, not from prose", () => {
    const lines = protectionLines(describeUpload({ password: null }));
    const content = lineFor(lines, "Content");

    expect(content).toContain(`${FILE_KEY_SIZE * 8}-bit key`);
    expect(content).toContain(`${RECORD_SIZE} bytes`);
  });

  /**
   * The assertion above cannot fail if the numbers are written out, because a
   * literal 256 and FILE_KEY_SIZE * 8 are the same value - so both survive
   * replacing one with the other. The rule is about the source, and is checked
   * against the source, the way scripts/audit-assets.sh checks the built
   * client for things no behaviour can distinguish.
   *
   * Without this, a card could be pinned to numbers that were true when
   * somebody typed them, which is the one thing a transparency report must not
   * be.
   */
  it("derives them, rather than restating them", () => {
    const source = readFileSync(new URL("./protection.ts", import.meta.url), "utf8");
    const body = source.slice(
      source.indexOf("function describeContent"),
      source.indexOf("\n}", source.indexOf("function describeContent")),
    );

    expect(body, "describeContent was not found").not.toBe("");
    expect(body).toContain("FILE_KEY_SIZE");
    expect(body).toContain("RECORD_SIZE");
    // The values themselves must not appear: writing them out is exactly the
    // mutation the behavioural test cannot see.
    expect(body).not.toMatch(/\b256\b/);
    expect(body).not.toMatch(/\b65536\b/);
  });

  /**
   * Not the defaults. The parameters are stored per upload so they can be
   * raised later, so an old link opened by a new client is protected by the
   * ones it was created with - and saying otherwise would overstate it.
   */
  it("reports the password parameters that were used, not the current defaults", () => {
    const older = params({ memoryKiB: 16 * 1024, iterations: 1, parallelism: 2 });
    const described = describePassword(older);

    expect(described).toMatchObject({
      function: "Argon2id",
      memoryKiB: 16 * 1024,
      iterations: 1,
      parallelism: 2,
      saltBits: 128,
    });
    // The defaults have moved on, and the card must not claim them.
    expect(described.memoryKiB).not.toBe(DEFAULT_MEMORY_KIB);
    expect(described.iterations).not.toBe(DEFAULT_ITERATIONS);

    const shown = lineFor(protectionLines(describeUpload({ password: older })), "Password");
    expect(shown).toContain("16384 KiB");
    expect(shown).toContain("1 pass");
    expect(shown).not.toContain(`${DEFAULT_MEMORY_KIB} KiB`);
  });

  it("reports a download's parameters from what the instance published", () => {
    const kdf = params({ memoryKiB: 262_144, iterations: 5, parallelism: 4 });
    const shown = lineFor(
      protectionLines(describeDownload(metadata({ passwordRequired: true, kdf }))),
      "Password",
    );

    expect(shown).toContain("262144 KiB");
    expect(shown).toContain("5 passes");
    expect(shown).toContain("parallelism 4");
  });

  /**
   * The absence of a password is the thing most worth stating plainly. A card
   * that simply omitted the line would let "no password" read as "protected".
   */
  it("says plainly when there is no password", () => {
    for (const protection of [describeUpload({ password: null }), describeDownload(metadata())]) {
      const shown = lineFor(protectionLines(protection), "Password");
      expect(shown).toContain("None");
      expect(shown.toLowerCase()).toContain("anyone with the link");
    }
  });

  it("describes the lifetime that is actually in force", () => {
    const deadline = new Date("2026-08-09T10:00:00Z");

    const limited = lineFor(
      protectionLines(describeUpload({ password: null, expiresAt: deadline, maxDownloads: 3 })),
      "Lifetime",
    );
    expect(limited).toContain("3 downloads remaining");
    expect(limited).toContain("Whichever comes first");

    const unlimited = lineFor(protectionLines(describeDownload(metadata())), "Lifetime");
    expect(unlimited).toContain("No deadline and no download limit");
  });

  /**
   * Zero means no limit in the wire format. Shown as a number it would read as
   * an upload that can never be downloaded, which is the opposite of the truth.
   */
  it("does not show an unlimited upload as having no downloads left", () => {
    for (const maxDownloads of [0, null, undefined]) {
      const shown = lineFor(
        protectionLines(describeUpload({ password: null, maxDownloads })),
        "Lifetime",
      );
      expect(shown, `${maxDownloads}`).not.toContain("0 downloads");
      expect(shown, `${maxDownloads}`).toContain("No deadline and no download limit");
    }
  });

  it("counts in singulars where there is one", () => {
    const one = lineFor(
      protectionLines(describeUpload({ password: null, maxDownloads: 1 })),
      "Lifetime",
    );
    expect(one).toContain("1 download remaining");
    expect(one).not.toContain("1 downloads");

    const once = lineFor(
      protectionLines(describeUpload({ password: params({ iterations: 1 }) })),
      "Password",
    );
    expect(once).toContain("1 pass,");
  });

  /**
   * A recipient cannot remove an upload - the owner token is the sender's - so
   * the card must not offer them a control they do not have.
   */
  it("offers deletion only to the sender", () => {
    expect(lineFor(protectionLines(describeUpload({ password: null })), "Lifetime")).toContain(
      "management secret",
    );
    expect(
      lineFor(protectionLines(describeDownload(metadata({ downloadsRemaining: 2 }))), "Lifetime"),
    ).not.toContain("management secret");
  });
});

describe("compatibility uploads", () => {
  /**
   * These use another protocol's server-enforced password model, so they are
   * genuinely less protected. Showing one beside a native upload without saying
   * so would claim protection the file does not have (`docs/design.md` §5).
   */
  it("are marked, and carry the caution with them", () => {
    const line = protectionLines(
      describeUpload({ password: null, endpoints: "compatibility" }),
    ).find((l) => l.label === "Endpoints");

    expect(line?.value).toContain("compatibility");
    expect(line?.caution).toBeDefined();
    expect(line?.caution).toContain("less protected");
  });

  it("are not what a native upload is marked as", () => {
    const line = protectionLines(describeUpload({ password: null })).find(
      (l) => l.label === "Endpoints",
    );

    expect(line?.value).toBe("Native");
    // No caution where there is nothing to caution about; a warning on every
    // upload is a warning nobody reads.
    expect(line?.caution).toBeUndefined();
  });
});

describe("the caveat", () => {
  /**
   * The card reports what the delivered client code did, and that code came
   * from the instance being reported on. Stating it is the difference between a
   * transparency measure and a claim the design cannot support.
   */
  it("says the report comes from code the instance served", () => {
    expect(CAVEAT).toMatch(/came from\s+this instance/);
    expect(CAVEAT).toContain("command line client");
    expect(CAVEAT).toContain("threat model");
  });

  it("does not claim to prove anything", () => {
    for (const overclaim of ["guarantee", "proves", "verified", "certified"]) {
      expect(CAVEAT.toLowerCase(), overclaim).not.toContain(overclaim);
    }
  });
});

describe("every line", () => {
  it("has a label and something to say", () => {
    for (const protection of [
      describeUpload({ password: null }),
      describeUpload({ password: params(), expiresAt: new Date(), maxDownloads: 2 }),
      describeDownload(metadata()),
      describeDownload(metadata({ passwordRequired: true, kdf: params(), downloadsRemaining: 1 })),
    ]) {
      const lines = protectionLines(protection);
      expect(lines.length).toBeGreaterThan(4);
      for (const line of lines) {
        expect(line.label.length, JSON.stringify(line)).toBeGreaterThan(0);
        expect(line.value.length, JSON.stringify(line)).toBeGreaterThan(3);
      }
    }
  });
});
