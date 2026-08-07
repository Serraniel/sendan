// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { FILE_ID_SIZE, LINK_SECRET_SIZE, newFileID, newLinkSecret } from "../crypto/index.js";
import { downloadLink, fragmentIsPresent, fromBase64Url, parseLink, toBase64Url } from "./link.js";

const fileID = () => new Uint8Array(FILE_ID_SIZE).fill(0xab);
const linkSecret = () => new Uint8Array(LINK_SECRET_SIZE).fill(0xcd);

describe("base64url", () => {
  /**
   * The expected text is written out rather than produced by the encoder. A
   * self-consistent wrong alphabet round trips here and is rejected by the
   * server, which is the failure this exists to prevent.
   */
  it("uses the URL alphabet and no padding", () => {
    // 0xfb 0xff 0xfe covers both substituted characters; three bytes encode to
    // four characters, so a fourth byte forces padding that must be stripped.
    expect(toBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]))).toBe("-__-");
    expect(toBase64Url(new Uint8Array([0xfb, 0xff, 0xfe, 0x01]))).toBe("-__-AQ");
    expect(toBase64Url(new Uint8Array([0x00]))).toBe("AA");
  });

  it("round trips arbitrary bytes", () => {
    for (let length = 1; length <= 40; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(fromBase64Url(toBase64Url(bytes)), `${length} bytes`).toEqual(bytes);
    }
  });

  it("refuses what is not this alphabet", () => {
    // Padding and the standard alphabet included on purpose: accepting them
    // would mean accepting a link some other implementation produced wrongly,
    // and the failure would surface as a file that will not decrypt.
    for (const text of ["", "a b", "a+b", "a/b", "AA==", "…", "AA\n"]) {
      expect(fromBase64Url(text), JSON.stringify(text)).toBeNull();
    }
  });
});

describe("building a link", () => {
  it("puts the identifier in the path and the secret in the fragment", () => {
    const link = downloadLink("https://send.example", fileID(), linkSecret());
    expect(link).toBe(
      `https://send.example/d/${toBase64Url(fileID())}#${toBase64Url(linkSecret())}`,
    );
  });

  /**
   * Spec §10 fixes these lengths. A person comparing what they pasted against
   * what they were given counts characters, and a 22/43 split is the check.
   */
  it("is 22 characters of identifier and 43 of secret", () => {
    const link = downloadLink("https://send.example", newFileID(), newLinkSecret());
    const [path, fragment] = link.split("#") as [string, string];
    expect(path.slice(path.lastIndexOf("/") + 1)).toHaveLength(22);
    expect(fragment).toHaveLength(43);
  });

  /**
   * The secret must never reach the server, so it must never be anywhere a
   * browser transmits. Everything before the fragment is sent on every request.
   */
  it("puts nothing secret in the part a browser sends", () => {
    const secret = newLinkSecret();
    const link = downloadLink("https://send.example", newFileID(), secret);
    const transmitted = link.slice(0, link.indexOf("#"));

    expect(transmitted).not.toContain(toBase64Url(secret));
    for (let i = 0; i + 8 <= secret.length; i++) {
      expect(transmitted, `bytes ${i}..${i + 8}`).not.toContain(
        toBase64Url(secret.subarray(i, i + 8)),
      );
    }
  });

  it("does not double the separator on an origin with a trailing slash", () => {
    expect(downloadLink("https://send.example/", fileID(), linkSecret())).toBe(
      downloadLink("https://send.example", fileID(), linkSecret()),
    );
  });

  it("refuses material of the wrong size", () => {
    expect(() => downloadLink("https://x", new Uint8Array(15), linkSecret())).toThrow(TypeError);
    expect(() => downloadLink("https://x", fileID(), new Uint8Array(31))).toThrow(TypeError);
  });
});

describe("parsing a link", () => {
  it("recovers what was built", () => {
    const id = newFileID();
    const secret = newLinkSecret();
    expect(parseLink(downloadLink("https://send.example", id, secret))).toEqual({
      fileID: id,
      linkSecret: secret,
    });
  });

  it("recovers it whatever the origin", () => {
    const id = newFileID();
    const secret = newLinkSecret();
    for (const origin of ["http://localhost:8080", "https://a.b.example:443"]) {
      expect(parseLink(downloadLink(origin, id, secret)), origin).toEqual({
        fileID: id,
        linkSecret: secret,
      });
    }
  });

  /**
   * The failure this whole module is written around: a link that lost its
   * fragment is still a well-formed URL to a real page. Parsing it as though it
   * were whole would derive keys from a truncated secret and report the file as
   * corrupt, which sends the person holding it to look in the wrong place.
   */
  it("refuses a link whose fragment was lost", () => {
    const whole = downloadLink("https://send.example", newFileID(), newLinkSecret());

    const withoutFragment = whole.slice(0, whole.indexOf("#"));
    const withEmptyFragment = `${withoutFragment}#`;
    const truncatedSecret = whole.slice(0, whole.length - 5);

    expect(parseLink(withoutFragment)).toBeNull();
    expect(parseLink(withEmptyFragment)).toBeNull();
    expect(parseLink(truncatedSecret)).toBeNull();
  });

  it("refuses a link whose identifier was damaged", () => {
    const whole = downloadLink("https://send.example", newFileID(), newLinkSecret());
    const hash = whole.indexOf("#");
    expect(parseLink(whole.slice(0, hash - 3) + whole.slice(hash))).toBeNull();
  });

  it("refuses what is not a download link", () => {
    for (const text of [
      "",
      "not a url",
      "https://send.example/",
      "https://send.example/d/#AAAA",
      `https://send.example/upload#${toBase64Url(linkSecret())}`,
      `https://send.example/d/x/y#${toBase64Url(linkSecret())}`,
    ]) {
      expect(parseLink(text), JSON.stringify(text)).toBeNull();
    }
  });
});

describe("telling someone what is wrong", () => {
  /**
   * Separate from parsing so an interface can say which half failed. "The
   * secret is missing from this link" is something the person holding it can
   * act on; "invalid link" is not.
   */
  it("distinguishes a lost fragment from a damaged one", () => {
    const whole = downloadLink("https://send.example", newFileID(), newLinkSecret());

    expect(fragmentIsPresent(whole)).toBe(true);
    expect(fragmentIsPresent(whole.slice(0, whole.indexOf("#")))).toBe(false);
    expect(fragmentIsPresent(`${whole.slice(0, whole.indexOf("#"))}#`)).toBe(false);
    // Damaged but present: parsing rejects this, and the reason is different.
    expect(fragmentIsPresent(whole.slice(0, whole.length - 5))).toBe(true);
  });
});
