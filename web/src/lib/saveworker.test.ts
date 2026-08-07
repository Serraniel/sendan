// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import { encryptBytes, MAX_RECORD_PLAINTEXT, newFileKey } from "../crypto/index.js";
import {
  buildSaveResponse,
  contentDisposition,
  type Handover,
  HandoverStore,
  SAVE_PATH,
  tokenOf,
} from "./saveworker.js";

const filled = (n: number) => new Uint8Array(n).map((_, i) => (i * 31 + 7) % 256);

const aHandover = (fileKey: Uint8Array, size: number, name = "notes.txt"): Handover => ({
  id: "AAAAAAAAAAAAAAAAAAAAAA",
  authToken: "dG9rZW4",
  fileKey,
  file: { name, type: "text/plain", size },
});

/** Serves bytes in pieces, and reports how far ahead it was read. */
function servingIn(bytes: Uint8Array, pieces: number) {
  const size = Math.ceil(bytes.length / pieces);
  const state = { pulled: 0 };

  const doFetch = (async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          const at = state.pulled * size;
          if (at >= bytes.length) {
            controller.close();
            return;
          }
          controller.enqueue(bytes.subarray(at, at + size));
          state.pulled++;
        },
      }),
      { status: 200 },
    )) as typeof fetch;

  return { doFetch, state };
}

const serving = (bytes: Uint8Array) =>
  servingIn(bytes, Math.max(1, Math.ceil(bytes.length / 4096)));

describe("handovers", () => {
  const handover = aHandover(new Uint8Array(32), 10);

  it("hands back what was stored", () => {
    const store = new HandoverStore();
    store.put("token-one", handover);
    expect(store.take("token-one")).toBe(handover);
  });

  /**
   * A handover holds a file key. It exists for one download, so a second claim
   * must get nothing - and nothing else in a Service Worker would ever clear
   * it, because a worker is not reloaded between downloads.
   */
  it("gives a handover away once", () => {
    const store = new HandoverStore();
    store.put("token-one", handover);

    expect(store.take("token-one")).not.toBeNull();
    expect(store.take("token-one")).toBeNull();
    expect(store.size).toBe(0);
  });

  it("forgets a handover nobody claimed", () => {
    let now = 1000;
    const store = new HandoverStore(() => now);
    store.put("token-one", handover, 500);

    now = 1400;
    expect(store.size).toBe(1);

    now = 1500;
    expect(store.take("token-one")).toBeNull();
    expect(store.size).toBe(0);
  });

  it("keeps handovers apart", () => {
    const store = new HandoverStore();
    const other = aHandover(new Uint8Array(32).fill(1), 20);
    store.put("token-one", handover);
    store.put("token-two", other);

    expect(store.take("token-two")).toBe(other);
    expect(store.take("token-one")).toBe(handover);
  });

  it("knows nothing about a token it never saw", () => {
    expect(new HandoverStore().take("never-stored-token")).toBeNull();
  });
});

describe("recognising a save URL", () => {
  it("takes the token out of one", () => {
    expect(tokenOf(`https://send.example${SAVE_PATH}abcdefghijklmnop`)).toBe("abcdefghijklmnop");
  });

  /**
   * Everything else must be declined so it reaches the network. A worker that
   * claimed more than its own path would be answering for the client itself.
   */
  it("declines anything that is not one", () => {
    for (const url of [
      "https://send.example/",
      "https://send.example/d/AAAAAAAAAAAAAAAAAAAAAA",
      "https://send.example/api/uploads/x/content",
      "https://send.example/_sendan/save/",
      "https://send.example/_sendan/save/too-short",
      `https://send.example/_sendan/save/${"a".repeat(65)}`,
      "https://send.example/_sendan/save/has spaces here",
      "https://send.example/_sendan/save/abcdefghijklmnop/extra",
      "https://send.example/_sendan/saved/abcdefghijklmnop",
      "not a url at all",
    ]) {
      expect(tokenOf(url), url).toBeNull();
    }
  });

  it("is not fooled by a query or a fragment", () => {
    expect(tokenOf(`https://send.example${SAVE_PATH}abcdefghijklmnop?x=1#y`)).toBe(
      "abcdefghijklmnop",
    );
  });
});

describe("the filename in the header", () => {
  it("carries an ordinary name in both forms", () => {
    expect(contentDisposition("report.pdf")).toBe(
      "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf",
    );
  });

  it("carries a name the ASCII form cannot express", () => {
    const got = contentDisposition("отчёт.pdf");
    expect(got).toContain("filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf");
    // Five Cyrillic characters, so five underscores. The fallback is still a
    // usable name rather than nothing.
    expect(got).toContain('filename="_____.pdf"');
  });

  /**
   * The name came from whoever uploaded the file. A carriage return or newline
   * in a header value ends the header and begins another, so no input may
   * produce one - in either form, and whatever else it contains.
   */
  it("cannot be made to end the header", () => {
    const attacks = [
      'evil.txt"\r\nSet-Cookie: a=b',
      "evil.txt\r\nX-Injected: yes",
      "evil.txt\nX-Injected: yes",
      'quote".txt',
      "semi;colon.txt",
      "back\\slash.txt",
      "\r\n\r\n<html>",
      "a".repeat(5000),
    ];

    for (const name of attacks) {
      const got = contentDisposition(name);
      expect(got, name).not.toMatch(/[\r\n]/);
      // One header, one value: the only quotes are the pair around the ASCII
      // form, and no semicolon appears inside either filename.
      expect(got.match(/"/g)?.length, name).toBe(2);
      expect(got.startsWith("attachment; "), name).toBe(true);
    }
  });

  /**
   * encodeURIComponent leaves !'()* alone and they are not valid in the token,
   * so they are encoded by hand. A name containing them is ordinary enough -
   * "notes (final)!.txt" - and getting it wrong produces a header some browsers
   * reject and others read as a different filename.
   */
  it("encodes the characters encodeURIComponent leaves behind", () => {
    const got = contentDisposition("notes (final)!*'.txt");

    expect(got).toContain("%28");
    expect(got).toContain("%29");
    expect(got).toContain("%21");
    expect(got).toContain("%2A");
    expect(got).toContain("%27");
    // The two apostrophes after the charset are RFC 5987 syntax, so the check
    // is against the encoded name itself rather than the whole parameter.
    const encoded = got.slice(got.indexOf("UTF-8''") + "UTF-8''".length);
    for (const raw of ["(", ")", "!", "*", "'", " "]) {
      expect(encoded, raw).not.toContain(raw);
    }
  });

  it("still names something when nothing usable is left", () => {
    expect(contentDisposition("///")).toContain('filename="___"');
    expect(contentDisposition("")).toContain('filename="download"');
  });
});

describe("the response the browser saves", () => {
  /**
   * Record reassembly, over a stream whose pieces do not line up with record
   * boundaries. The worker never sees a whole record in one read, which is the
   * ordinary case on a network.
   */
  it("reassembles records across arbitrary network pieces", async () => {
    const plaintext = filled(3 * MAX_RECORD_PLAINTEXT + 777);
    const fileKey = newFileKey();
    const ciphertext = await encryptBytes(fileKey, plaintext);

    for (const pieces of [1, 3, 17, 250]) {
      const { doFetch } = servingIn(ciphertext, pieces);
      const response = await buildSaveResponse(aHandover(fileKey, plaintext.length), doFetch);

      expect(response.status, `${pieces} pieces`).toBe(200);
      const got = new Uint8Array(await response.arrayBuffer());
      expect(got, `${pieces} pieces`).toEqual(plaintext);
    }
  });

  it("declares the length the envelope gives, not the ciphertext's", async () => {
    const plaintext = filled(100_000);
    const fileKey = newFileKey();
    const ciphertext = await encryptBytes(fileKey, plaintext);
    const { doFetch } = serving(ciphertext);

    const response = await buildSaveResponse(aHandover(fileKey, plaintext.length), doFetch);

    expect(response.headers.get("Content-Length")).toBe("100000");
    expect(ciphertext.length).not.toBe(plaintext.length);
  });

  /**
   * The media type is deliberately not the envelope's. This response is
   * same-origin, so an upload claiming text/html would otherwise be a document
   * rendering itself inside the client's own origin.
   */
  it("is always an attachment of octets, whatever the file claims to be", async () => {
    const fileKey = newFileKey();
    const ciphertext = await encryptBytes(fileKey, filled(10));
    const { doFetch } = serving(ciphertext);

    const handover = aHandover(fileKey, 10, "page.html");
    handover.file.type = "text/html";
    const response = await buildSaveResponse(handover, doFetch);

    expect(response.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Content-Disposition")).toMatch(/^attachment;/);
  });

  it("stores nothing", async () => {
    const fileKey = newFileKey();
    const { doFetch } = serving(await encryptBytes(fileKey, filled(10)));

    const response = await buildSaveResponse(aHandover(fileKey, 10), doFetch);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("presents the token as a bearer credential", async () => {
    const fileKey = newFileKey();
    const ciphertext = await encryptBytes(fileKey, filled(10));
    let seen: { url: string; auth: string | null } | null = null;

    const watching = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen = { url: String(input), auth: new Headers(init?.headers).get("Authorization") };
      return new Response(new Blob([ciphertext as BufferSource]).stream(), { status: 200 });
    }) as typeof fetch;

    await buildSaveResponse(aHandover(fileKey, 10), watching);

    const request = seen as unknown as { url: string; auth: string };
    expect(request.auth).toBe("Bearer dG9rZW4");
    expect(request.url).not.toContain("dG9rZW4");
  });

  /**
   * Invariant 3 reaching the browser's download machinery. A truncated stream
   * must fail the response rather than complete it, or the file lands on disk
   * short and looking whole.
   */
  it("fails rather than completing when the stream is truncated", async () => {
    const plaintext = filled(2 * MAX_RECORD_PLAINTEXT);
    const fileKey = newFileKey();
    const ciphertext = await encryptBytes(fileKey, plaintext);

    for (const [name, body] of [
      ["truncated", ciphertext.subarray(0, ciphertext.length - 100)],
      [
        "one bit flipped",
        (() => {
          const copy = ciphertext.slice();
          copy[copy.length - 20] = (copy[copy.length - 20] as number) ^ 0xff;
          return copy;
        })(),
      ],
      [
        "a record removed",
        (() => {
          const copy = new Uint8Array(ciphertext.length - 65536);
          copy.set(ciphertext.subarray(0, 21), 0);
          copy.set(ciphertext.subarray(21 + 65536), 21);
          return copy;
        })(),
      ],
      ["nothing at all", new Uint8Array(0)],
    ] as [string, Uint8Array][]) {
      const { doFetch } = serving(body);
      const response = await buildSaveResponse(aHandover(fileKey, plaintext.length), doFetch);

      // The response begins - the header and the first records are valid - and
      // then errors. Reading it to the end is what the browser does.
      await expect(response.arrayBuffer(), name).rejects.toThrow();
    }
  });

  /**
   * Back-pressure, which is the whole reason this path exists. If the worker
   * read ahead of the consumer, the file would accumulate in memory and this
   * would be the blob path with extra steps.
   */
  it("reads no further ahead than the consumer takes", async () => {
    const plaintext = filled(40 * MAX_RECORD_PLAINTEXT);
    const fileKey = newFileKey();
    const ciphertext = await encryptBytes(fileKey, plaintext);

    // 200 network pieces, so reading the whole thing would be 200 pulls.
    const { doFetch, state } = servingIn(ciphertext, 200);
    const response = await buildSaveResponse(aHandover(fileKey, plaintext.length), doFetch);

    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    await reader.read();

    // A pipeline that ignored back-pressure would drain the source while this
    // test does nothing with it. Waiting is the test: if reading ahead were
    // unbounded, all 200 pieces would have been pulled by now.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(state.pulled, "the source was drained while nothing was reading").toBeLessThan(200);

    // Back-pressure delays; it does not drop. The rest of the file is still
    // there, and reading it to the end recovers every byte.
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
    }
    expect(state.pulled).toBe(200);
    expect(received).toBeGreaterThan(0);
    reader.releaseLock();
  });

  it("answers a refusal as a failed download rather than as a file", async () => {
    const fileKey = newFileKey();

    for (const status of [401, 404, 429, 500]) {
      const refusing = (async () => new Response(null, { status })) as typeof fetch;
      const response = await buildSaveResponse(aHandover(fileKey, 10), refusing);

      expect(response.status, `${status}`).toBe(502);
      expect(response.headers.get("Content-Disposition"), `${status}`).toBeNull();
    }
  });
});
