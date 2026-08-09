// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  canStreamRequests,
  createUpload,
  currentOffset,
  encodeMetadata,
  patchChunk,
  patchStream,
  TusError,
} from "./tus.js";

/** A fetch that answers once, and records what it was asked. */
function answering(response: Response): { fetch: typeof fetch; seen: Request[] } {
  const seen: Request[] = [];
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push(new Request(typeof input === "string" ? new URL(input, "http://x/") : input, init));
    return response;
  }) as typeof fetch;
  return { fetch: f, seen };
}

function created(location: string): Response {
  return new Response(null, { status: 201, headers: { Location: location } });
}

describe("upload metadata", () => {
  /**
   * The server decodes this header before Sendan sees it, using the protocol's
   * padded standard base64 rather than the base64url the wire format uses for
   * everything else. Getting the alphabet wrong is self-consistent on this side
   * and rejected on the other, so the expected text is written out rather than
   * produced by the encoder under test.
   */
  it("encodes bytes as padded standard base64", () => {
    // 0xff 0xfe encodes to //4=, which uses both characters base64url replaces
    // and needs padding.
    expect(encodeMetadata({ k: new Uint8Array([0xff, 0xfe]) })).toBe("k //4=");
  });

  it("encodes numbers as decimal text", () => {
    // 3600 as the five bytes "3600", not as an integer in any width.
    expect(encodeMetadata({ ttlSeconds: 3600 })).toBe(`ttlSeconds ${btoa("3600")}`);
    expect(encodeMetadata({ maxDownloads: 0 })).toBe(`maxDownloads ${btoa("0")}`);
  });

  it("encodes strings as their UTF-8", () => {
    expect(encodeMetadata({ k: "é" })).toBe(`k ${btoa("\xc3\xa9")}`);
  });

  it("separates pairs with commas", () => {
    const got = encodeMetadata({ a: new Uint8Array([1]), b: new Uint8Array([2]) });
    expect(got).toBe(`a ${btoa("\x01")},b ${btoa("\x02")}`);
  });

  it("encodes nothing as nothing", () => {
    expect(encodeMetadata({})).toBe("");
  });

  /**
   * A space or a comma in a key would be reparsed by the server as a different
   * key, or as two of them, and the upload would be refused for a missing field
   * that was in fact sent. Refusing here names the actual fault.
   */
  it("refuses a key the format cannot carry", () => {
    for (const key of ["", "two words", "a,b", "tab\there"]) {
      expect(() => encodeMetadata({ [key]: "v" }), JSON.stringify(key)).toThrow(TypeError);
    }
  });

  it("encodes a value larger than one call can spread", () => {
    // Guards the chunking in the encoder: spreading a large array into
    // fromCharCode exceeds the argument limit, which is a fault that appears
    // only above some size.
    const big = new Uint8Array(200_000).fill(0x41);
    expect(encodeMetadata({ k: big })).toBe(`k ${btoa("A".repeat(200_000))}`);
  });
});

describe("creating an upload", () => {
  it("declares the length and the protocol version", async () => {
    const { fetch, seen } = answering(created("/api/uploads/abc"));
    await createUpload({ length: 1234, metadata: { k: "v" } }, { fetch });

    const req = seen[0] as Request;
    expect(req.method).toBe("POST");
    expect(req.headers.get("Tus-Resumable")).toBe("1.0.0");
    expect(req.headers.get("Upload-Length")).toBe("1234");
    expect(req.headers.get("Upload-Metadata")).toBe(`k ${btoa("v")}`);
  });

  it("resolves a relative Location against the request", async () => {
    const response = created("/api/uploads/abc");
    Object.defineProperty(response, "url", { value: "https://host.example/api/uploads" });
    const { fetch } = answering(response);

    expect(await createUpload({ length: 1, metadata: {} }, { fetch })).toBe(
      "https://host.example/api/uploads/abc",
    );
  });

  it("keeps an absolute Location", async () => {
    const { fetch } = answering(created("https://elsewhere.example/api/uploads/abc"));
    expect(await createUpload({ length: 1, metadata: {} }, { fetch })).toBe(
      "https://elsewhere.example/api/uploads/abc",
    );
  });

  /**
   * Only 201 means created. A 200 with a Location would otherwise be followed
   * as though it were, and the upload would be sent to whatever answered.
   */
  it("accepts nothing but 201", async () => {
    for (const status of [200, 204, 301]) {
      const { fetch } = answering(
        new Response(null, { status, headers: { Location: "/api/uploads/abc" } }),
      );
      await expect(createUpload({ length: 1, metadata: {} }, { fetch })).rejects.toThrow(TusError);
    }
  });

  it("reports the status a refusal carried", async () => {
    const { fetch } = answering(
      new Response(JSON.stringify({ code: "too_large", message: "too big" }), { status: 413 }),
    );
    await expect(createUpload({ length: 1, metadata: {} }, { fetch })).rejects.toMatchObject({
      status: 413,
      message: "too big",
    });
  });

  it("reports a plain-text refusal from the protocol handler", async () => {
    const { fetch } = answering(
      new Response("ERR_SIZE_REQUIRED: the total upload length must be declared up front", {
        status: 400,
      }),
    );
    await expect(createUpload({ length: 1, metadata: {} }, { fetch })).rejects.toThrow(
      /must be declared up front/,
    );
  });

  it("reports an empty refusal by its status", async () => {
    const { fetch } = answering(new Response(null, { status: 429 }));
    await expect(createUpload({ length: 1, metadata: {} }, { fetch })).rejects.toThrow("HTTP 429");
  });

  it("refuses a creation that says nothing about where", async () => {
    const { fetch } = answering(new Response(null, { status: 201 }));
    await expect(createUpload({ length: 1, metadata: {} }, { fetch })).rejects.toThrow(/where/);
  });
});

describe("sending a chunk", () => {
  const accepted = (offset: number) =>
    new Response(null, { status: 204, headers: { "Upload-Offset": `${offset}` } });

  it("sends the bytes at the offset", async () => {
    const { fetch, seen } = answering(accepted(3));
    const next = await patchChunk("/api/uploads/abc", 0, new Uint8Array([1, 2, 3]), { fetch });

    const req = seen[0] as Request;
    expect(req.method).toBe("PATCH");
    expect(req.headers.get("Upload-Offset")).toBe("0");
    expect(req.headers.get("Content-Type")).toBe("application/offset+octet-stream");
    expect(new Uint8Array(await req.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(next).toBe(3);
  });

  /**
   * Chunks are views into one reused buffer, so sending the view's buffer would
   * send the whole buffer - the tail of a file padded with the previous chunk.
   * The upload would still complete, with the wrong bytes.
   */
  it("sends only the view, not the buffer behind it", async () => {
    const { fetch, seen } = answering(accepted(2));
    const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    await patchChunk("/api/uploads/abc", 0, buffer.subarray(0, 2), { fetch });

    const body = new Uint8Array(await (seen[0] as Request).arrayBuffer());
    expect(body).toEqual(new Uint8Array([1, 2]));
    expect(body.length).toBe(2);
  });

  it("returns the offset the server reports, not the one implied", async () => {
    // They agree ordinarily. Where they do not, the server decides what it
    // stored, and continuing from the local guess would leave a hole.
    const { fetch } = answering(accepted(10));
    expect(await patchChunk("/api/uploads/abc", 0, new Uint8Array(3), { fetch })).toBe(10);
  });

  it("accepts nothing but 204", async () => {
    for (const status of [200, 404, 409, 413]) {
      const { fetch } = answering(
        new Response(null, { status, headers: { "Upload-Offset": "3" } }),
      );
      await expect(
        patchChunk("/api/uploads/abc", 0, new Uint8Array(3), { fetch }),
      ).rejects.toMatchObject({ status });
    }
  });

  it("refuses an acceptance with no offset", async () => {
    const { fetch } = answering(new Response(null, { status: 204 }));
    await expect(patchChunk("/api/uploads/abc", 0, new Uint8Array(1), { fetch })).rejects.toThrow(
      /without reporting an offset/,
    );
  });

  it("refuses an offset that is not a byte count", async () => {
    for (const value of ["", "-1", "nonsense", "1.5", "9007199254740993"]) {
      const { fetch } = answering(
        new Response(null, { status: 204, headers: { "Upload-Offset": value } }),
      );
      await expect(
        patchChunk("/api/uploads/abc", 0, new Uint8Array(1), { fetch }),
        value,
      ).rejects.toThrow(TusError);
    }
  });
});

describe("resuming", () => {
  it("reports where the server left off", async () => {
    const { fetch, seen } = answering(
      new Response(null, { status: 200, headers: { "Upload-Offset": "4096" } }),
    );
    expect(await currentOffset("/api/uploads/abc", { fetch })).toBe(4096);
    expect((seen[0] as Request).method).toBe("HEAD");
  });

  /**
   * A completed upload answers 404, which is the answer rather than a fault:
   * there is nothing left to resume. Treating it as an error would turn a
   * finished upload into a failed one.
   */
  it("reports a completed upload as nothing to resume", async () => {
    const { fetch } = answering(new Response(null, { status: 404 }));
    expect(await currentOffset("/api/uploads/abc", { fetch })).toBeNull();
  });

  it("raises anything else", async () => {
    const { fetch } = answering(new Response(null, { status: 500 }));
    await expect(currentOffset("/api/uploads/abc", { fetch })).rejects.toThrow(TusError);
  });

  it("refuses an offset it cannot use", async () => {
    const { fetch } = answering(new Response(null, { status: 200 }));
    await expect(currentOffset("/api/uploads/abc", { fetch })).rejects.toThrow(TusError);
  });
});

describe("whether the browser will stream a request", () => {
  /**
   * The canonical detection: a browser that supports it consults the duplex
   * getter and does not infer a Content-Type from the body. Both facts together
   * are what distinguish it, and either alone would be wrong about something.
   */
  it("says yes where the duplex option is read", () => {
    expect(canStreamRequests()).toBe(true);
  });

  it("says no where it is not", () => {
    // A constructor that ignores duplex, as an older browser's does.
    const oblivious = class {
      headers = new Headers({ "Content-Type": "text/plain" });
      constructor(_url: string, _init: RequestInit) {}
    } as unknown as typeof Request;

    expect(canStreamRequests(oblivious)).toBe(false);
  });

  /**
   * Older browsers throw rather than ignore: a stream body is not something
   * they can construct a request from at all. Detection must answer the
   * question rather than propagate that.
   */
  it("says no where constructing the probe throws", () => {
    const refusing = class {
      constructor() {
        throw new TypeError("streaming bodies are not supported");
      }
    } as unknown as typeof Request;

    expect(canStreamRequests(refusing)).toBe(false);
  });
});

describe("streaming a body", () => {
  const oneByte = () =>
    new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array([1]));
        c.close();
      },
    });

  it("reports the offset the server holds afterwards", async () => {
    const { fetch } = answering(
      new Response(null, { status: 204, headers: { "Upload-Offset": "1" } }),
    );
    expect(await patchStream("/api/uploads/abc", 0, oneByte(), { fetch })).toEqual({
      offset: 1,
      refusedOutright: false,
    });
  });

  it("refuses an acceptance with no offset", async () => {
    const { fetch } = answering(new Response(null, { status: 204 }));
    await expect(patchStream("/api/uploads/abc", 0, oneByte(), { fetch })).rejects.toThrow(
      /without reporting an offset/,
    );
  });

  /**
   * A browser refuses a streamed body over HTTP/1.1, which is an ordinary
   * deployment rather than a fault. Reported rather than thrown, so the caller
   * can write chunks instead - nothing was sent.
   */
  it("reports a refusal before anything was sent, rather than throwing", async () => {
    const refusing = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;

    expect(await patchStream("/api/uploads/abc", 7, oneByte(), { fetch: refusing })).toEqual({
      offset: 7,
      refusedOutright: true,
    });
  });

  /**
   * A rejection is different from a refusal: the request was made, so bytes may
   * already be stored and writing from the beginning again would write over
   * them.
   */
  it("raises a rejection, which is not something to retry", async () => {
    const { fetch } = answering(new Response(null, { status: 409 }));
    await expect(patchStream("/api/uploads/abc", 0, oneByte(), { fetch })).rejects.toMatchObject({
      status: 409,
    });
  });

  it("lets a cancellation through as itself", async () => {
    const aborting = (async () => {
      throw new DOMException("aborted", "AbortError");
    }) as typeof fetch;

    await expect(
      patchStream("/api/uploads/abc", 0, oneByte(), { fetch: aborting }),
    ).rejects.toThrow(DOMException);
  });
});
