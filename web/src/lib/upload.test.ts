// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  authTokenHash,
  decryptBytes,
  deriveKeys,
  deriveKeysWithPassword,
  encodedContentLength,
  FILE_ID_SIZE,
  LINK_SECRET_SIZE,
  MAX_RECORD_PLAINTEXT,
  OWNER_TOKEN_SIZE,
  openMetadata,
  ownerTokenHash,
  unwrapFileKey,
} from "../crypto/index.js";
import { expectBytes } from "../testing/bytes.js";
import { TusError } from "./tus.js";
import { DEFAULT_CHUNK_SIZE, type UploadProgress, uploadFile } from "./upload.js";

/**
 * A server that behaves as `docs/api.md` says one does.
 *
 * It keeps what it was sent so a test can check it against what the client
 * should have produced. It deliberately enforces the offset rule and the
 * declared length, because a client that quietly disagrees with either would
 * pass against a server that accepted anything.
 */
class FakeServer {
  metadata: Record<string, Uint8Array> = {};
  declaredLength = 0;
  body = new Uint8Array(0);
  patches = 0;

  readonly fetch: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);

    if (method === "POST") {
      this.declaredLength = Number(headers.get("Upload-Length"));
      this.metadata = parseMetadata(headers.get("Upload-Metadata") ?? "");
      return new Response(null, { status: 201, headers: { Location: "/api/uploads/abc" } });
    }

    if (method === "PATCH") {
      this.patches++;
      const offset = Number(headers.get("Upload-Offset"));
      if (offset !== this.body.length) {
        return new Response(null, { status: 409 });
      }
      // A buffer or a stream, the same as the real server: a streamed write
      // arrives with no Content-Length and is otherwise the same PATCH. A fake
      // that understood only one of them would let the other go untested.
      const body = init?.body;
      const chunk =
        body instanceof ReadableStream
          ? new Uint8Array(await new Response(body).arrayBuffer())
          : new Uint8Array(body as ArrayBuffer);
      if (this.body.length + chunk.length > this.declaredLength) {
        return new Response(null, { status: 413 });
      }
      const next = new Uint8Array(this.body.length + chunk.length);
      next.set(this.body, 0);
      next.set(chunk, this.body.length);
      this.body = next;
      return new Response(null, {
        status: 204,
        headers: { "Upload-Offset": `${this.body.length}` },
      });
    }

    return new Response(null, { status: 405, headers: { "x-url": url } });
  }) as typeof fetch;
}

function parseMetadata(header: string): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  if (header === "") return out;
  for (const pair of header.split(",")) {
    const [key, value] = pair.split(" ") as [string, string];
    out[key] = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  }
  return out;
}

const text = (m: Record<string, Uint8Array>, key: string) =>
  new TextDecoder().decode(m[key] as Uint8Array);

/** Deterministic filler, so a failure is reproducible. */
function filled(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) % 256;
  return b;
}

const fileOf = (bytes: Uint8Array, name = "notes.txt", type = "text/plain") =>
  new File([bytes as BufferSource], name, { type });

describe("uploading", () => {
  /**
   * The whole client sequence against a server that enforces what the real one
   * does, with the result decrypted independently of the code that produced it.
   *
   * Deriving here from nothing but the identifier and the link secret is the
   * point: those two values are all a recipient has, so anything this test
   * cannot recover from them is something no recipient could recover either.
   */
  it("produces a file a recipient can decrypt from the link alone", async () => {
    const plaintext = filled(3 * MAX_RECORD_PLAINTEXT + 1234);
    const server = new FakeServer();

    const result = await uploadFile({
      file: fileOf(plaintext, "report.pdf", "application/pdf"),
      transport: { fetch: server.fetch },
    });

    // Everything below is derived from the link, exactly as a recipient would.
    const keys = await deriveKeys(result.fileID, result.linkSecret);
    const fileKey = await unwrapFileKey(
      keys.wrapping,
      server.metadata.wrapNonce as Uint8Array,
      server.metadata.wrappedFileKey as Uint8Array,
    );

    expectBytes(await decryptBytes(fileKey, server.body), plaintext);

    const metadata = await openMetadata(
      keys.metadata,
      server.metadata.metadataNonce as Uint8Array,
      server.metadata.metadataEnvelope as Uint8Array,
    );
    expect(metadata).toEqual({
      name: "report.pdf",
      type: "application/pdf",
      size: plaintext.length,
    });
  });

  it("declares the identifier it generated", async () => {
    const server = new FakeServer();
    const result = await uploadFile({
      file: fileOf(filled(100)),
      transport: { fetch: server.fetch },
    });

    expect(result.fileID).toHaveLength(FILE_ID_SIZE);
    expect(server.metadata.fileID).toEqual(result.fileID);
  });

  /**
   * The declared length is enforced by the server, and the client computes it
   * before producing a byte of what it describes. A disagreement is an upload
   * that can never complete, so it is checked against what was actually sent.
   */
  it("declares a length equal to what it sends", async () => {
    for (const size of [0, 1, MAX_RECORD_PLAINTEXT, MAX_RECORD_PLAINTEXT + 1]) {
      const server = new FakeServer();
      await uploadFile({ file: fileOf(filled(size)), transport: { fetch: server.fetch } });

      expect(server.declaredLength, `${size} bytes`).toBe(encodedContentLength(size));
      expect(server.body.length, `${size} bytes`).toBe(server.declaredLength);
    }
  });

  it("sends an empty file, which is still an encoded stream", async () => {
    const server = new FakeServer();
    const result = await uploadFile({
      file: fileOf(new Uint8Array(0), "empty.bin", ""),
      transport: { fetch: server.fetch },
    });

    expect(server.body.length).toBeGreaterThan(0);
    const keys = await deriveKeys(result.fileID, result.linkSecret);
    const fileKey = await unwrapFileKey(
      keys.wrapping,
      server.metadata.wrapNonce as Uint8Array,
      server.metadata.wrappedFileKey as Uint8Array,
    );
    expect(await decryptBytes(fileKey, server.body)).toEqual(new Uint8Array(0));
  });

  it("names a type the browser would not", async () => {
    // A browser leaves the type empty for anything it does not recognise, and a
    // recipient still has to be told something a save dialog will accept.
    const server = new FakeServer();
    const result = await uploadFile({
      file: fileOf(filled(10), "thing", ""),
      transport: { fetch: server.fetch },
    });

    const keys = await deriveKeys(result.fileID, result.linkSecret);
    const metadata = await openMetadata(
      keys.metadata,
      server.metadata.metadataNonce as Uint8Array,
      server.metadata.metadataEnvelope as Uint8Array,
    );
    expect(metadata.type).toBe("application/octet-stream");
  });

  it("sends the hashes of both tokens and neither token", async () => {
    const server = new FakeServer();
    const result = await uploadFile({
      file: fileOf(filled(10)),
      transport: { fetch: server.fetch },
    });

    const keys = await deriveKeys(result.fileID, result.linkSecret);
    expect(server.metadata.authTokenHash).toEqual(await authTokenHash(keys.authToken));
    expect(server.metadata.ownerTokenHash).toEqual(await ownerTokenHash(result.ownerToken));
    expect(result.ownerToken).toHaveLength(OWNER_TOKEN_SIZE);

    // The tokens themselves must not appear anywhere in what was sent.
    const sent = Object.values(server.metadata);
    for (const value of sent) {
      expect(contains(value, keys.authToken)).toBe(false);
      expect(contains(value, result.ownerToken)).toBe(false);
    }
  });

  /**
   * The secrets exist only on this side. If any of them reached the server the
   * scheme would be decoration, so what was sent is searched for each of them.
   */
  it("sends nothing that would let the server read the file", async () => {
    const server = new FakeServer();
    const plaintext = filled(50_000);
    const result = await uploadFile({
      file: fileOf(plaintext, "secret.txt"),
      transport: { fetch: server.fetch },
    });

    const keys = await deriveKeys(result.fileID, result.linkSecret);
    const fileKey = await unwrapFileKey(
      keys.wrapping,
      server.metadata.wrapNonce as Uint8Array,
      server.metadata.wrappedFileKey as Uint8Array,
    );

    const everything = [...Object.values(server.metadata), server.body];
    for (const secret of [result.linkSecret, fileKey, keys.wrapping, keys.metadata]) {
      for (const value of everything) {
        expect(contains(value, secret)).toBe(false);
      }
    }
    // Nor the plaintext, nor the name, which travels in the envelope.
    expect(contains(server.body, plaintext.subarray(0, 64))).toBe(false);
    expect(contains(server.metadata.metadataEnvelope as Uint8Array, encode("secret.txt"))).toBe(
      false,
    );
  });

  it("carries the options the sender chose", async () => {
    const server = new FakeServer();
    await uploadFile({
      file: fileOf(filled(10)),
      options: { ttlSeconds: 3600, maxDownloads: 5 },
      transport: { fetch: server.fetch },
    });

    expect(text(server.metadata, "ttlSeconds")).toBe("3600");
    expect(text(server.metadata, "maxDownloads")).toBe("5");
  });

  it("asks for the instance defaults when the sender chose nothing", async () => {
    const server = new FakeServer();
    await uploadFile({ file: fileOf(filled(10)), transport: { fetch: server.fetch } });

    expect(text(server.metadata, "ttlSeconds")).toBe("0");
    expect(text(server.metadata, "maxDownloads")).toBe("0");
    expect(server.metadata.passwordSalt).toBeUndefined();
  });
});

describe("uploading with a password", () => {
  /**
   * The password contributes to the key, so a recipient deriving without it
   * must fail to unwrap - not be refused by the server, which is what a
   * server-checked password would mean.
   */
  it("produces a file that cannot be opened without the password", async () => {
    const plaintext = filled(2048);
    const server = new FakeServer();

    const result = await uploadFile({
      file: fileOf(plaintext),
      options: { password: "correct horse" },
      transport: { fetch: server.fetch },
    });

    const params = {
      salt: server.metadata.passwordSalt as Uint8Array,
      memoryKiB: Number(text(server.metadata, "argon2MemoryKiB")),
      iterations: Number(text(server.metadata, "argon2Iterations")),
      parallelism: Number(text(server.metadata, "argon2Parallelism")),
    };

    const right = await deriveKeysWithPassword(
      result.fileID,
      result.linkSecret,
      "correct horse",
      params,
    );
    const fileKey = await unwrapFileKey(
      right.wrapping,
      server.metadata.wrapNonce as Uint8Array,
      server.metadata.wrappedFileKey as Uint8Array,
    );
    expectBytes(await decryptBytes(fileKey, server.body), plaintext);

    // The link alone is not enough, and neither is the wrong password.
    for (const wrong of [
      await deriveKeys(result.fileID, result.linkSecret),
      await deriveKeysWithPassword(result.fileID, result.linkSecret, "wrong horse", params),
    ]) {
      await expect(
        unwrapFileKey(
          wrong.wrapping,
          server.metadata.wrapNonce as Uint8Array,
          server.metadata.wrappedFileKey as Uint8Array,
        ),
      ).rejects.toThrow();
    }
  }, 30_000);

  it("declares the parameters a recipient needs, and never the password", async () => {
    const server = new FakeServer();
    await uploadFile({
      file: fileOf(filled(10)),
      options: { password: "hunter2" },
      transport: { fetch: server.fetch },
    });

    expect(server.metadata.passwordSalt).toHaveLength(16);
    expect(Number(text(server.metadata, "argon2MemoryKiB"))).toBeGreaterThan(0);
    expect(Number(text(server.metadata, "argon2Iterations"))).toBeGreaterThan(0);
    expect(Number(text(server.metadata, "argon2Parallelism"))).toBeGreaterThan(0);

    for (const value of Object.values(server.metadata)) {
      expect(contains(value, encode("hunter2"))).toBe(false);
    }
  }, 30_000);

  /**
   * The parameters come back because only this function knows them: they are
   * generated here, and asking for them again would produce a different salt.
   * An interface reporting what protected the file needs the ones that were
   * used, so they are checked against what the instance was actually sent.
   */
  it("returns the parameters it used, and they are the ones it sent", async () => {
    const server = new FakeServer();
    const result = await uploadFile({
      file: fileOf(filled(10)),
      options: { password: "hunter2" },
      transport: { fetch: server.fetch },
    });

    expect(result.passwordParams).not.toBeNull();
    const used = result.passwordParams as NonNullable<typeof result.passwordParams>;

    expect(used.salt).toEqual(server.metadata.passwordSalt);
    expect(`${used.memoryKiB}`).toBe(text(server.metadata, "argon2MemoryKiB"));
    expect(`${used.iterations}`).toBe(text(server.metadata, "argon2Iterations"));
    expect(`${used.parallelism}`).toBe(text(server.metadata, "argon2Parallelism"));
  }, 30_000);

  it("returns no parameters where no password was set", async () => {
    const server = new FakeServer();
    const result = await uploadFile({
      file: fileOf(filled(10)),
      transport: { fetch: server.fetch },
    });
    expect(result.passwordParams).toBeNull();
  });

  it("treats an empty password as no password", async () => {
    // An interface with an untouched password field must not produce an upload
    // that demands a password nobody set.
    const server = new FakeServer();
    await uploadFile({
      file: fileOf(filled(10)),
      options: { password: "" },
      transport: { fetch: server.fetch },
    });
    expect(server.metadata.passwordSalt).toBeUndefined();
  });
});

describe("progress", () => {
  it("advances as bytes are acknowledged, not after the file is encrypted", async () => {
    // The point of chunking: a large file must advance from the first chunk
    // rather than sit at zero while it is encrypted and then jump to complete.
    const server = new FakeServer();
    const seen: UploadProgress[] = [];

    await uploadFile({
      file: fileOf(filled(20 * 65536)),
      chunkSize: 65536,
      stream: false,
      transport: { fetch: server.fetch },
      onProgress: (p) => seen.push({ ...p }),
    });

    const sending = seen.filter((p) => p.stage === "sending");
    expect(sending.length).toBeGreaterThan(5);

    const partial = sending.filter((p) => p.sent > 0 && p.sent < p.total);
    expect(partial.length).toBeGreaterThan(3);

    // Monotonic, never past the total, and the total never changes.
    let previous = -1;
    for (const p of seen) {
      expect(p.sent).toBeGreaterThanOrEqual(previous);
      expect(p.sent).toBeLessThanOrEqual(p.total);
      expect(p.total).toBe(server.declaredLength);
      previous = p.sent;
    }
  });

  it("reports the pause before anything is sent", async () => {
    // Key derivation with a password is a visible wait, and a bar that sits at
    // zero through it is indistinguishable from a hang.
    const server = new FakeServer();
    const seen: UploadProgress[] = [];
    await uploadFile({
      file: fileOf(filled(10)),
      transport: { fetch: server.fetch },
      onProgress: (p) => seen.push({ ...p }),
    });

    expect(seen[0]?.stage).toBe("deriving");
    expect(seen.at(-1)).toEqual({
      stage: "done",
      sent: server.body.length,
      total: server.body.length,
    });
  });

  it("ends at exactly the total", async () => {
    const server = new FakeServer();
    let last: UploadProgress | null = null;
    await uploadFile({
      file: fileOf(filled(100_000)),
      transport: { fetch: server.fetch },
      onProgress: (p) => {
        last = p;
      },
    });
    expect(last).not.toBeNull();
    expect((last as unknown as UploadProgress).sent).toBe(
      (last as unknown as UploadProgress).total,
    );
  });
});

describe("chunking", () => {
  it("sends a small file in one request", async () => {
    const server = new FakeServer();
    await uploadFile({ file: fileOf(filled(10)), transport: { fetch: server.fetch } });
    expect(server.patches).toBe(1);
  });

  /**
   * Chunks are cut from one reused buffer. If a partial chunk were sent as the
   * whole buffer, the upload would still complete - with the tail padded by
   * whatever the previous chunk left there.
   */
  it("sends a partial final chunk as its own length", async () => {
    const plaintext = filled(200_000);
    const server = new FakeServer();

    const result = await uploadFile({
      file: fileOf(plaintext),
      chunkSize: 65536,
      stream: false,
      transport: { fetch: server.fetch },
    });

    expect(server.patches).toBeGreaterThan(1);
    expect(server.body.length).toBe(server.declaredLength);

    const keys = await deriveKeys(result.fileID, result.linkSecret);
    const fileKey = await unwrapFileKey(
      keys.wrapping,
      server.metadata.wrapNonce as Uint8Array,
      server.metadata.wrappedFileKey as Uint8Array,
    );
    expectBytes(await decryptBytes(fileKey, server.body), plaintext);
  });

  it("produces the same bytes at any chunk size", async () => {
    const plaintext = filled(150_000);
    const bodies: string[] = [];

    for (const chunkSize of [1, 17, 65536, DEFAULT_CHUNK_SIZE]) {
      const server = new FakeServer();
      const result = await uploadFile({
        file: fileOf(plaintext),
        chunkSize,
        transport: { fetch: server.fetch },
      });

      const keys = await deriveKeys(result.fileID, result.linkSecret);
      const fileKey = await unwrapFileKey(
        keys.wrapping,
        server.metadata.wrapNonce as Uint8Array,
        server.metadata.wrappedFileKey as Uint8Array,
      );
      expectBytes(await decryptBytes(fileKey, server.body), plaintext, `chunk size ${chunkSize}`);
      bodies.push(`${server.body.length}`);
    }

    // The chunk size is a transport decision and must not change the encoding.
    expect(new Set(bodies).size).toBe(1);
  }, 30_000);

  it("refuses a chunk size that is not a byte count", async () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      await expect(
        uploadFile({
          file: fileOf(filled(10)),
          chunkSize: bad,
          stream: false,
          transport: { fetch: new FakeServer().fetch },
        }),
        `${bad}`,
      ).rejects.toThrow(TypeError);
    }
  });
});

describe("the two ways of sending a body", () => {
  /**
   * Both, on purpose, and with the same assertion. Two upload paths means the
   * one a given environment does not take is the one that rots - and which one
   * that is depends on the deployment, not on the code: request streaming
   * needs HTTP/2, so an instance behind a proxy that speaks HTTP/1.1 takes the
   * chunked path however new the browser is.
   */
  it("produce identical uploads", async () => {
    const plaintext = filled(200_000);
    const bodies: string[] = [];

    for (const stream of [true, false]) {
      const server = new FakeServer();
      const result = await uploadFile({
        file: fileOf(plaintext, "same.bin"),
        chunkSize: 65536,
        stream,
        transport: { fetch: server.fetch },
      });

      const keys = await deriveKeys(result.fileID, result.linkSecret);
      const fileKey = await unwrapFileKey(
        keys.wrapping,
        server.metadata.wrapNonce as Uint8Array,
        server.metadata.wrappedFileKey as Uint8Array,
      );
      expectBytes(await decryptBytes(fileKey, server.body), plaintext, `stream=${stream}`);
      expect(server.body.length, `stream=${stream}`).toBe(server.declaredLength);
      bodies.push(`${server.body.length}`);
    }

    // The transport is a transport. It must not change the encoding.
    expect(new Set(bodies).size).toBe(1);
  });

  it("differ only in how many requests they take", async () => {
    const plaintext = filled(300_000);

    const streamed = new FakeServer();
    await uploadFile({
      file: fileOf(plaintext),
      stream: true,
      transport: { fetch: streamed.fetch },
    });

    const chunked = new FakeServer();
    await uploadFile({
      file: fileOf(plaintext),
      chunkSize: 65536,
      stream: false,
      transport: { fetch: chunked.fetch },
    });

    expect(streamed.patches).toBe(1);
    expect(chunked.patches).toBeGreaterThan(4);
  });

  /**
   * Required by the platform, and only by the platform: a stream body without
   * it is refused by the browser before the request is made. Node accepts the
   * request either way, so no assertion about the *result* can see this - what
   * is checked is the request that was made.
   */
  it("declare duplex on a streamed request, which the browser requires", async () => {
    const server = new FakeServer();
    const inits: RequestInit[] = [];

    const watching = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH") inits.push(init as RequestInit);
      return server.fetch(input, init);
    }) as typeof fetch;

    await uploadFile({
      file: fileOf(filled(1000)),
      stream: true,
      transport: { fetch: watching },
    });

    expect(inits).toHaveLength(1);
    expect((inits[0] as RequestInit & { duplex?: string }).duplex).toBe("half");
    expect(inits[0]?.body).toBeInstanceOf(ReadableStream);
  });

  /**
   * Detection is not enough. Request streaming also needs HTTP/2, which a
   * browser only has over TLS, so a browser that supports it still cannot use
   * it against an instance reached over HTTP/1.1 - an ordinary deployment. The
   * fetch is refused before anything is sent, and the upload has to complete
   * anyway rather than failing.
   */
  it("fall back to chunks when the browser refuses to stream", async () => {
    const plaintext = filled(200_000);
    const server = new FakeServer();
    let refusals = 0;

    const refusingToStream = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH" && init?.body instanceof ReadableStream) {
        refusals++;
        // What Chromium raises for a streamed body over HTTP/1.1.
        throw new TypeError("Failed to fetch");
      }
      return server.fetch(input, init);
    }) as typeof fetch;

    const result = await uploadFile({
      file: fileOf(plaintext),
      chunkSize: 65536,
      stream: true,
      transport: { fetch: refusingToStream },
    });

    expect(refusals).toBe(1);
    expect(server.patches).toBeGreaterThan(1);

    const keys = await deriveKeys(result.fileID, result.linkSecret);
    const fileKey = await unwrapFileKey(
      keys.wrapping,
      server.metadata.wrapNonce as Uint8Array,
      server.metadata.wrappedFileKey as Uint8Array,
    );
    expectBytes(await decryptBytes(fileKey, server.body), plaintext);
  });

  /**
   * A bar that walked forwards and then started again from zero would look
   * like a fault. The streamed attempt counts bytes as it hands them over, so
   * a refusal has to put that back before the chunked path starts.
   */
  it("do not let a refused stream leave progress ahead of itself", async () => {
    const server = new FakeServer();
    const seen: number[] = [];

    const refusingLate = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH" && init?.body instanceof ReadableStream) {
        // Drained first, so the counter has advanced before the refusal.
        await new Response(init.body).arrayBuffer();
        throw new TypeError("Failed to fetch");
      }
      return server.fetch(input, init);
    }) as typeof fetch;

    await uploadFile({
      file: fileOf(filled(200_000)),
      chunkSize: 65536,
      stream: true,
      transport: { fetch: refusingLate },
      onProgress: (p) => {
        if (p.stage === "sending") seen.push(p.sent);
      },
    });

    // Exactly one step back, and it goes to zero. Asserting only that it went
    // backwards would pass without the reset: the chunked path's first report
    // is one chunk, which is already less than the streamed attempt reached.
    const backwards: number[] = [];
    let previous = -1;
    for (const sent of seen) {
      if (sent < previous) backwards.push(sent);
      previous = sent;
    }
    expect(backwards).toEqual([0]);
    expect(seen.at(-1)).toBe(server.declaredLength);
  });

  it("can be cancelled part way through a streamed body", async () => {
    // Cancelling a streamed upload has to stop the stream itself, not only the
    // request: the body is being produced as it is sent, so a signal that
    // reached the fetch and not the pipeline would leave an encoder running
    // with nowhere to write.
    const server = new FakeServer();
    const controller = new AbortController();

    const aborting = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH") {
        controller.abort();
        throw new DOMException("aborted", "AbortError");
      }
      return server.fetch(input, init);
    }) as typeof fetch;

    await expect(
      uploadFile({
        file: fileOf(filled(300_000)),
        stream: true,
        transport: { fetch: aborting, signal: controller.signal },
      }),
    ).rejects.toThrow();

    expect(server.body.length).toBeLessThan(server.declaredLength);
  });

  it("refuse a stream that was rejected after bytes were stored", async () => {
    // Nothing to fall back to: writing from the beginning again would write
    // over what the instance already holds.
    const server = new FakeServer();
    const rejecting = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH") {
        await new Response(init?.body as ReadableStream).arrayBuffer();
        return new Response(null, { status: 409 });
      }
      return server.fetch(input, init);
    }) as typeof fetch;

    await expect(
      uploadFile({ file: fileOf(filled(1000)), stream: true, transport: { fetch: rejecting } }),
    ).rejects.toMatchObject({ status: 409 });
  });
});

describe("when it goes wrong", () => {
  it("raises what the server said, rather than reporting a link", async () => {
    const refusing = (async () =>
      new Response(JSON.stringify({ code: "rate_limited", message: "slow down" }), {
        status: 429,
      })) as typeof fetch;

    await expect(
      uploadFile({ file: fileOf(filled(10)), transport: { fetch: refusing } }),
    ).rejects.toMatchObject({ status: 429 });
  });

  it("raises when a chunk is refused part way through", async () => {
    const server = new FakeServer();
    let patches = 0;
    const failing = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH" && ++patches === 2) {
        return new Response(null, { status: 409 });
      }
      return server.fetch(input, init);
    }) as typeof fetch;

    await expect(
      uploadFile({
        file: fileOf(filled(300_000)),
        chunkSize: 65536,
        stream: false,
        transport: { fetch: failing },
      }),
    ).rejects.toThrow(TusError);
  });

  /**
   * A server that acknowledges fewer bytes than were declared leaves an upload
   * that never completes and a link that never resolves. Saying so beats
   * handing out a link to nothing.
   */
  it("raises when the server acknowledged less than was declared", async () => {
    const server = new FakeServer();
    const lying = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await server.fetch(input, init);
      if ((init?.method ?? "GET") !== "PATCH") return response;
      // Acknowledges one byte short of what it in fact stored.
      return new Response(null, {
        status: 204,
        headers: { "Upload-Offset": `${server.body.length - 1}` },
      });
    }) as typeof fetch;

    await expect(
      uploadFile({ file: fileOf(filled(10)), transport: { fetch: lying } }),
    ).rejects.toThrow(/declared/);
  });

  it("stops when the caller aborts", async () => {
    const server = new FakeServer();
    const controller = new AbortController();
    const aborting = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "PATCH") controller.abort();
      if (controller.signal.aborted && (init?.method ?? "GET") === "PATCH") {
        throw new DOMException("aborted", "AbortError");
      }
      return server.fetch(input, init);
    }) as typeof fetch;

    await expect(
      uploadFile({
        file: fileOf(filled(300_000)),
        chunkSize: 65536,
        stream: false,
        transport: { fetch: aborting, signal: controller.signal },
      }),
    ).rejects.toThrow();
    expect(server.body.length).toBeLessThan(server.declaredLength);
  });
});

/** Whether needle appears in haystack. Used to assert that it does not. */
function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

const encode = (s: string) => new TextEncoder().encode(s);

/** Keeps the imported sizes honest: a change to either is a wire change. */
it("uses the sizes the specification fixes", () => {
  expect(FILE_ID_SIZE).toBe(16);
  expect(LINK_SECRET_SIZE).toBe(32);
  expect(OWNER_TOKEN_SIZE).toBe(32);
});
