// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it } from "vitest";
import {
  deriveKeys,
  deriveKeysWithPassword,
  encryptBytes,
  MAX_RECORD_PLAINTEXT,
  newFileID,
  newFileKey,
  newLinkSecret,
  newPasswordParams,
  sealMetadata,
  wrapFileKey,
} from "../crypto/index.js";
import { expectBytes } from "../testing/bytes.js";
import {
  DownloadError,
  type DownloadFault,
  type DownloadProgress,
  downloadContent,
  explain,
  fetchMetadata,
  openUpload,
  parseMetadata,
  type UploadMetadata,
} from "./download.js";
import { downloadLink, parseLink, toBase64Url } from "./link.js";
import { uploadFile } from "./upload.js";

/** A copy with one byte flipped. */
function flipped(bytes: Uint8Array, at: number): Uint8Array {
  const copy = bytes.slice();
  copy[at] = (copy[at] as number) ^ 0xff;
  return copy;
}

/** Deterministic filler, so a failure is reproducible. */
function filled(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) % 256;
  return b;
}

/**
 * An upload as the instance would hold it, built by the real sealing code.
 *
 * Fixtures are not written by hand here: the values are related by the key
 * schedule, and a hand-written set would be internally consistent with nothing.
 */
async function anUpload(
  plaintext: Uint8Array,
  options: { password?: string; name?: string; type?: string } = {},
) {
  const fileID = newFileID();
  const linkSecret = newLinkSecret();
  const fileKey = newFileKey();
  const params = options.password === undefined ? null : newPasswordParams();

  const keys =
    params === null
      ? await deriveKeys(fileID, linkSecret)
      : await deriveKeysWithPassword(fileID, linkSecret, options.password as string, params);

  const wrapped = await wrapFileKey(keys.wrapping, fileKey);
  const sealed = await sealMetadata(keys.metadata, {
    name: options.name ?? "notes.txt",
    type: options.type ?? "text/plain",
    size: plaintext.length,
  });

  const body: Record<string, unknown> = {
    id: toBase64Url(fileID),
    wrappedFileKey: toBase64Url(wrapped.wrapped),
    wrapNonce: toBase64Url(wrapped.nonce),
    metadataEnvelope: toBase64Url(sealed.envelope),
    metadataNonce: toBase64Url(sealed.nonce),
    passwordRequired: params !== null,
  };
  if (params !== null) {
    body.kdf = {
      salt: toBase64Url(params.salt),
      memoryKiB: params.memoryKiB,
      iterations: params.iterations,
      parallelism: params.parallelism,
    };
  }

  return {
    fileID,
    linkSecret,
    fileKey,
    body,
    metadata: parseMetadata(body) as UploadMetadata,
    ciphertext: await encryptBytes(fileKey, plaintext),
  };
}

const answering = (response: Response) => (async () => response) as typeof fetch;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const streamOf = (bytes: Uint8Array, chunk = 4096) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < bytes.length; i += chunk) {
        controller.enqueue(bytes.subarray(i, i + chunk));
      }
      controller.close();
    },
  });

/**
 * The fault a call produced.
 *
 * Something other than a DownloadError is reported as "unclassified" rather
 * than folded in with success. An earlier version returned the same value for
 * both, and reported a raw KeyMaterialError escaping the module as though the
 * file had opened - which is how the empty-password case was nearly missed.
 */
const faultOf = async (
  p: Promise<unknown>,
): Promise<DownloadFault | "none" | `unclassified: ${string}`> => {
  try {
    await p;
    return "none";
  } catch (error) {
    if (error instanceof DownloadError) return error.fault;
    return `unclassified: ${(error as Error).name}`;
  }
};

describe("reading what the instance publishes", () => {
  it("parses a complete response", async () => {
    const upload = await anUpload(filled(10));
    const parsed = parseMetadata(upload.body);

    expect(parsed).not.toBeNull();
    expect((parsed as UploadMetadata).passwordRequired).toBe(false);
    expect((parsed as UploadMetadata).kdf).toBeNull();
  });

  it("parses the parameters a password-protected upload carries", async () => {
    const upload = await anUpload(filled(10), { password: "hunter2" });
    const parsed = parseMetadata(upload.body) as UploadMetadata;

    expect(parsed.passwordRequired).toBe(true);
    expect(parsed.kdf?.salt).toHaveLength(16);
    expect(parsed.kdf?.memoryKiB).toBeGreaterThan(0);
  });

  it("parses the limits when they are present, and their absence when not", async () => {
    const upload = await anUpload(filled(10));

    const withLimits = parseMetadata({
      ...upload.body,
      expiresAt: "2026-08-07T12:00:00Z",
      downloadsRemaining: 2,
    }) as UploadMetadata;
    expect(withLimits.expiresAt?.toISOString()).toBe("2026-08-07T12:00:00.000Z");
    expect(withLimits.downloadsRemaining).toBe(2);

    // Absent means unlimited, which must not be read as zero.
    const without = parseMetadata(upload.body) as UploadMetadata;
    expect(without.expiresAt).toBeNull();
    expect(without.downloadsRemaining).toBeNull();
  });

  /**
   * The instance is the party this client protects the file from, so what it
   * sends is checked rather than assumed. A field that reached the key schedule
   * as undefined would fail somewhere far from the cause.
   */
  it("refuses a response it cannot rely on", async () => {
    const upload = await anUpload(filled(10));
    const cases: [string, unknown][] = [
      ["not an object", "nonsense"],
      ["null", null],
      ["no identifier", { ...upload.body, id: undefined }],
      ["empty identifier", { ...upload.body, id: "" }],
      ["no wrapped key", { ...upload.body, wrappedFileKey: undefined }],
      ["wrapped key not base64url", { ...upload.body, wrappedFileKey: "not base64!" }],
      ["no nonce", { ...upload.body, wrapNonce: undefined }],
      ["no envelope", { ...upload.body, metadataEnvelope: undefined }],
      ["passwordRequired not a boolean", { ...upload.body, passwordRequired: "yes" }],
      ["expiry not a date", { ...upload.body, expiresAt: "the day after tomorrow" }],
      ["expiry not a string", { ...upload.body, expiresAt: 1234 }],
      ["downloads not a number", { ...upload.body, downloadsRemaining: "two" }],
    ];

    for (const [name, body] of cases) {
      expect(parseMetadata(body), name).toBeNull();
    }
  });

  /**
   * A password-protected upload without derivation parameters is one nobody
   * could ever open, so it is refused here rather than producing keys from
   * defaults that were never used to seal it.
   */
  it("refuses a protected upload whose parameters are unusable", async () => {
    const upload = await anUpload(filled(10), { password: "hunter2" });
    const kdf = upload.body.kdf as Record<string, unknown>;

    for (const [name, replacement] of [
      ["absent", undefined],
      ["not an object", "x"],
      ["no salt", { ...kdf, salt: undefined }],
      ["salt not base64url", { ...kdf, salt: "!!!" }],
      ["no memory", { ...kdf, memoryKiB: undefined }],
      ["zero memory", { ...kdf, memoryKiB: 0 }],
      ["fractional iterations", { ...kdf, iterations: 1.5 }],
      ["negative parallelism", { ...kdf, parallelism: -1 }],
    ] as [string, unknown][]) {
      expect(parseMetadata({ ...upload.body, kdf: replacement }), name).toBeNull();
    }
  });

  it("reports an unavailable upload without guessing why", async () => {
    const fault = await faultOf(fetchMetadata("abc", { fetch: answering(json({}, 404)) }));
    expect(fault).toBe("unavailable");
  });

  it("reports being rate limited, with how long to wait", async () => {
    const response = new Response(null, { status: 429, headers: { "Retry-After": "30" } });
    try {
      await fetchMetadata("abc", { fetch: answering(response) });
      expect.unreachable();
    } catch (error) {
      expect((error as DownloadError).fault).toBe("too-many-attempts");
      expect((error as DownloadError).retryAfter).toBe(30);
    }
  });

  it("survives a Retry-After it cannot use", async () => {
    for (const value of ["", "in a bit", "-5"]) {
      const response = new Response(null, { status: 429, headers: { "Retry-After": value } });
      try {
        await fetchMetadata("abc", { fetch: answering(response) });
        expect.unreachable();
      } catch (error) {
        expect((error as DownloadError).retryAfter, value).toBeNull();
      }
    }
  });

  it("reports an instance that cannot be reached or does not answer sensibly", async () => {
    const refusing = (async () => {
      throw new TypeError("network");
    }) as typeof fetch;

    expect(await faultOf(fetchMetadata("abc", { fetch: refusing }))).toBe("unreachable");
    expect(await faultOf(fetchMetadata("abc", { fetch: answering(new Response("<html>")) }))).toBe(
      "unreachable",
    );
    expect(await faultOf(fetchMetadata("abc", { fetch: answering(json({ id: 1 })) }))).toBe(
      "unreachable",
    );
    expect(await faultOf(fetchMetadata("abc", { fetch: answering(json({}, 500)) }))).toBe(
      "unreachable",
    );
  });
});

describe("opening an upload", () => {
  it("recovers the key and the description from the link alone", async () => {
    const upload = await anUpload(filled(1000), { name: "report.pdf", type: "application/pdf" });

    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    expect(opened.fileKey).toEqual(upload.fileKey);
    expect(opened.file).toEqual({ name: "report.pdf", type: "application/pdf", size: 1000 });
  });

  it("recovers it with the password when one is set", async () => {
    const upload = await anUpload(filled(1000), { password: "correct horse" });

    const opened = await openUpload(
      upload.fileID,
      upload.linkSecret,
      upload.metadata,
      "correct horse",
    );
    expect(opened.fileKey).toEqual(upload.fileKey);
  }, 30_000);

  /**
   * Checked locally rather than by asking the instance. The wrapped key is
   * authenticated, so a wrong key cannot open it - and a check the instance
   * performed would be one it could lie about, and one that spent an attempt
   * allowance against a recipient who had done nothing wrong.
   */
  it("rejects a wrong password without asking the instance", async () => {
    const upload = await anUpload(filled(1000), { password: "correct horse" });
    let asked = 0;
    const counting = (async () => {
      asked++;
      return new Response(null, { status: 204 });
    }) as typeof fetch;

    const fault = await faultOf(
      openUpload(upload.fileID, upload.linkSecret, upload.metadata, "wrong horse"),
    );

    expect(fault).toBe("password-wrong");
    expect(asked).toBe(0);
    expect(counting).toBeDefined();
  }, 30_000);

  /**
   * Pressing the button with the field untouched is the commonest thing that
   * will happen here, and the key schedule refuses an empty password outright
   * (spec §4). Unhandled, that surfaces as a crash rather than as the answer.
   */
  it("rejects an empty password as a wrong one, not as a crash", async () => {
    const upload = await anUpload(filled(100), { password: "hunter2" });
    expect(await faultOf(openUpload(upload.fileID, upload.linkSecret, upload.metadata, ""))).toBe(
      "password-wrong",
    );
  });

  /**
   * With no password there is nothing to be wrong, so the same failure means
   * the link or the stored key is damaged. Reporting "wrong password" for an
   * upload that has none would send someone looking for a password that does
   * not exist.
   */
  it("reports a damaged link differently when no password is involved", async () => {
    const upload = await anUpload(filled(100));

    expect(await faultOf(openUpload(upload.fileID, newLinkSecret(), upload.metadata))).toBe(
      "damaged",
    );

    const corrupted = {
      ...upload.metadata,
      wrappedFileKey: flipped(upload.metadata.wrappedFileKey, 0),
    };
    expect(await faultOf(openUpload(upload.fileID, upload.linkSecret, corrupted))).toBe("damaged");
  });

  it("reports a damaged envelope once the key has already opened", async () => {
    // The wrapped key opened, so the keys are right and the envelope is not.
    // Saying so precisely is safe exactly because the key already worked.
    const upload = await anUpload(filled(100));
    const corrupted = {
      ...upload.metadata,
      metadataEnvelope: flipped(upload.metadata.metadataEnvelope, 0),
    };

    expect(await faultOf(openUpload(upload.fileID, upload.linkSecret, corrupted))).toBe("corrupt");
  });

  it("is refused by the wrong identifier, which salts the schedule", async () => {
    const upload = await anUpload(filled(100));
    expect(await faultOf(openUpload(newFileID(), upload.linkSecret, upload.metadata))).toBe(
      "damaged",
    );
  });
});

describe("fetching the content", () => {
  const served = (ciphertext: Uint8Array) =>
    (async () => new Response(streamOf(ciphertext), { status: 200 })) as typeof fetch;

  it("decrypts what was sent", async () => {
    const plaintext = filled(3 * MAX_RECORD_PLAINTEXT + 55);
    const upload = await anUpload(plaintext);
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    const got = await downloadContent({
      id: upload.metadata.id,
      opened,
      transport: { fetch: served(upload.ciphertext) },
    });
    expectBytes(got, plaintext);
  });

  it("decrypts an empty file", async () => {
    const upload = await anUpload(new Uint8Array(0));
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    const got = await downloadContent({
      id: upload.metadata.id,
      opened,
      transport: { fetch: served(upload.ciphertext) },
    });
    expect(got).toEqual(new Uint8Array(0));
  });

  it("presents the token in the header, never in the query", async () => {
    // The token derives from the link secret, which this whole scheme keeps out
    // of logs by putting it in the fragment. A query parameter would write it
    // to every access log between here and the instance.
    const upload = await anUpload(filled(100));
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);
    let seen: { url: string; auth: string | null } | null = null;

    const watching = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen = {
        url: String(input),
        auth: new Headers(init?.headers).get("Authorization"),
      };
      return new Response(streamOf(upload.ciphertext), { status: 200 });
    }) as typeof fetch;

    await downloadContent({ id: upload.metadata.id, opened, transport: { fetch: watching } });

    const request = seen as unknown as { url: string; auth: string };
    expect(request.auth).toBe(`Bearer ${toBase64Url(opened.keys.authToken)}`);
    expect(request.url).not.toContain(toBase64Url(opened.keys.authToken));
    expect(request.url).not.toContain("?");
  });

  /**
   * Invariant 3: truncated, reordered or modified ciphertext never yields
   * plaintext. Partial output would be worse than none - it looks like a file.
   */
  it("yields nothing at all from a stream that was tampered with", async () => {
    const plaintext = filled(2 * MAX_RECORD_PLAINTEXT);
    const upload = await anUpload(plaintext);
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    const truncated = upload.ciphertext.subarray(0, upload.ciphertext.length - 100);
    const altered = flipped(upload.ciphertext, upload.ciphertext.length - 20);
    // A whole record removed, so what remains is well-formed but not the file.
    const shortened = new Uint8Array(upload.ciphertext.length - 65536);
    shortened.set(upload.ciphertext.subarray(0, 21), 0);
    shortened.set(upload.ciphertext.subarray(21 + 65536), 21);

    for (const [name, body] of [
      ["truncated", truncated],
      ["a flipped bit", altered],
      ["a record removed", shortened],
      ["nothing at all", new Uint8Array(0)],
    ] as [string, Uint8Array][]) {
      const fault = await faultOf(
        downloadContent({
          id: upload.metadata.id,
          opened,
          transport: { fetch: served(body) },
        }),
      );
      expect(fault, name).toBe("corrupt");
    }
  });

  /**
   * The envelope is authenticated and declares the size, so content that does
   * not match it means the two disagree. Growing a buffer to fit would let an
   * instance decide how much memory this page uses.
   */
  it("refuses content that disagrees with the size the envelope declares", async () => {
    // The envelope is authenticated and the content decrypts cleanly, so a
    // disagreement means the instance is serving something other than what was
    // sealed. Growing a buffer to fit would let it decide how much memory this
    // page uses; trusting the short count would hand back a truncated file.
    const upload = await anUpload(filled(1000));
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    const understated = { ...opened, file: { ...opened.file, size: 500 } };
    const overstated = { ...opened, file: { ...opened.file, size: 2000 } };

    for (const [name, claim, says] of [
      ["content longer than declared", understated, /longer than its description/],
      ["content shorter than declared", overstated, /shorter than its description/],
    ] as [string, typeof opened, RegExp][]) {
      const attempt = downloadContent({
        id: upload.metadata.id,
        opened: claim,
        transport: { fetch: served(upload.ciphertext) },
      });

      // The message is asserted, not only the fault. Without the length check
      // the overlong case still fails - the destination buffer is exactly the
      // declared size, so writing past it throws - but it would be reported as
      // a failed integrity check. That sends someone looking for corruption
      // when what is happening is an instance serving something other than
      // what was sealed. The two are different problems.
      await expect(attempt, name).rejects.toThrow(says);
      await expect(attempt, name).rejects.toMatchObject({ fault: "corrupt" });
    }
  });

  it("reports an upload that went away between reading it and fetching it", async () => {
    const upload = await anUpload(filled(100));
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    for (const status of [404, 401]) {
      // 401 means the upload changed underneath: the token derives from the
      // same schedule that just unwrapped the key, so it cannot be wrong here.
      const fault = await faultOf(
        downloadContent({
          id: upload.metadata.id,
          opened,
          transport: { fetch: answering(new Response(null, { status })) },
        }),
      );
      expect(fault, `${status}`).toBe("unavailable");
    }
  });

  it("reports being rate limited during a download", async () => {
    const upload = await anUpload(filled(100));
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);

    expect(
      await faultOf(
        downloadContent({
          id: upload.metadata.id,
          opened,
          transport: {
            fetch: answering(new Response(null, { status: 429, headers: { "Retry-After": "5" } })),
          },
        }),
      ),
    ).toBe("too-many-attempts");
  });

  it("reports progress against the size the envelope declares", async () => {
    const plaintext = filled(4 * MAX_RECORD_PLAINTEXT);
    const upload = await anUpload(plaintext);
    const opened = await openUpload(upload.fileID, upload.linkSecret, upload.metadata);
    const seen: DownloadProgress[] = [];

    await downloadContent({
      id: upload.metadata.id,
      opened,
      transport: { fetch: served(upload.ciphertext) },
      onProgress: (p) => seen.push({ ...p }),
    });

    expect(seen.length).toBeGreaterThan(2);
    let previous = -1;
    for (const p of seen) {
      expect(p.received).toBeGreaterThanOrEqual(previous);
      expect(p.total).toBe(plaintext.length);
      previous = p.received;
    }
    expect(seen.at(-1)?.received).toBe(plaintext.length);
  });
});

describe("when the connection is the problem", () => {
  const anUploadOpened = async () => {
    const upload = await anUpload(filled(100));
    return {
      upload,
      opened: await openUpload(upload.fileID, upload.linkSecret, upload.metadata),
    };
  };

  it("reports an instance that cannot be reached during the transfer", async () => {
    const { upload, opened } = await anUploadOpened();
    const refusing = (async () => {
      throw new TypeError("network");
    }) as typeof fetch;

    expect(
      await faultOf(
        downloadContent({ id: upload.metadata.id, opened, transport: { fetch: refusing } }),
      ),
    ).toBe("unreachable");
  });

  it("reports an answer it cannot use", async () => {
    const { upload, opened } = await anUploadOpened();

    for (const [name, response] of [
      ["a server fault", new Response(null, { status: 500 })],
      ["success with no body", new Response(null, { status: 200 })],
    ] as [string, Response][]) {
      expect(
        await faultOf(
          downloadContent({
            id: upload.metadata.id,
            opened,
            transport: { fetch: answering(response) },
          }),
        ),
        name,
      ).toBe("unreachable");
    }
  });

  /**
   * Cancelling is not a fault and must not be dressed as one. An AbortError
   * reported as "the instance could not be reached" would send someone to check
   * a connection they had just closed themselves.
   */
  it("lets a cancellation through as itself", async () => {
    const { upload, opened } = await anUploadOpened();
    const aborting = (async () => {
      throw new DOMException("aborted", "AbortError");
    }) as typeof fetch;

    for (const attempt of [
      fetchMetadata(upload.metadata.id, { fetch: aborting }),
      downloadContent({ id: upload.metadata.id, opened, transport: { fetch: aborting } }),
    ]) {
      await expect(attempt).rejects.toThrow(DOMException);
      await expect(attempt).rejects.not.toThrow(DownloadError);
    }
  });
});

describe("what a person is told", () => {
  it("has wording for every fault", () => {
    const faults: DownloadFault[] = [
      "link-incomplete",
      "link-damaged",
      "unavailable",
      "password-wrong",
      "damaged",
      "corrupt",
      "too-many-attempts",
      "unreachable",
    ];
    for (const fault of faults) {
      expect(explain(fault).length, fault).toBeGreaterThan(20);
    }
  });

  /**
   * The instance answers 404 for expired, exhausted, revoked and unknown alike,
   * and it is right to. An interface that picked one would be stating something
   * it does not know, about an upload it cannot prove existed.
   */
  it("does not claim to know why an upload is unavailable", () => {
    const said = explain("unavailable").toLowerCase();
    expect(said).toContain("may have");
    for (const claim of ["has expired", "was deleted", "reached its limit"]) {
      expect(said).not.toContain(claim);
    }
  });

  it("says the missing fragment cannot be recovered", () => {
    expect(explain("link-incomplete").toLowerCase()).toContain("cannot be recovered");
  });
});

/**
 * The two halves against each other, with nothing carried between them but the
 * link. This is the whole point: a file sent by this client must be readable by
 * this client, and the only thing joining them is a URL.
 */
describe("a file sent and then received", () => {
  it("survives the round trip through a link", async () => {
    const plaintext = filled(200_000);
    const stored: { metadata: Record<string, Uint8Array>; body: Uint8Array } = {
      metadata: {},
      body: new Uint8Array(0),
    };

    const instance = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const headers = new Headers(init?.headers);

      if (method === "POST") {
        for (const pair of (headers.get("Upload-Metadata") ?? "").split(",")) {
          const [key, value] = pair.split(" ") as [string, string];
          stored.metadata[key] = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
        }
        return new Response(null, { status: 201, headers: { Location: "/api/uploads/abc" } });
      }
      if (method === "PATCH") {
        // A buffer or a stream, the same as the real server: the client sends
        // one request body where the browser allows it and several where it
        // does not, and the server does not distinguish them.
        const sent = init?.body;
        const chunk =
          sent instanceof ReadableStream
            ? new Uint8Array(await new Response(sent).arrayBuffer())
            : new Uint8Array(sent as ArrayBuffer);
        const next = new Uint8Array(stored.body.length + chunk.length);
        next.set(stored.body, 0);
        next.set(chunk, stored.body.length);
        stored.body = next;
        return new Response(null, {
          status: 204,
          headers: { "Upload-Offset": `${stored.body.length}` },
        });
      }
      if (url.endsWith("/metadata")) {
        return json({
          id: toBase64Url(stored.metadata.fileID as Uint8Array),
          wrappedFileKey: toBase64Url(stored.metadata.wrappedFileKey as Uint8Array),
          wrapNonce: toBase64Url(stored.metadata.wrapNonce as Uint8Array),
          metadataEnvelope: toBase64Url(stored.metadata.metadataEnvelope as Uint8Array),
          metadataNonce: toBase64Url(stored.metadata.metadataNonce as Uint8Array),
          passwordRequired: false,
          downloadsRemaining: 3,
        });
      }
      return new Response(streamOf(stored.body), { status: 200 });
    }) as typeof fetch;

    const sent = await uploadFile({
      file: new File([plaintext as BufferSource], "round.bin", { type: "application/pdf" }),
      transport: { fetch: instance },
    });

    // From here, nothing but the link.
    const link = downloadLink("https://send.example", sent.fileID, sent.linkSecret);
    const parsed = parseLink(link);
    expect(parsed).not.toBeNull();
    const { fileID, linkSecret } = parsed as { fileID: Uint8Array; linkSecret: Uint8Array };

    const published = await fetchMetadata("abc", { fetch: instance });
    const opened = await openUpload(fileID, linkSecret, published);

    expect(opened.file).toEqual({
      name: "round.bin",
      type: "application/pdf",
      size: plaintext.length,
    });
    expectBytes(
      await downloadContent({ id: "abc", opened, transport: { fetch: instance } }),
      plaintext,
    );
  }, 30_000);
});

describe("uploads made through the compatibility endpoints", () => {
  // Those uploads carry no envelope in this format, so the fields a native
  // upload requires are empty. Recognising the upload before requiring them is
  // what turns a confusing decryption failure into a statement of fact.
  const compatible = {
    id: "aaaaaaaaaaaaaaaaaaaaaa",
    wrappedFileKey: "",
    wrapNonce: "",
    metadataEnvelope: "",
    metadataNonce: "",
    passwordRequired: false,
    endpoints: "compatibility",
  };

  it("is recognised and marked", () => {
    const parsed = parseMetadata(compatible);
    expect(parsed).not.toBeNull();
    expect(parsed?.endpoints).toBe("compatibility");
  });

  it("defaults to native when the instance says nothing", () => {
    const { endpoints, ...rest } = compatible;
    void endpoints;
    const parsed = parseMetadata({
      ...rest,
      wrappedFileKey: "AAAA",
      wrapNonce: "AAAA",
      metadataEnvelope: "AAAA",
      metadataNonce: "AAAA",
    });
    expect(parsed?.endpoints).toBe("native");
  });

  // A native upload with an empty envelope is not a compatibility upload, it is
  // a broken one, and accepting it would defer the failure to decryption.
  it("does not accept an empty envelope from a native upload", () => {
    const { endpoints, ...rest } = compatible;
    void endpoints;
    expect(parseMetadata(rest)).toBeNull();
  });
});
