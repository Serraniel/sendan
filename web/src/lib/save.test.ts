// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it, vi } from "vitest";
import {
  deriveKeys,
  encryptBytes,
  newFileID,
  newFileKey,
  newLinkSecret,
  sealMetadata,
  wrapFileKey,
} from "../crypto/index.js";
import { expectBytes } from "../testing/bytes.js";
import {
  DownloadError,
  openUpload,
  parseMetadata,
  saveContent,
  type UploadMetadata,
} from "./download.js";
import { toBase64Url } from "./link.js";
import {
  canStreamViaWorker,
  canWriteToDisk,
  chooseDestination,
  extensionOf,
  newSaveToken,
  offerAsBlob,
  offerViaWorker,
  readySaveWorker,
} from "./save.js";
import { SAVE_PATH, tokenOf } from "./saveworker.js";

const filled = (n: number) => new Uint8Array(n).map((_, i) => (i * 31 + 7) % 256);

/** An upload as the instance would hold it, sealed by the real code. */
async function anUpload(plaintext: Uint8Array, name = "notes.txt", type = "text/plain") {
  const fileID = newFileID();
  const linkSecret = newLinkSecret();
  const fileKey = newFileKey();
  const keys = await deriveKeys(fileID, linkSecret);
  const wrapped = await wrapFileKey(keys.wrapping, fileKey);
  const sealed = await sealMetadata(keys.metadata, { name, type, size: plaintext.length });

  const metadata = parseMetadata({
    id: toBase64Url(fileID),
    wrappedFileKey: toBase64Url(wrapped.wrapped),
    wrapNonce: toBase64Url(wrapped.nonce),
    metadataEnvelope: toBase64Url(sealed.envelope),
    metadataNonce: toBase64Url(sealed.nonce),
    passwordRequired: false,
  }) as UploadMetadata;

  return {
    fileID,
    linkSecret,
    metadata,
    opened: await openUpload(fileID, linkSecret, metadata),
    ciphertext: await encryptBytes(fileKey, plaintext),
  };
}

const streamOf = (bytes: Uint8Array, chunk = 4096) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      for (let i = 0; i < bytes.length; i += chunk) {
        controller.enqueue(bytes.subarray(i, i + chunk));
      }
      controller.close();
    },
  });

const serving = (ciphertext: Uint8Array) =>
  (async () => new Response(streamOf(ciphertext), { status: 200 })) as typeof fetch;

/**
 * A destination that records what happened to it.
 *
 * Whether it was closed or aborted is the thing under test: a closed sink is a
 * file on disk, and an aborted one is nothing.
 */
function aFile() {
  const written: Uint8Array[] = [];
  const state = { closed: false, aborted: false };

  const stream = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk.slice());
    },
    close() {
      state.closed = true;
    },
    abort() {
      state.aborted = true;
    },
  });

  return {
    stream,
    state,
    get contents() {
      const total = written.reduce((n, c) => n + c.length, 0);
      const all = new Uint8Array(total);
      let at = 0;
      for (const chunk of written) {
        all.set(chunk, at);
        at += chunk.length;
      }
      return all;
    },
  };
}

describe("writing to a file", () => {
  it("writes the plaintext, and closes", async () => {
    const plaintext = filled(200_000);
    const upload = await anUpload(plaintext);
    const file = aFile();

    await saveContent(
      {
        id: upload.metadata.id,
        opened: upload.opened,
        transport: { fetch: serving(upload.ciphertext) },
      },
      file.stream,
    );

    expectBytes(file.contents, plaintext);
    expect(file.state.closed).toBe(true);
    expect(file.state.aborted).toBe(false);
  });

  /**
   * The point of this path: nothing accumulates. A file arrives in pieces and
   * each is written as it is decrypted, so what can be received is bounded by
   * the disk rather than by the tab.
   */
  it("writes in pieces rather than in one go", async () => {
    const upload = await anUpload(filled(300_000));
    const written: number[] = [];

    const counting = new WritableStream<Uint8Array>({
      write(chunk) {
        written.push(chunk.length);
      },
    });

    await saveContent(
      {
        id: upload.metadata.id,
        opened: upload.opened,
        transport: { fetch: serving(upload.ciphertext) },
      },
      counting,
    );

    expect(written.length).toBeGreaterThan(3);
    expect(Math.max(...written)).toBeLessThan(300_000);
  });

  /**
   * The guarantee that makes this path safe to use. A download that fails part
   * way must leave nothing at the chosen path - a truncated file looks like a
   * file, and somebody would open it and find it damaged much later.
   */
  it("aborts rather than closes when the content fails its integrity check", async () => {
    const upload = await anUpload(filled(200_000));
    const file = aFile();

    // A whole record removed: what remains is well-formed and decrypts for a
    // while, so bytes reach the destination before the failure is detected.
    const damaged = new Uint8Array(upload.ciphertext.length - 65536);
    damaged.set(upload.ciphertext.subarray(0, 21), 0);
    damaged.set(upload.ciphertext.subarray(21 + 65536), 21);

    await expect(
      saveContent(
        { id: upload.metadata.id, opened: upload.opened, transport: { fetch: serving(damaged) } },
        file.stream,
      ),
    ).rejects.toThrow(DownloadError);

    expect(file.state.aborted).toBe(true);
    expect(file.state.closed).toBe(false);
  });

  it("aborts when the stream is truncated", async () => {
    const upload = await anUpload(filled(200_000));
    const file = aFile();
    const truncated = upload.ciphertext.subarray(0, upload.ciphertext.length - 200);

    await expect(
      saveContent(
        { id: upload.metadata.id, opened: upload.opened, transport: { fetch: serving(truncated) } },
        file.stream,
      ),
    ).rejects.toMatchObject({ fault: "corrupt" });

    expect(file.state.aborted).toBe(true);
    expect(file.state.closed).toBe(false);
  });

  /**
   * The destination is opened before the request is made, because the picker
   * needs the click. So a request that never succeeds must still not leave an
   * empty file at the path somebody chose.
   */
  it("aborts when the instance refuses before a byte is written", async () => {
    const upload = await anUpload(filled(1000));
    const file = aFile();

    await expect(
      saveContent(
        {
          id: upload.metadata.id,
          opened: upload.opened,
          transport: { fetch: (async () => new Response(null, { status: 404 })) as typeof fetch },
        },
        file.stream,
      ),
    ).rejects.toMatchObject({ fault: "unavailable" });

    expect(file.state.aborted).toBe(true);
    expect(file.state.closed).toBe(false);
  });

  /**
   * The abort is a best effort. A destination that cannot even be aborted is a
   * worse problem than the download that failed, but the download's fault is
   * the one worth reporting - it is what a person can act on, and replacing it
   * would hide why the file never arrived.
   */
  it("reports the download's fault even when the destination cannot be aborted", async () => {
    const upload = await anUpload(filled(1000));
    const unabortable = new WritableStream<Uint8Array>({
      abort() {
        throw new Error("the disk went away");
      },
    });

    await expect(
      saveContent(
        {
          id: upload.metadata.id,
          opened: upload.opened,
          transport: { fetch: (async () => new Response(null, { status: 404 })) as typeof fetch },
        },
        unabortable,
      ),
    ).rejects.toMatchObject({ fault: "unavailable" });
  });

  it("writes an empty file as an empty file", async () => {
    const upload = await anUpload(new Uint8Array(0), "empty.bin");
    const file = aFile();

    await saveContent(
      {
        id: upload.metadata.id,
        opened: upload.opened,
        transport: { fetch: serving(upload.ciphertext) },
      },
      file.stream,
    );

    expect(file.contents).toEqual(new Uint8Array(0));
    expect(file.state.closed).toBe(true);
  });
});

describe("asking where to save", () => {
  it("detects the capability rather than the browser", () => {
    expect(canWriteToDisk({ showSaveFilePicker: () => {} })).toBe(true);
    expect(canWriteToDisk({})).toBe(false);
    expect(canWriteToDisk({ showSaveFilePicker: "not a function" })).toBe(false);
    expect(canWriteToDisk(undefined)).toBe(false);
  });

  it("suggests the name and type from the envelope", async () => {
    const picker = vi.fn(async () => ({}) as FileSystemFileHandle);

    await chooseDestination(
      { name: "report.pdf", type: "application/pdf", size: 10 },
      { showSaveFilePicker: picker },
    );

    expect(picker).toHaveBeenCalledWith({
      suggestedName: "report.pdf",
      types: [
        {
          description: "application/pdf",
          accept: { "application/pdf": [".pdf"] },
        },
      ],
    });
  });

  /**
   * Declining the dialog is somebody changing their mind, not a failure, and
   * must not be reported as one.
   */
  it("reports a declined dialog as no destination", async () => {
    const declining = async () => {
      throw new DOMException("The user aborted a request.", "AbortError");
    };

    expect(
      await chooseDestination(
        { name: "a.txt", type: "text/plain", size: 1 },
        {
          showSaveFilePicker: declining,
        },
      ),
    ).toBeNull();
  });

  it("falls back rather than failing when the picker refuses", async () => {
    // A browser that has the method but will not use it - a frame without
    // permission, a policy - must reach the blob path, not an error page.
    const refusing = async () => {
      throw new DOMException("Not allowed", "SecurityError");
    };

    expect(
      await chooseDestination(
        { name: "a.txt", type: "text/plain", size: 1 },
        {
          showSaveFilePicker: refusing,
        },
      ),
    ).toBeNull();
  });

  it("reports no destination where there is no picker", async () => {
    expect(await chooseDestination({ name: "a.txt", type: "text/plain", size: 1 }, {})).toBeNull();
  });
});

describe("the extension offered to the picker", () => {
  /**
   * The name came from the sender and is not trusted to be well formed. The
   * picker rejects anything that is not a plain suffix, and refusing to save
   * because a filename was unusual would be worse than a generic one.
   */
  it("takes a plain suffix and replaces anything else", () => {
    const cases: [string, string][] = [
      ["report.pdf", ".pdf"],
      ["archive.tar.gz", ".gz"],
      ["IMAGE.JPEG", ".JPEG"],
      ["notes", ".bin"],
      ["", ".bin"],
      [".hidden", ".bin"],
      ["trailing.", ".bin"],
      ["odd.name with spaces", ".bin"],
      ["long.extensionthatisfartoolongtobereal", ".bin"],
      ["unicode.pdf ", ".bin"],
      ["path.tar/../etc", ".bin"],
    ];

    for (const [name, want] of cases) {
      expect(extensionOf(name), name).toBe(want);
    }
  });
});

describe("offering a blob", () => {
  it("hands back a URL and the means to release it", () => {
    const created: string[] = [];
    const revoked: string[] = [];
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;

    URL.createObjectURL = ((blob: Blob) => {
      const url = `blob:test/${created.length}`;
      created.push(`${blob.type}:${blob.size}`);
      return url;
    }) as typeof URL.createObjectURL;
    URL.revokeObjectURL = ((url: string) => {
      revoked.push(url);
    }) as typeof URL.revokeObjectURL;

    try {
      const offered = offerAsBlob(filled(100), {
        name: "a.pdf",
        type: "application/pdf",
        size: 100,
      });

      expect(offered.url).toBe("blob:test/0");
      expect(created).toEqual(["application/pdf:100"]);

      // Not revoking holds the file in memory for the life of the document,
      // which on this path is the whole file.
      offered.revoke();
      expect(revoked).toEqual(["blob:test/0"]);
    } finally {
      URL.createObjectURL = originalCreate;
      URL.revokeObjectURL = originalRevoke;
    }
  });
});

describe("handing a download to the worker", () => {
  const anOpened = async () => (await anUpload(filled(10))).opened;

  /**
   * A worker that acknowledges. The handover is captured so a test can check
   * what actually crossed - this is where the file key leaves the page.
   */
  function acknowledging(reply: unknown = { type: "sendan/ready" }) {
    const seen: { message: unknown } = { message: null };
    const worker = {
      postMessage(message: unknown, transfer: Transferable[]) {
        seen.message = message;
        const port = transfer[0] as MessagePort;
        port.start?.();
        queueMicrotask(() => port.postMessage(reply));
      },
    } as unknown as ServiceWorker;
    return { worker, seen };
  }

  it("returns the URL that starts the download", async () => {
    const { worker } = acknowledging();
    const url = await offerViaWorker(worker, "an-upload-id", await anOpened());

    expect(url).not.toBeNull();
    expect(url?.startsWith(SAVE_PATH)).toBe(true);
    // The worker recognises what the page produced. These two agree or the
    // download reaches the network and 404s.
    expect(tokenOf(`https://send.example${url}`)).not.toBeNull();
  });

  it("sends the key, the token and the description, and nothing else", async () => {
    const opened = await anOpened();
    const { worker, seen } = acknowledging();

    await offerViaWorker(worker, "an-upload-id", opened);

    expect(seen.message).toMatchObject({
      type: "sendan/save",
      handover: {
        id: "an-upload-id",
        fileKey: opened.fileKey,
        file: opened.file,
      },
    });
  });

  /**
   * A different token every time. Two downloads in one tab must not be able to
   * claim each other's handover, and a token that could be guessed would be a
   * file key another page on this origin could ask for.
   */
  it("uses a fresh token each time", () => {
    const tokens = new Set(Array.from({ length: 200 }, () => newSaveToken()));
    expect(tokens.size).toBe(200);
    for (const token of tokens) {
      expect(tokenOf(`https://send.example${SAVE_PATH}${token}`), token).toBe(token);
    }
  });

  /**
   * The acknowledgement is what makes this safe to navigate to. Without it the
   * page could navigate before the worker had stored anything, and the download
   * would fail as "no longer waiting" - for a reason nobody could diagnose.
   */
  it("gives up rather than navigating to a URL nothing will answer", async () => {
    const silent = { postMessage() {} } as unknown as ServiceWorker;

    expect(await offerViaWorker(silent, "an-upload-id", await anOpened(), "", 20)).toBeNull();
  });

  it("gives up when the worker answers something else", async () => {
    const { worker } = acknowledging({ type: "sendan/something-else" });
    expect(await offerViaWorker(worker, "an-upload-id", await anOpened(), "", 50)).toBeNull();
  });
});

describe("deciding whether the worker is available", () => {
  it("requires a secure context and a service worker container", () => {
    expect(canStreamViaWorker({ isSecureContext: true, navigator: { serviceWorker: {} } })).toBe(
      true,
    );
    // Not over plain HTTP: the API is absent, and pretending otherwise would
    // mean a download that fails instead of falling back.
    expect(canStreamViaWorker({ isSecureContext: false, navigator: { serviceWorker: {} } })).toBe(
      false,
    );
    expect(canStreamViaWorker({ isSecureContext: true, navigator: {} })).toBe(false);
    expect(canStreamViaWorker({})).toBe(false);
    expect(canStreamViaWorker(undefined)).toBe(false);
  });

  it("reports no worker where there is none, rather than throwing", async () => {
    expect(await readySaveWorker({ isSecureContext: false, navigator: {} })).toBeNull();
  });

  it("reports no worker when registration fails", async () => {
    const failing = {
      isSecureContext: true,
      navigator: {
        serviceWorker: {
          register: async () => {
            throw new Error("refused");
          },
          ready: Promise.resolve({}),
          controller: null,
          addEventListener() {},
        },
      },
    };
    expect(await readySaveWorker(failing)).toBeNull();
  });

  /**
   * Registered is not the same as in charge. A worker that is active but not
   * controlling this page does not see its requests, so the save URL would go
   * to the network and 404.
   */
  it("waits for the worker to take control, and returns it", async () => {
    const controller = { id: "the-worker" } as unknown as ServiceWorker;
    const listeners: (() => void)[] = [];
    const container = {
      register: async () => ({}),
      ready: Promise.resolve({}),
      controller: null as ServiceWorker | null,
      addEventListener(_: string, fn: () => void) {
        listeners.push(fn);
      },
    };

    const pending = readySaveWorker({
      isSecureContext: true,
      navigator: { serviceWorker: container },
    });
    await new Promise((resolve) => setTimeout(resolve, 10));

    container.controller = controller;
    for (const fn of listeners) fn();

    expect(await pending).toBe(controller);
  });

  /**
   * A worker that never takes control must not leave the page waiting for
   * ever. Giving up falls back to holding the file in memory, which is worse
   * but finite; waiting is a download that never starts and never says why.
   */
  it("gives up if the worker never takes control", async () => {
    const container = {
      register: async () => ({}),
      ready: Promise.resolve({}),
      controller: null,
      addEventListener() {},
    };

    const got = await readySaveWorker(
      { isSecureContext: true, navigator: { serviceWorker: container } },
      30,
    );
    expect(got).toBeNull();
  });

  it("uses the controller already in charge", async () => {
    const controller = { id: "already-controlling" } as unknown as ServiceWorker;
    const container = {
      register: async () => ({}),
      ready: Promise.resolve({}),
      controller,
      addEventListener() {},
    };

    expect(
      await readySaveWorker({ isSecureContext: true, navigator: { serviceWorker: container } }),
    ).toBe(controller);
  });
});
