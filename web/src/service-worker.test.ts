// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { beforeAll, describe, expect, it } from "vitest";
import { encryptBytes, newFileKey } from "./crypto/index.js";
import { SAVE_PATH } from "./lib/saveworker.js";

type Listener = (event: unknown) => void;

const listeners = new Map<string, Listener>();
const claimed = { install: false, activate: false };

/**
 * A Service Worker scope, which no test runner has.
 *
 * The wiring is small, but it is where a mistake would be invisible: a message
 * handler that took the wrong shape, or a fetch handler that claimed requests
 * it should have let through to the network.
 */
beforeAll(async () => {
  (globalThis as { self?: unknown }).self = {
    addEventListener(type: string, fn: Listener) {
      listeners.set(type, fn);
    },
    skipWaiting: async () => {
      claimed.install = true;
    },
    clients: {
      claim: async () => {
        claimed.activate = true;
      },
    },
  };
  await import("./service-worker.js");
});

const fire = (type: string, event: unknown) => listeners.get(type)?.(event);

/** A fetch event that records what it was answered with. */
function aFetch(url: string) {
  const answered: { with: Promise<Response> | null } = { with: null };
  return {
    event: {
      request: { url },
      respondWith(response: Promise<Response> | Response) {
        answered.with = Promise.resolve(response);
      },
    },
    answered,
  };
}

/** A message event carrying a reply port. */
function aMessage(data: unknown) {
  const replies: unknown[] = [];
  return {
    event: { data, ports: [{ postMessage: (m: unknown) => replies.push(m) }] },
    replies,
  };
}

describe("the worker's wiring", () => {
  it("takes over at once rather than on the next navigation", async () => {
    // A page registers the worker and then immediately needs it to answer.
    // Waiting for a reload would make the first download of a visit fall back.
    fire("install", {});
    const waited: Promise<unknown>[] = [];
    fire("activate", { waitUntil: (p: Promise<unknown>) => waited.push(p) });
    await Promise.all(waited);

    expect(claimed.install).toBe(true);
    expect(claimed.activate).toBe(true);
  });

  it("stores a handover and says so before the page navigates", async () => {
    const fileKey = newFileKey();
    const { event, replies } = aMessage({
      type: "sendan/save",
      token: "abcdefghijklmnopq",
      handover: {
        id: "x",
        authToken: "t",
        fileKey,
        file: { name: "a", type: "text/plain", size: 1 },
      },
    });

    fire("message", event);
    expect(replies).toEqual([{ type: "sendan/ready", token: "abcdefghijklmnopq" }]);
  });

  /**
   * Anything else must be ignored. A worker that acted on any message would act
   * on messages from other code running in this origin.
   */
  it("ignores a message that is not a handover", () => {
    for (const data of [
      null,
      "a string",
      { type: "something/else", token: "abcdefghijklmnopq" },
      { type: "sendan/save" },
      { type: "sendan/save", token: 42 },
    ]) {
      const { event, replies } = aMessage(data);
      fire("message", event);
      expect(replies, JSON.stringify(data)).toEqual([]);
    }
  });

  /**
   * Everything that is not a save URL must reach the network. A worker that
   * claimed more would be answering for the client itself, and for the API.
   */
  it("lets everything but its own path through", () => {
    for (const url of [
      "https://send.example/",
      "https://send.example/d/AAAAAAAAAAAAAAAAAAAAAA",
      "https://send.example/api/uploads/abc/content",
      "https://send.example/service-worker.js",
      "https://send.example/_app/immutable/entry/app.js",
    ]) {
      const { event, answered } = aFetch(url);
      fire("fetch", event);
      expect(answered.with, url).toBeNull();
    }
  });

  it("serves a handover it was given, once", async () => {
    const fileKey = newFileKey();
    const plaintext = new Uint8Array(5000).map((_, i) => i % 256);
    const ciphertext = await encryptBytes(fileKey, plaintext);

    const original = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(new Blob([ciphertext as BufferSource]).stream(), {
        status: 200,
      })) as typeof fetch;

    try {
      const { event: message } = aMessage({
        type: "sendan/save",
        token: "servedoncetoken12",
        handover: {
          id: "x",
          authToken: "t",
          fileKey,
          file: { name: "a.bin", type: "text/plain", size: plaintext.length },
        },
      });
      fire("message", message);

      const first = aFetch(`https://send.example${SAVE_PATH}servedoncetoken12`);
      fire("fetch", first.event);
      const response = await (first.answered.with as Promise<Response>);
      expect(response.status).toBe(200);
      expect(new Uint8Array(await response.arrayBuffer())).toEqual(plaintext);

      // The handover held a file key and is gone. A second attempt is answered
      // rather than declined: declining would send it to the network, where the
      // instance has never heard of this path.
      const second = aFetch(`https://send.example${SAVE_PATH}servedoncetoken12`);
      fire("fetch", second.event);
      const again = await (second.answered.with as Promise<Response>);
      expect(again.status).toBe(404);
      expect(again.headers.get("Content-Disposition")).toBeNull();
    } finally {
      globalThis.fetch = original;
    }
  });

  it("answers an unknown token rather than letting it reach the network", async () => {
    const { event, answered } = aFetch(`https://send.example${SAVE_PATH}neverregistered1`);
    fire("fetch", event);

    expect(answered.with).not.toBeNull();
    expect((await (answered.with as Promise<Response>)).status).toBe(404);
  });
});
