// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/// <reference lib="webworker" />

/**
 * The Service Worker.
 *
 * It exists for one thing: answering a save request with a stream of decrypted
 * plaintext, so a browser without the File System Access API can write a file
 * to disk without the page holding it in memory. See `src/lib/saveworker.ts`,
 * where the logic is, and `docs/design.md` §4.6.
 *
 * It deliberately caches nothing. A cached client would mean a browser running
 * code an instance served at some point in the past, which is precisely the
 * thing the source report and the asset manifest exist to make checkable. An
 * offline client is not worth an unverifiable one.
 */

import { buildSaveResponse, type Handover, HandoverStore, tokenOf } from "./lib/saveworker.js";

// Relative rather than the $lib alias, and self read through globalThis: both
// so this file can be imported by a test runner, which has no Service Worker
// scope and no SvelteKit resolution. The wiring below is small but it is where
// a mistake would be invisible - a message handler that accepted the wrong
// shape, or a fetch handler that claimed requests it should have let through.
const worker = (globalThis as { self?: unknown }).self as unknown as ServiceWorkerGlobalScope;

const waiting = new HandoverStore();

// Taking over at once rather than on the next navigation. The page registers
// this worker and then immediately needs it to answer, so waiting for a reload
// would mean the first download of a visit silently falling back.
worker.addEventListener("install", () => {
  void worker.skipWaiting();
});

worker.addEventListener("activate", (event) => {
  event.waitUntil(worker.clients.claim());
});

interface HandoverMessage {
  type: "sendan/save";
  token: string;
  handover: Omit<Handover, "fileKey"> & { fileKey: Uint8Array };
}

worker.addEventListener("message", (event) => {
  const data = event.data as Partial<HandoverMessage> | null;
  if (data?.type !== "sendan/save" || typeof data.token !== "string") return;

  waiting.put(data.token, data.handover as Handover);
  // Acknowledged before the page navigates, so the handover cannot be claimed
  // before it was stored - which would fall back to a whole-file download the
  // person did not ask for.
  event.ports[0]?.postMessage({ type: "sendan/ready", token: data.token });
});

worker.addEventListener("fetch", (event) => {
  const token = tokenOf(event.request.url);
  if (token === null) return;

  const handover = waiting.take(token);
  if (handover === null) {
    // Expired, already used, or never registered. Answering rather than
    // declining, because declining would send the request to the network and
    // the instance would answer 404 for a path it has never heard of.
    event.respondWith(
      new Response("This download is no longer waiting to be saved.", {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      }),
    );
    return;
  }

  event.respondWith(buildSaveResponse(handover));
});
