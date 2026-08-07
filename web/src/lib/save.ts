// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Getting a decrypted file out of the tab and onto the disk.
 *
 * Two ways, and which one is available decides how large a file can be
 * received. Writing straight to a file the person chose holds nothing, so the
 * size is bounded by the disk. A blob holds the whole file in memory first, so
 * it is bounded by the tab - a few hundred megabytes, then a failure with no
 * useful message.
 */

import type { Metadata } from "../crypto/index.js";
import type { OpenedUpload } from "./download.js";
import { toBase64Url } from "./link.js";
import { type Handover, SAVE_PATH } from "./saveworker.js";

/** The part of the File System Access API this uses. */
interface SaveFilePicker {
  showSaveFilePicker(options: {
    suggestedName?: string;
    types?: { description: string; accept: Record<string, string[]> }[];
  }): Promise<FileSystemFileHandle>;
}

/**
 * Whether this browser can be asked for somewhere to write.
 *
 * Absent in Firefox and Safari at the time of writing, and absent everywhere in
 * a cross-origin frame, so the fallback is not a rare path.
 */
export function canWriteToDisk(target: unknown = globalThis): boolean {
  return typeof (target as Partial<SaveFilePicker>)?.showSaveFilePicker === "function";
}

/**
 * A save destination the person chose, or null if they declined.
 *
 * Must be called from the click that starts the download, not after it. The
 * picker requires a user gesture, and a gesture does not survive an await on
 * the network - prompting once the transfer had begun would be refused by the
 * browser, on a path only reachable with a real server and a real click.
 *
 * Declining is not a failure. It is somebody changing their mind, and is
 * reported as null rather than thrown.
 */
export async function chooseDestination(
  file: Metadata,
  target: unknown = globalThis,
): Promise<FileSystemFileHandle | null> {
  // No capability check first. Calling a method that is not there throws, and
  // the handler below already has to treat "the picker did not produce a
  // destination" as the fallback case - so a guard would be a second path
  // reaching the same answer, and one no test could tell from its absence.
  // canWriteToDisk exists for the interface, which needs to know before it
  // offers the choice.
  try {
    return await (target as SaveFilePicker).showSaveFilePicker({
      suggestedName: file.name,
      types: [
        {
          description: file.type,
          // The name is what a recipient sees, so its extension is kept. The
          // envelope's type is used rather than one guessed from the name,
          // because the name came from the sender and the type is what the
          // sender's browser actually reported.
          accept: { [file.type]: [extensionOf(file.name)] },
        },
      ],
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return null;
    // Anything else - a browser that has the method but refuses, a frame
    // without permission - falls back rather than failing the download.
    return null;
  }
}

/**
 * The extension of a name, as the picker wants it.
 *
 * A name with no extension, or one that is only an extension, yields ".bin":
 * the API rejects an empty string and a leading dot, and refusing to save
 * because a filename was unusual would be worse than a generic suffix.
 */
export function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return ".bin";

  const extension = name.slice(dot);
  // The picker refuses anything that is not a plain suffix, and a name arriving
  // from a sender is not trusted to be one.
  return /^\.[A-Za-z0-9]{1,16}$/.test(extension) ? extension : ".bin";
}

/**
 * Offers the file as a link the browser will download.
 *
 * The whole file is already in memory here, which is what this path costs. The
 * object URL must be revoked once it has been used or the memory is held for
 * the life of the document, so the caller is handed the means to do that.
 */
export function offerAsBlob(
  plaintext: Uint8Array,
  file: Metadata,
): { url: string; revoke(): void } {
  const blob = new Blob([plaintext as BufferSource], { type: file.type });
  const url = URL.createObjectURL(blob);
  return { url, revoke: () => URL.revokeObjectURL(url) };
}

/**
 * Whether the browser can save through a Service Worker.
 *
 * The path that matters for Firefox and Safari, which have no way to hand a
 * page a file to write. It needs a secure context, which localhost counts as.
 */
export function canStreamViaWorker(target: unknown = globalThis): boolean {
  const scope = target as { navigator?: { serviceWorker?: unknown }; isSecureContext?: boolean };
  return scope?.isSecureContext === true && scope?.navigator?.serviceWorker !== undefined;
}

/**
 * Registers the worker and waits until it is the one in charge.
 *
 * Registration alone is not enough: a worker that is installed but not yet
 * controlling this page will not see its requests, and the save would fall
 * through to the network as a 404. Resolves to null if any of that fails, which
 * means the caller falls back rather than the download failing.
 */
export async function readySaveWorker(
  target: unknown = globalThis,
  timeoutMs = 5000,
): Promise<ServiceWorker | null> {
  if (!canStreamViaWorker(target)) return null;
  const container = (target as { navigator: { serviceWorker: ServiceWorkerContainer } }).navigator
    .serviceWorker;

  try {
    // An absolute path, and scope "/". The download page lives at /d/<id>, and
    // a relative registration from there would ask for /d/service-worker.js and
    // take a scope that does not cover the save path.
    await container.register("/service-worker.js", { scope: "/" });
    await container.ready;
    if (container.controller !== null) return container.controller;

    // First visit: the worker is active but is not yet controlling this page.
    // clients.claim() in the worker fixes that, and this waits for it rather
    // than assuming how long it takes.
    return await new Promise<ServiceWorker | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      container.addEventListener(
        "controllerchange",
        () => {
          clearTimeout(timer);
          resolve(container.controller);
        },
        { once: true },
      );
    });
  } catch {
    return null;
  }
}

/** A token for one handover: unguessable, and long enough not to collide. */
export function newSaveToken(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(18)));
}

/**
 * Hands the worker what it needs, and returns the URL that starts the download.
 *
 * The file key crosses to the worker here. It goes by postMessage to this
 * origin's own worker, never over the network, and the worker forgets it the
 * moment the download begins.
 *
 * Resolves to null if the worker does not acknowledge, so a caller falls back
 * to holding the file in memory rather than navigating to a URL that nothing
 * will answer.
 */
export async function offerViaWorker(
  worker: ServiceWorker,
  id: string,
  opened: OpenedUpload,
  origin = "",
  timeoutMs = 5000,
): Promise<string | null> {
  const token = newSaveToken();
  const handover: Handover = {
    id,
    authToken: toBase64Url(opened.keys.authToken),
    fileKey: opened.fileKey,
    file: opened.file,
    origin,
  };

  const acknowledged = await new Promise<boolean>((resolve) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => {
      channel.port1.close();
      resolve(false);
    }, timeoutMs);

    channel.port1.onmessage = (event: MessageEvent) => {
      clearTimeout(timer);
      channel.port1.close();
      resolve((event.data as { type?: string } | null)?.type === "sendan/ready");
    };

    // Acknowledged before navigating, because a navigation that arrives before
    // the handover was stored is answered as "no longer waiting" - a download
    // that fails for a reason nobody could diagnose.
    worker.postMessage({ type: "sendan/save", token, handover }, [channel.port2]);
  });

  return acknowledged ? `${SAVE_PATH}${token}` : null;
}
