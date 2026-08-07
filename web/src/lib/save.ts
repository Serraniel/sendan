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
