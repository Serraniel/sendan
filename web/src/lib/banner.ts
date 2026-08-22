// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Whether an operator's notice has already been read.
 *
 * Dismissing one is a fact about this browser, so it is kept here and never
 * sent anywhere. What is stored is a digest of the text rather than the text
 * itself: it keeps the entry small, it does not copy an operator's words into
 * storage, and - the reason it exists - a changed notice is a different notice
 * and must appear again. A flag saying only "dismissed" would silence every
 * future notice as well, including the one that matters.
 */

/** Where the acknowledgement lives, beside the theme and the upload list. */
export const BANNER_KEY = "sendan.banner.seen";

/** Storage, narrowed so a test can pass a fake one. */
export interface BannerStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/**
 * A short digest of the text.
 *
 * FNV-1a: not cryptographic, and it does not need to be. Nothing turns on a
 * collision here beyond a changed notice occasionally not reappearing, and the
 * alternative - hashing with WebCrypto - would make this asynchronous for no
 * gain.
 */
export function digest(text: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(36);
}

/** Whether this notice should be shown. */
export function unseen(text: string, store: BannerStore | null = safeStore()): boolean {
  if (store === null) return true;
  try {
    return store.getItem(BANNER_KEY) !== digest(text);
  } catch {
    // A browser that refuses storage sees the notice every time, which is the
    // safe direction: showing a notice twice is better than never showing one.
    return true;
  }
}

/** Records that this notice has been read. */
export function markSeen(text: string, store: BannerStore | null = safeStore()): void {
  if (store === null) return;
  try {
    store.setItem(BANNER_KEY, digest(text));
  } catch {
    // Not being able to remember it is not a reason to refuse to dismiss it.
  }
}

function safeStore(): BannerStore | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}
