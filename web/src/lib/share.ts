// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * Handing a link to the operating system's own share sheet.
 *
 * The link is the whole product of this application and the one thing somebody
 * does with it is send it somewhere. On a phone the clipboard is the long way
 * round.
 *
 * ## What is being handed over
 *
 * The fragment is the key. Sharing the link shares it - which is the intent,
 * and no worse than copying. What differs is deliberateness: copying goes to
 * one destination a person chose, a sheet offers a dozen, and a target that
 * generates a link preview then holds the key in that application for as long
 * as it keeps the message. The instance never sees the fragment; the app does.
 *
 * So the sheet carries the link and nothing else. A warning appended to `text`
 * would ride along into whatever message the person is about to send, which
 * puts our sentence in their conversation. The page says it instead, where it
 * belongs.
 */

/** What the platform is asked to share. */
export interface Shareable {
  url: string;
  title?: string;
}

/** Navigator, narrowed to what this needs, so a test can pass a fake one. */
export interface Sharer {
  share?: (data: ShareData) => Promise<void>;
  canShare?: (data: ShareData) => boolean;
}

/**
 * Whether a share sheet is worth offering.
 *
 * Feature detection rather than a browser list: this exists on Android, on iOS,
 * on Safari and Chromium desktop, and not on Firefox desktop - and that set
 * moves. `canShare` is asked with the payload rather than in the abstract,
 * because a platform may support sharing and refuse this particular shape.
 *
 * A browser without it is not offered a control that does nothing: Copy link is
 * already the answer there, and a disabled button beside it would be noise.
 */
export function canShare(what: Shareable, from: Sharer = navigatorOrNothing()): boolean {
  if (typeof from.share !== "function") return false;
  // Some platforms have share and not canShare. Having the first is the
  // requirement; the second only narrows it.
  if (typeof from.canShare !== "function") return true;
  try {
    return from.canShare(payload(what));
  } catch {
    return false;
  }
}

/** The result of asking, so a caller can tell refusal from failure. */
export type ShareOutcome = "shared" | "dismissed" | "unavailable";

/**
 * Opens the sheet.
 *
 * A person closing it without choosing is not an error, and must not be
 * reported as one: the platform rejects with AbortError either way, so the two
 * are told apart here rather than left to a caller to guess.
 */
export async function share(
  what: Shareable,
  from: Sharer = navigatorOrNothing(),
): Promise<ShareOutcome> {
  if (typeof from.share !== "function") return "unavailable";
  try {
    await from.share(payload(what));
    return "shared";
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") return "dismissed";
    return "unavailable";
  }
}

function payload(what: Shareable): ShareData {
  // The link and nothing else. See the note at the top of this file about why
  // no warning travels with it.
  return what.title === undefined ? { url: what.url } : { url: what.url, title: what.title };
}

function navigatorOrNothing(): Sharer {
  try {
    return typeof navigator === "undefined" ? {} : navigator;
  } catch {
    return {};
  }
}
