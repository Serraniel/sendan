// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * The list of uploads this browser made.
 *
 * There is no account, so there is nothing on the instance that knows an upload
 * is yours. What makes a "my uploads" view possible at all is this: the browser
 * keeps the link and the owner token, and the instance keeps neither.
 *
 * ## What is stored, and what that costs
 *
 * The **whole link, including the secret after the `#`**, and the owner token.
 * Together they open the file and remove it. They are held in IndexedDB, which
 * means:
 *
 * - Anybody who can read this browser profile can open every file in this list.
 *   That is the same exposure as a bookmark to the link would be, and it is the
 *   price of the feature.
 * - Clearing site data destroys it, and **nothing can bring it back**. The
 *   instance does not have the secret and cannot reissue the owner token, both
 *   by design. That is not a limitation to be fixed later; it is the same
 *   property that stops the operator reading your files.
 *
 * The interface has to say so before somebody relies on it, which is why
 * `mustWarn` exists and why the upload page asks before the first record is
 * written rather than after.
 */

const DATABASE = "sendan";
const STORE = "uploads";
const VERSION = 1;

/** Where the warning-acknowledged flag lives. Deliberately not IndexedDB: it is
 * about this browser, not about any upload, and it should survive the list
 * being emptied. */
const ACKNOWLEDGED = "sendan.uploads.acknowledged";

/** One upload this browser made. */
export interface StoredUpload {
  /** The identifier, which is also the key. */
  id: string;
  /** The whole link, secret included. Without it the file cannot be opened. */
  link: string;
  /** Base64url, as the interface shows it. Without it the file cannot be removed. */
  ownerToken: string;
  name: string;
  size: number;
  createdAt: number;
  /** Milliseconds since the epoch, or null when the upload never expires. */
  expiresAt: number | null;
}

/** Whether this browser can keep a list at all. */
export function isSupported(): boolean {
  return typeof indexedDB !== "undefined";
}

/**
 * Whether the warning still has to be shown.
 *
 * Before the first record is written, not after: somebody who has already
 * closed the tab has already relied on it.
 */
export function mustWarn(): boolean {
  try {
    return localStorage.getItem(ACKNOWLEDGED) !== "yes";
  } catch {
    // A browser that refuses storage will refuse the list too, and warning
    // again costs nothing.
    return true;
  }
}

/** Records that the warning has been read. */
export function acknowledge(): void {
  try {
    localStorage.setItem(ACKNOWLEDGED, "yes");
  } catch {
    // Not being able to remember the acknowledgement is not a reason to fail
    // an upload.
  }
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("indexeddb: open failed"));
    // A second tab holding an older version open blocks the upgrade. Failing is
    // better than waiting forever on something the user cannot see.
    request.onblocked = () => reject(new Error("indexeddb: blocked by another tab"));
  });
}

function run<T>(
  mode: IDBTransactionMode,
  work: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const request = work(tx.objectStore(STORE));

        // Resolved when the transaction commits, not when the request
        // succeeds. A request succeeds while its transaction is still open, so
        // resolving there hands control back before anything is durable - and
        // a caller that navigates on the next line, as the upload page does,
        // can leave the browser to discard the write. The upload arrives, the
        // record does not, and the list is empty for a file that was sent.
        let result: T | undefined;
        request.onsuccess = () => {
          result = request.result;
        };
        request.onerror = () => reject(request.error ?? new Error("indexeddb: request failed"));

        tx.oncomplete = () => {
          db.close();
          resolve(result as T);
        };
        tx.onabort = () => {
          db.close();
          reject(tx.error ?? new Error("indexeddb: transaction aborted"));
        };
      }),
  );
}

/** Adds an upload to the list, replacing any record with the same identifier. */
export async function remember(upload: StoredUpload): Promise<void> {
  await run("readwrite", (store) => store.put(upload));
}

/**
 * Every upload this browser knows about, newest first.
 *
 * Expired ones are dropped rather than shown: the record would name a file that
 * no longer exists, and a list that lies about what is still there is worse than
 * a shorter one.
 */
export async function list(now: number = Date.now()): Promise<StoredUpload[]> {
  const all = await run<StoredUpload[]>("readonly", (store) => store.getAll());
  const { live, expired } = partition(all, now);

  if (expired.length > 0) {
    // Tidied opportunistically. A record for a file that has expired is not
    // sensitive, but it is clutter that never goes away on its own.
    await Promise.all(expired.map((u) => forget(u.id)));
  }
  return live;
}

/**
 * Splits records into those still worth showing and those that are not.
 *
 * Separated from the storage so it can be tested without a browser: what
 * belongs in the list is a decision, and the IndexedDB around it is plumbing.
 */
export function partition(
  all: StoredUpload[],
  now: number,
): { live: StoredUpload[]; expired: StoredUpload[] } {
  const live: StoredUpload[] = [];
  const expired: StoredUpload[] = [];

  for (const upload of all) {
    // An upload with no deadline never expires, so it stays until the person
    // who made it says otherwise.
    if (upload.expiresAt === null || upload.expiresAt > now) {
      live.push(upload);
    } else {
      expired.push(upload);
    }
  }

  // Newest first: the thing somebody just sent is the thing they are looking
  // for.
  live.sort((a, b) => b.createdAt - a.createdAt);
  return { live, expired };
}

/** Removes one record. The upload itself is unaffected. */
export async function forget(id: string): Promise<void> {
  await run("readwrite", (store) => store.delete(id));
}

/** Empties the list. The uploads themselves are unaffected. */
export async function forgetAll(): Promise<void> {
  await run("readwrite", (store) => store.clear());
}
