<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { page } from "$app/state";
  import {
    type DownloadFault,
    type DownloadProgress,
    DownloadError,
    type OpenedUpload,
    type UploadMetadata,
    downloadContent,
    explain,
    fetchMetadata,
    openUpload,
    saveContent,
  } from "$lib/download";
  import {
    chooseDestination,
    offerAsBlob,
    offerViaWorker,
    readySaveWorker,
  } from "$lib/save";
  import { fragmentIsPresent, parseLink } from "$lib/link";

  type Phase = "reading" | "password" | "ready" | "downloading" | "saved";

  let phase = $state<Phase>("reading");
  let published = $state<UploadMetadata | null>(null);
  let opened = $state<OpenedUpload | null>(null);
  let password = $state("");
  let working = $state(false);
  let fault = $state<DownloadFault | null>(null);
  let retryAfter = $state<number | null>(null);
  let progress = $state<DownloadProgress | null>(null);
  let offered = $state<{ url: string; revoke(): void } | null>(null);
  let via = $state<"disk" | "worker" | "memory" | null>(null);

  let link: { fileID: Uint8Array; linkSecret: Uint8Array } | null = null;

  const id = $derived(page.params.id ?? "");

  /**
   * Read once, on mount.
   *
   * The secret is in the fragment, which the server never receives, so there is
   * nothing to read until the page is running - which is also why this route
   * is neither prerendered nor server-rendered.
   */
  onMount(async () => {
    const here = window.location.href;

    if (!fragmentIsPresent(here)) {
      fail("link-incomplete");
      return;
    }
    link = parseLink(here);
    if (link === null) {
      fail("link-damaged");
      return;
    }

    try {
      published = await fetchMetadata(id);
    } catch (error) {
      report(error);
      return;
    }

    if (published.passwordRequired) {
      phase = "password";
      return;
    }
    await open("");
  });

  function fail(which: DownloadFault, seconds: number | null = null) {
    fault = which;
    retryAfter = seconds;
  }

  function report(error: unknown) {
    if (error instanceof DownloadError) {
      fail(error.fault, error.retryAfter);
      return;
    }
    if (error instanceof DOMException && error.name === "AbortError") return;
    fail("unreachable");
  }

  /** Derives, unwraps and reads the description. Nothing here touches the network. */
  async function open(candidate: string) {
    if (published === null || link === null) return;
    working = true;
    fault = null;

    try {
      opened = await openUpload(link.fileID, link.linkSecret, published, candidate);
      // Not needed again, and there is no reason to keep it.
      password = "";
      phase = "ready";
    } catch (error) {
      report(error);
      // A wrong password is worth another attempt; a damaged link is not, and
      // offering the field again would suggest otherwise.
      phase = fault === "password-wrong" ? "password" : phase;
    } finally {
      working = false;
    }
  }

  function submitPassword(event: SubmitEvent) {
    event.preventDefault();
    void open(password);
  }

  async function download() {
    if (opened === null) return;

    // Asked for before anything else, and specifically before any await on the
    // network. The picker needs the user gesture that this click is, and a
    // gesture does not survive a round trip - prompting once the transfer had
    // started would be refused by the browser, on a path only reachable with a
    // real click against a real instance.
    const handle = await chooseDestination(opened.file);

    working = true;
    fault = null;
    phase = "downloading";

    const track = (p: DownloadProgress) => {
      progress = p;
    };

    try {
      if (handle !== null) {
        // Nothing accumulates: each record is decrypted and written as it
        // arrives, so the size of the file is bounded by the disk. If anything
        // fails the write is aborted rather than closed, and the chosen path is
        // left untouched rather than holding a truncated file.
        await saveContent({ id, opened, onProgress: track }, await handle.createWritable());
        via = "disk";
        phase = "saved";
        return;
      }

      // No picker: Firefox and Safari. A Service Worker answers a request this
      // page makes to itself with a stream of plaintext, and the browser's own
      // download machinery writes it - so nothing is held here either.
      const worker = await readySaveWorker();
      const saveUrl = worker === null ? null : await offerViaWorker(worker, id, opened);
      if (saveUrl !== null) {
        via = "worker";
        phase = "saved";
        // Navigating rather than fetching: the response is an attachment, so
        // this hands it to the browser instead of bringing it back into the tab.
        window.location.href = saveUrl;
        return;
      }

      // Neither. The whole file is held in memory, which is what bounds this
      // path - a file too large for the tab fails here, with nothing better
      // available in this browser.
      const plaintext = await downloadContent({ id, opened, onProgress: track });
      offered = offerAsBlob(plaintext, opened.file);
      via = "memory";
      phase = "saved";
    } catch (error) {
      report(error);
      phase = "ready";
    } finally {
      working = false;
    }
  }

  // The object URL holds the whole file until it is released, and the anchor
  // has been used by the time the page is left.
  onDestroy(() => offered?.revoke());

  const percent = $derived(
    progress === null || progress.total === 0
      ? 0
      : Math.floor((progress.received / progress.total) * 100),
  );

  /** Sizes are shown in whole units; the exact byte count is never the question. */
  function readableSize(bytes: number): string {
    const units = ["bytes", "kB", "MB", "GB", "TB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1000 && unit < units.length - 1) {
      value /= 1000;
      unit++;
    }
    return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
  }
</script>

<h1>Download</h1>

{#if fault !== null && phase !== "password"}
  <p class="failure" role="alert">{explain(fault)}</p>
  {#if retryAfter !== null}
    <p class="note">Try again in {retryAfter} seconds.</p>
  {/if}
{:else if phase === "reading"}
  <p aria-live="polite">Reading…</p>
{/if}

{#if phase === "password"}
  <form onsubmit={submitPassword}>
    <p>This file is protected with a password.</p>
    <p>
      <label for="password">Password</label><br />
      <input
        id="password"
        type="password"
        bind:value={password}
        autocomplete="off"
        disabled={working}
        required
      />
    </p>
    {#if fault !== null}
      <p class="failure" role="alert">{explain(fault)}</p>
    {/if}
    <p>
      <button type="submit" disabled={working}>
        {working ? "Checking…" : "Unlock"}
      </button>
    </p>
    <p class="note">
      The password is checked here, not by the instance: it is part of the key,
      so a wrong one produces a key that does not fit. Nothing is sent while you
      try.
    </p>
  </form>
{/if}

{#if opened !== null && (phase === "ready" || phase === "downloading" || phase === "saved")}
  <dl>
    <dt>Name</dt>
    <dd>{opened.file.name}</dd>
    <dt>Type</dt>
    <dd>{opened.file.type}</dd>
    <dt>Size</dt>
    <dd>{readableSize(opened.file.size)}</dd>
  </dl>

  {#if published?.expiresAt}
    <p class="note">Expires {published.expiresAt.toLocaleString()}.</p>
  {/if}
  {#if published?.downloadsRemaining !== null && published?.downloadsRemaining !== undefined}
    <p class="note">
      {published.downloadsRemaining} download{published.downloadsRemaining === 1 ? "" : "s"}
      remaining.
    </p>
  {/if}
{/if}

{#if phase === "ready"}
  <p>
    <button type="button" onclick={download} disabled={working}>Download and decrypt</button>
  </p>
{:else if phase === "downloading"}
  <p>
    <progress value={progress?.received ?? 0} max={progress?.total ?? 1} aria-describedby="stage">
      {percent}%
    </progress>
  </p>
  <p id="stage" aria-live="polite">Downloading and decrypting… {percent}%</p>
{:else if phase === "saved" && opened !== null}
  {#if via === "disk"}
    <p>Saved {opened.file.name}.</p>
    <p class="note">
      Written straight to the file you chose as it arrived, so the size was
      never limited by this tab.
    </p>
  {:else if via === "worker"}
    <p>Saving {opened.file.name}…</p>
    <p class="note">
      Handed to your browser's downloads, decrypted piece by piece as it
      arrives, so the size was never limited by this tab.
    </p>
  {:else if via === "memory" && offered !== null}
    <p>
      <a href={offered.url} download={opened.file.name}>Save {opened.file.name}</a>
    </p>
  {/if}
  <p class="note">
    Decrypted in this tab. Nothing that could open it was sent to the instance.
  </p>
{/if}

<style>
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
  }

  dt {
    font-weight: bold;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  progress {
    width: 100%;
  }

  .note {
    font-size: 0.9rem;
  }

  .failure {
    font-weight: bold;
  }
</style>
