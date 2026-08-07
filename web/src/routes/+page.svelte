<script lang="ts">
  import { page } from "$app/state";
  import { downloadLink, toBase64Url } from "$lib/link";
  import { TusError } from "$lib/tus";
  import { type UploadProgress, type UploadResult, uploadFile } from "$lib/upload";

  let file = $state<File | null>(null);
  let password = $state("");
  let ttlSeconds = $state(0);
  let maxDownloads = $state(0);

  let progress = $state<UploadProgress | null>(null);
  let result = $state<UploadResult | null>(null);
  let failure = $state<string | null>(null);
  let copied = $state(false);
  let controller: AbortController | null = null;

  const busy = $derived(progress !== null && result === null);

  const link = $derived(
    result === null ? "" : downloadLink(page.url.origin, result.fileID, result.linkSecret),
  );
  // Split for display only. The fragment is shown apart from the rest so it is
  // visibly part of the link rather than something trailing off the end.
  const linkPath = $derived(link === "" ? "" : link.slice(0, link.indexOf("#") + 1));
  const linkSecretText = $derived(link === "" ? "" : link.slice(link.indexOf("#") + 1));

  const ttlChoices = [
    { seconds: 0, label: "This instance's default" },
    { seconds: 3600, label: "1 hour" },
    { seconds: 86400, label: "1 day" },
    { seconds: 7 * 86400, label: "7 days" },
    { seconds: 30 * 86400, label: "30 days" },
  ];

  const downloadChoices = [
    { count: 0, label: "No limit" },
    { count: 1, label: "1 download" },
    { count: 5, label: "5 downloads" },
    { count: 20, label: "20 downloads" },
    { count: 100, label: "100 downloads" },
  ];

  function chooseFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    file = input.files?.[0] ?? null;
    failure = null;
  }

  async function send(event: SubmitEvent) {
    event.preventDefault();
    if (file === null || busy) return;

    failure = null;
    result = null;
    copied = false;
    controller = new AbortController();

    try {
      result = await uploadFile({
        file,
        options: { password, ttlSeconds, maxDownloads },
        transport: { signal: controller.signal },
        onProgress: (p) => {
          progress = p;
        },
      });
      // The password is not needed again and there is no reason to keep it in
      // memory, or in a field the next upload would silently reuse.
      password = "";
    } catch (error) {
      failure = describe(error);
      progress = null;
    } finally {
      controller = null;
    }
  }

  function cancel() {
    controller?.abort();
  }

  /**
   * What to tell the person watching.
   *
   * The server's own message is used where there is one, because it knows
   * things this side does not - which limit was exceeded, how long to wait.
   */
  function describe(error: unknown): string {
    if (error instanceof DOMException && error.name === "AbortError") {
      return "Upload cancelled. Nothing was kept.";
    }
    if (error instanceof TusError) {
      switch (error.status) {
        case 413:
          return "This file is larger than the instance accepts.";
        case 429:
          return "The instance is rate limiting this connection. Try again shortly.";
        default:
          return `The instance refused the upload: ${error.message}`;
      }
    }
    if (error instanceof Error) return error.message;
    return "The upload failed.";
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(link);
      copied = true;
    } catch {
      // Refused, or no permission. The field is selectable, so say so rather
      // than claiming a copy that did not happen.
      copied = false;
      failure = "Could not reach the clipboard. Select the link below and copy it.";
    }
  }

  function startOver() {
    file = null;
    result = null;
    progress = null;
    failure = null;
    copied = false;
    ttlSeconds = 0;
    maxDownloads = 0;
  }

  const percent = $derived(
    progress === null || progress.total === 0
      ? 0
      : Math.floor((progress.sent / progress.total) * 100),
  );

  const stageText = $derived(
    progress === null
      ? ""
      : progress.stage === "deriving"
        ? "Preparing keys…"
        : progress.stage === "done"
          ? "Done."
          : `Encrypting and sending… ${percent}%`,
  );
</script>

<h1>Send a file</h1>

{#if result === null}
  <form onsubmit={send}>
    <p>
      <label for="file">File</label><br />
      <input id="file" type="file" onchange={chooseFile} disabled={busy} required />
    </p>

    <fieldset disabled={busy}>
      <legend>Options</legend>

      <p>
        <label for="password">Password (optional)</label><br />
        <input
          id="password"
          type="password"
          bind:value={password}
          autocomplete="new-password"
          aria-describedby="password-note"
        />
      </p>
      <p id="password-note" class="note">
        The password becomes part of the key. Nobody can open the file without
        it, including whoever runs this instance — and nobody can reset it.
      </p>

      <p>
        <label for="ttl">Expires after</label><br />
        <select id="ttl" bind:value={ttlSeconds}>
          {#each ttlChoices as choice (choice.seconds)}
            <option value={choice.seconds}>{choice.label}</option>
          {/each}
        </select>
      </p>

      <p>
        <label for="downloads">Download limit</label><br />
        <select id="downloads" bind:value={maxDownloads}>
          {#each downloadChoices as choice (choice.count)}
            <option value={choice.count}>{choice.label}</option>
          {/each}
        </select>
      </p>
    </fieldset>

    <p>
      <button type="submit" disabled={file === null || busy}>Encrypt and send</button>
      {#if busy}
        <button type="button" onclick={cancel}>Cancel</button>
      {/if}
    </p>
  </form>

  {#if progress !== null}
    <!--
      A native progress element rather than a styled bar. Setting a width would
      mean an inline style attribute, which style-src 'self' blocks: it would
      work in development and render an empty bar on a real instance.
    -->
    <p>
      <progress value={progress.sent} max={progress.total} aria-describedby="stage">
        {percent}%
      </progress>
    </p>
    <p id="stage" aria-live="polite">{stageText}</p>
  {/if}
{:else}
  <h2>Ready to share</h2>

  <p>
    <label for="link">Link</label><br />
    <!--
      Readonly rather than a paragraph of text: a field can be selected whole in
      one gesture, and cannot be partially selected by a stray drag. The link is
      also shown split below, so the fragment is visible rather than scrolled
      out of sight.
    -->
    <input id="link" type="text" value={link} readonly />
  </p>

  <p>
    <button type="button" onclick={copy}>Copy link</button>
    {#if copied}<span aria-live="polite">Copied.</span>{/if}
  </p>

  <p class="split">
    <span>{linkPath}</span><strong>{linkSecretText}</strong>
  </p>

  <p class="note">
    <strong>The part in bold is the key, and it is not sent to the server.</strong>
    A link that loses it cannot be repaired, by anyone. Check that what you paste
    ends in those {linkSecretText.length} characters.
  </p>

  {#if maxDownloads > 0 || ttlSeconds > 0}
    <p class="note">
      This upload {#if ttlSeconds > 0}expires after
        {ttlChoices.find((c) => c.seconds === ttlSeconds)?.label.toLowerCase()}{/if}{#if maxDownloads > 0 && ttlSeconds > 0}, and{/if}{#if maxDownloads > 0}
        allows {maxDownloads} download{maxDownloads === 1 ? "" : "s"}{/if}. Whichever
      comes first removes it.
    </p>
  {/if}

  <details>
    <summary>Management secret</summary>
    <p class="note">
      This deletes the upload before it expires. It is shown once and stored
      nowhere; the instance holds only its hash and cannot reissue it.
    </p>
    <p><input type="text" value={toBase64Url(result.ownerToken)} readonly /></p>
  </details>

  <p><button type="button" onclick={startOver}>Send another file</button></p>
{/if}

{#if failure !== null}
  <p class="failure" role="alert">{failure}</p>
{/if}

<style>
  fieldset {
    border: 1px solid;
    margin: 1rem 0;
  }

  input[type="text"] {
    width: 100%;
    font-family: monospace;
  }

  progress {
    width: 100%;
  }

  .note {
    font-size: 0.9rem;
  }

  .split {
    font-family: monospace;
    overflow-wrap: anywhere;
  }

  .failure {
    font-weight: bold;
  }
</style>
