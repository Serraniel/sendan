<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import { downloadLink, toBase64Url } from "$lib/link";
  import {
    fetchMaxUploadSize,
    formatSize,
    type MaxUploadSize,
    tooLargeMessage,
  } from "$lib/limits";
  import { fetchInstancePolicy, type InstancePolicy, nothingKnown } from "$lib/instance";
  import { DEFAULT_WORDS, describeStrength, generate } from "$lib/passphrase";
  import {
    describeRetention,
    downloadChoices as downloadChoices2,
    expiryChoices,
  } from "$lib/retention";
  import InstanceRules from "$lib/InstanceRules.svelte";
  import { acknowledge, isSupported, mustWarn, remember } from "$lib/vault";
  import { TusError } from "$lib/tus";
  import { type UploadProgress, type UploadResult, uploadFile } from "$lib/upload";
  import TransparencyCard from "$lib/TransparencyCard.svelte";
  import { describeUpload, type Protection } from "$lib/protection";
  import { fetchBuild } from "$lib/source";

  let file = $state<File | null>(null);
  let password = $state("");
  let ttlSeconds = $state(0);
  let maxDownloads = $state(0);

  let progress = $state<UploadProgress | null>(null);
  let result = $state<UploadResult | null>(null);
  let failure = $state<string | null>(null);
  let copied = $state(false);
  let controller: AbortController | null = null;
  // What actually protected the file, recorded as it was sent rather than
  // rebuilt from the form afterwards - the form can be edited, and what
  // happened cannot.
  let protection = $state<Protection | null>(null);
  let source = $state<string | null>(null);

  const busy = $derived(progress !== null && result === null);

  const link = $derived(
    result === null ? "" : downloadLink(page.url.origin, result.fileID, result.linkSecret),
  );
  // Split for display only. The fragment is shown apart from the rest so it is
  // visibly part of the link rather than something trailing off the end.
  const linkPath = $derived(link === "" ? "" : link.slice(0, link.indexOf("#") + 1));
  const linkSecretText = $derived(link === "" ? "" : link.slice(link.indexOf("#") + 1));

  // What the instance permits, so somebody can see the rules rather than
  // discover them by being refused.
  let policy = $state<InstancePolicy>(nothingKnown);

  const ttlChoices = $derived(expiryChoices(policy));
  const downloadChoices = $derived(downloadChoices2(policy));

  function chooseFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    file = input.files?.[0] ?? null;
    failure = null;
  }

  // Dropping is an addition to the file input, never a replacement for it: the
  // input stays in the markup and stays operable, so the keyboard path and the
  // click path are unchanged for anybody who cannot drag.
  let dragging = $state(false);

  function overZone(event: DragEvent) {
    if (busy) return;
    event.preventDefault();
    dragging = true;
  }

  function leaveZone() {
    dragging = false;
  }

  function dropFile(event: DragEvent) {
    if (busy) return;
    event.preventDefault();
    dragging = false;

    const dropped = event.dataTransfer?.files?.[0];
    if (!dropped) return;
    file = dropped;
    failure = null;
  }

  // The limit the instance advertises, and what to say when a file exceeds it.
  // Read once on mount; null means the instance did not say, in which case the
  // interface behaves exactly as it did before this existed.
  let maxUploadSize = $state<MaxUploadSize>(null);


  const overSize = $derived(file === null ? null : tooLargeMessage(file.size, maxUploadSize));

  async function send(event: SubmitEvent) {
    event.preventDefault();
    if (file === null || busy) return;

    failure = null;
    result = null;
    copied = false;
    controller = new AbortController();

    try {
      // Captured before the upload, because these are the parameters it will
      // use; reading them back off the form afterwards would report what the
      // form says now rather than what the file got.
      const applied = {
        password,
        ttlSeconds,
        maxDownloads,
        startedAt: Date.now(),
      };

      result = await uploadFile({
        file,
        options: { password, ttlSeconds, maxDownloads },
        transport: { signal: controller.signal },
        onProgress: (p) => {
          progress = p;
        },
      });

      protection = describeUpload({
        password: result.passwordParams,
        // The instance decides the deadline from the requested lifetime, so
        // this is what was asked for rather than what was granted. Where
        // nothing was asked for, the instance's default applies and this side
        // does not know it.
        expiresAt:
          applied.ttlSeconds > 0
            ? new Date(applied.startedAt + applied.ttlSeconds * 1000)
            : null,
        maxDownloads: applied.maxDownloads,
      });

      await keep(file.name, file.size, applied);
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

  /**
   * Adds the upload to this browser's list, having asked first.
   *
   * Asked before the first record is written rather than after, because what is
   * being consented to is that the link and the owner token are kept here and
   * nowhere else, with no way to recover them. Somebody who has already closed
   * the tab has already relied on it.
   *
   * Failing to record an upload never fails the upload: the file is sent and
   * the link is on screen, and this list is a convenience.
   */
  async function keep(
    name: string,
    size: number,
    applied: { ttlSeconds: number; startedAt: number },
  ) {
    if (result === null || !isSupported()) return;

    if (mustWarn()) {
      const agreed = confirm(
        "Keep a list of your uploads in this browser?\n\n" +
          "The link and the owner token are stored here and nowhere else. " +
          "Anybody who can use this browser profile can then open these files.\n\n" +
          "There is no way to recover the list. Clearing site data, or using " +
          "another browser, loses it permanently \u2014 the instance does not " +
          "hold the key that opens your files or the token that removes them.",
      );
      if (!agreed) return;
      acknowledge();
    }

    try {
      await remember({
        id: toBase64Url(result.fileID),
        link,
        ownerToken: toBase64Url(result.ownerToken),
        name,
        size,
        createdAt: applied.startedAt,
        expiresAt:
          applied.ttlSeconds > 0 ? applied.startedAt + applied.ttlSeconds * 1000 : null,
      });
    } catch {
      // The upload succeeded; only the note about it did not, and there is
      // nothing the person can usefully do about that here.
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
          // Still reachable: an instance can be reconfigured between this page
          // loading and the upload finishing, and a limit read early is a hint
          // rather than a promise.
          return maxUploadSize === null
            ? "This file is larger than the instance accepts."
            : `This file is larger than the instance accepts (${formatSize(maxUploadSize)}).`;
        case 429:
          return "The instance is rate limiting this connection. Try again shortly.";
        default:
          return `The instance refused the upload: ${error.message}`;
      }
    }
    if (error instanceof Error) return error.message;
    return "The upload failed.";
  }

  /**
   * What was actually applied, said in full.
   *
   * The previous version said nothing at all when an upload was set never to
   * expire, which is the choice that most needs stating: an upload with no
   * deadline and no download limit is one that stays until somebody removes it
   * by hand, and the reason this project deletes anything is that nobody
   * remembers to.
   */
  const retention = $derived(describeRetention(ttlSeconds, maxDownloads, policy));

  /**
   * Puts a generated passphrase in the field.
   *
   * Shown, necessarily: a password nobody can read is a file nobody can open.
   * So the field is switched to plain text at the same moment, because a
   * generated secret hidden behind dots is one somebody will retype wrongly.
   */
  let passwordVisible = $state(false);
  let generated = $state(false);

  function generatePassword() {
    password = generate(DEFAULT_WORDS);
    passwordVisible = true;
    generated = true;
  }

  async function copyPassword() {
    try {
      await navigator.clipboard.writeText(password);
      passwordCopied = true;
    } catch {
      passwordCopied = false;
      failure = "Could not reach the clipboard. Select the password and copy it.";
    }
  }
  let passwordCopied = $state(false);

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

  // Read from the protocol, not from isSecureContext. A browser grants
  // localhost the privileges of a secure context over plain HTTP, so
  // isSecureContext is true there - and reporting "encrypted" about a
  // connection that is not would be exactly the kind of comfortable falsehood
  // this panel exists to avoid.
  const secureConnection = $derived(
    typeof window === "undefined" ? true : window.location.protocol === "https:",
  );

  onMount(async () => {
    source = (await fetchBuild())?.source ?? null;
    maxUploadSize = await fetchMaxUploadSize();
    policy = await fetchInstancePolicy();
  });

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
    <!--
      The label is the visible control and the input is behind it, so the whole
      area is clickable and the input keeps its own keyboard behaviour. The
      drag handlers sit on the label rather than the input because a hidden
      input is not a drop target anybody can hit.
    -->
    <label
      class="drop"
      class:dragging
      class:chosen={file !== null}
      for="file"
      ondragover={overZone}
      ondragleave={leaveZone}
      ondrop={dropFile}
    >
      <input id="file" type="file" onchange={chooseFile} disabled={busy} required />
      {#if file === null}
        <span class="drop-main">Choose a file, or drop one here</span>
        <span class="drop-sub muted small">
          It is encrypted here, before it leaves this browser{#if maxUploadSize !== null}{" · up to "}{formatSize(
              maxUploadSize,
            )}{/if}
        </span>
      {:else}
        <span class="drop-main break">{file.name}</span>
        <span class="drop-sub muted small">{formatSize(file.size)} · choose or drop another to replace it</span>
      {/if}
    </label>

    <fieldset disabled={busy}>
      <legend>Options</legend>
      <p class="muted small options-note">Most people change none of these.</p>

      <p>
        <label for="password">Password (optional)</label>
        <span class="password-row">
          <input
            id="password"
            type={passwordVisible ? "text" : "password"}
            bind:value={password}
            autocomplete="new-password"
            aria-describedby="password-note"
          />
          <button type="button" onclick={generatePassword}>Generate</button>
        </span>
      </p>

      {#if generated}
        <!--
          Said out loud, because the consequences are not obvious: it is on
          screen, it is not stored anywhere, and it has to reach the recipient
          by some route other than the link.
        -->
        <p class="note generated" role="status">
          <strong>Copy this now.</strong> It is {describeStrength(DEFAULT_WORDS)} It is not
          stored anywhere and will not be shown again after this upload.
          <button type="button" onclick={copyPassword}>Copy password</button>
          {#if passwordCopied}<span class="copied">Copied.</span>{/if}
        </p>
        <p class="note">
          Send it by some route other than the link. A password in the same
          message as the link protects nothing: whoever reads the message has
          both.
        </p>
      {/if}
      <p id="password-note" class="note">
        The password becomes part of the key. Nobody can open the file without
        it, including whoever runs this instance — and nobody can reset it.
      </p>

      <p>
        <label for="ttl">Expires after</label><br />
        <select id="ttl" bind:value={ttlSeconds}>
          {#each ttlChoices as choice (choice.value)}
            <option value={choice.value}>{choice.label}</option>
          {/each}
        </select>
      </p>

      <p>
        <label for="downloads">Download limit</label><br />
        <select id="downloads" bind:value={maxDownloads}>
          {#each downloadChoices as choice (choice.value)}
            <option value={choice.value}>{choice.label}</option>
          {/each}
        </select>
      </p>
    </fieldset>

    {#if overSize !== null}
      <!--
        Said when the file is chosen rather than after an upload that was never
        going to be accepted, and it names the limit: without the number the
        next attempt is a guess.
      -->
      <p class="failure" role="alert">{overSize}</p>
    {/if}

    <p class="actions">
      <button type="submit" class="primary" disabled={file === null || busy || overSize !== null}>
        Encrypt and send
      </button>
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

  <InstanceRules {policy} secure={secureConnection} />
{:else}
  <h2>Ready to share</h2>

  <p class="result">
    <label for="link">Link</label>
    <!--
      Readonly rather than a paragraph of text: a field can be selected whole in
      one gesture, and cannot be partially selected by a stray drag. The link is
      also shown split below, so the fragment is visible rather than scrolled
      out of sight.
    -->
    <input id="link" type="text" value={link} readonly />
  </p>

  <p class="actions">
    <button type="button" class="primary" onclick={copy}>Copy link</button>
    {#if copied}<span class="copied" aria-live="polite">Copied.</span>{/if}
  </p>

  <p class="split">
    <span>{linkPath}</span><strong>{linkSecretText}</strong>
  </p>

  <p class="note">
    <strong>The part in bold is the key, and it is not sent to the server.</strong>
    A link that loses it cannot be repaired, by anyone. Check that what you paste
    ends in those {linkSecretText.length} characters.
  </p>

  <p class="note" class:standout={retention.neverRemoved}>{retention.text}</p>

  {#if protection}
    <TransparencyCard {protection} {source} />
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
  /* The file input is behind its label rather than removed: it keeps its
     keyboard behaviour, its required validation and the id the browser tests
     drive it by. */
  .drop input[type="file"] {
    position: absolute;
    width: 1px;
    height: 1px;
    opacity: 0;
    pointer-events: none;
  }

  .drop {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-1);
    text-align: center;
    min-height: 8.5rem;
    padding: var(--space-5) var(--space-4);
    border: 2px dashed var(--border-strong);
    border-radius: var(--radius-lg);
    background: var(--surface-raised);
    cursor: pointer;
  }

  .drop:hover {
    border-color: var(--accent);
  }

  /* The input is hidden, so its focus ring would be invisible; the label wears
     it instead. Without this the keyboard path has no visible focus at all. */
  .drop:focus-within {
    outline: 2px solid var(--focus);
    outline-offset: 2px;
  }

  .drop.dragging {
    border-color: var(--accent);
    border-style: solid;
    background: var(--accent-quiet);
  }

  .drop.chosen {
    border-style: solid;
    border-color: var(--accent);
  }

  .drop-main {
    font-weight: 600;
  }

  fieldset {
    /* Browsers give a fieldset a min-inline-size of min-content, which stops it
       shrinking with the page: at 320px it stayed wider than the viewport and
       took the whole document sideways with it. Nothing else on the page
       behaves this way. */
    min-inline-size: 0;
    margin: var(--space-5) 0;
    padding: var(--space-4) var(--space-5) var(--space-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface-raised);
  }

  legend {
    padding-inline: var(--space-2);
    font-weight: 600;
  }

  .options-note {
    margin-top: 0;
  }

  fieldset label,
  .result label {
    display: block;
    margin-bottom: var(--space-1);
    font-weight: 600;
    font-size: var(--text-sm);
  }

  input[type="text"] {
    width: 100%;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }

  select {
    /* No minimum: a minimum here becomes the fieldset's minimum, and then the
       page's. Full width up to a cap keeps it from spanning a desktop column
       on its own. */
    width: 100%;
    max-width: 22rem;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    align-items: center;
  }

  progress {
    width: 100%;
    height: 0.6rem;
  }

  .note {
    font-size: var(--text-sm);
    color: var(--text-muted);
  }

  /* The fragment, shown apart from the rest so it is visible rather than
     scrolled out of sight. The emphasis is the point of the paragraph beneath
     it, so it is not decoration. */
  .split {
    /* The link is one unbroken token; without this it is the widest thing on
       the page at every width. */
    overflow-wrap: anywhere;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-sunken);
  }

  .split strong {
    color: var(--accent);
  }

  details {
    margin: var(--space-4) 0;
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }

  summary {
    cursor: pointer;
    font-weight: 600;
    min-height: 1.75rem;
  }

  .failure {
    font-weight: 600;
    color: var(--danger);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--danger);
    border-radius: var(--radius);
    background: var(--danger-quiet);
  }

  /* An upload nothing will remove on its own is worth reading twice. */
  .standout {
    color: var(--text);
    font-weight: 600;
  }

  .password-row {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .password-row input {
    flex: 1;
    min-width: 0;
    /* A generated passphrase is long, and hyphenated words are easier to check
       against a written copy in a monospaced face. */
    font-family: var(--font-mono);
  }

  .generated {
    color: var(--text);
  }

  .generated button {
    min-height: 2rem;
    padding: 0 var(--space-2);
    font-size: var(--text-sm);
  }

  .copied {
    color: var(--positive);
    font-weight: 600;
    font-size: var(--text-sm);
  }
</style>
