<script lang="ts">
  import { onMount } from "svelte";
  import { explainRevoke, RevokeError, revokeUpload } from "$lib/revoke";
  import { forget, forgetAll, isSupported, list, type StoredUpload } from "$lib/vault";

  let uploads = $state<StoredUpload[]>([]);
  let loaded = $state(false);
  let supported = $state(true);
  let failure = $state<string | null>(null);

  onMount(async () => {
    supported = isSupported();
    if (!supported) {
      loaded = true;
      return;
    }
    try {
      uploads = await list();
    } catch {
      // A browser that refuses storage - private mode in some, or a profile
      // with site data disabled - is not a broken one. Saying so beats an
      // empty list that looks like nothing was ever sent.
      failure = "This browser would not open the list. Site data may be disabled.";
    }
    loaded = true;
  });

  let working = $state<string | null>(null);
  let notice = $state<string | null>(null);

  /**
   * Removes the file itself, not just the record.
   *
   * Confirmed first, because it cannot be undone by anybody: the instance takes
   * the same path it takes when an upload expires, so the row, the blob and the
   * at-rest key are gone rather than marked.
   */
  async function remove(upload: StoredUpload) {
    if (
      !confirm(
        `Delete ${upload.name} from the instance?\n\n` +
          "Anybody holding the link loses access immediately, and this cannot be " +
          "undone — not by you and not by whoever runs the instance.",
      )
    ) {
      return;
    }

    working = upload.id;
    notice = null;
    try {
      await revokeUpload(upload.id, upload.ownerToken);
      await forget(upload.id);
      uploads = uploads.filter((u) => u.id !== upload.id);
      notice = `${upload.name} was deleted.`;
    } catch (error) {
      if (error instanceof RevokeError) {
        notice = explainRevoke(error.fault);
        // An upload the instance no longer has is one this list should stop
        // showing, whatever the reason it is gone.
        if (error.fault === "not-owner") {
          await forget(upload.id);
          uploads = uploads.filter((u) => u.id !== upload.id);
        }
      } else {
        notice = "Something went wrong. The upload has not been removed.";
      }
    } finally {
      working = null;
    }
  }

  async function drop(id: string) {
    await forget(id);
    uploads = uploads.filter((u) => u.id !== id);
  }

  async function dropEverything() {
    await forgetAll();
    uploads = [];
  }

  function when(at: number | null): string {
    if (at === null) return "never";
    return new Date(at).toLocaleString();
  }

  function size(bytes: number): string {
    const units = ["B", "kB", "MB", "GB"];
    let n = bytes;
    let unit = 0;
    while (n >= 1000 && unit < units.length - 1) {
      n /= 1000;
      unit++;
    }
    return `${unit === 0 ? n : n.toFixed(1)} ${units[unit]}`;
  }
</script>

<svelte:head><title>Your uploads</title></svelte:head>

<h1>Your uploads</h1>

<!--
  Stated on the page itself, not only when the first record is written. Somebody
  arriving here later is deciding whether to rely on this list, and the answer
  depends on facts that are not visible from the list itself.
-->
<p class="note">
  This list is kept in this browser and nowhere else. The instance has no account
  and does not know which uploads are yours.
</p>
<p class="note">
  <strong>There is no way to recover it.</strong> Clearing site data, using a
  different browser, or a private window removes it, and nothing can bring it
  back — the instance does not hold the key that opens your files or the token
  that removes them. That is the same property that stops whoever runs the
  instance reading them.
</p>

{#if notice}
  <p class="note" role="status" aria-live="polite">{notice}</p>
{/if}

{#if !loaded}
  <p aria-live="polite">Reading…</p>
{:else if !supported}
  <p class="failure">This browser cannot keep a list: it has no storage available.</p>
{:else if failure}
  <p class="failure">{failure}</p>
{:else if uploads.length === 0}
  <p>Nothing here yet. Uploads you make in this browser will appear on this page.</p>
{:else}
  <ul class="uploads">
    {#each uploads as upload (upload.id)}
      <li>
        <p class="name">{upload.name}</p>
        <p class="detail">{size(upload.size)} · expires {when(upload.expiresAt)}</p>
        <p><input type="text" value={upload.link} readonly aria-label="Link for {upload.name}" /></p>
        <!--
          Removing the record is not removing the upload, and saying which is
          which matters: somebody clearing this list to tidy up should not
          believe they have withdrawn the files.
        -->
        <p class="actions">
          <!--
            Deleting first, because it is what somebody looking at this list
            usually wants: the file is out there and they want it back. The two
            are labelled for what they do rather than sharing a word.
          -->
          <button
            type="button"
            onclick={() => remove(upload)}
            disabled={working !== null}
          >
            {working === upload.id ? "Deleting…" : "Delete this file"}
          </button>
          <button type="button" onclick={() => drop(upload.id)} disabled={working !== null}>
            Forget this link
          </button>
        </p>
      </li>
    {/each}
  </ul>

  <p>
    <button type="button" onclick={dropEverything}>Forget every link</button>
  </p>
  <p class="note">
    <strong>Delete this file</strong> removes it from the instance, using the
    owner token stored here. Anybody holding the link loses access at once, and
    it cannot be undone.
  </p>
  <p class="note">
    <strong>Forget this link</strong> removes only this browser's record of it.
    The upload stays until it expires, runs out of downloads, or is deleted.
  </p>
{/if}

<style>
  .uploads {
    list-style: none;
    padding: 0;
  }

  .uploads li {
    border-top: 1px solid;
    padding: 0.75rem 0;
  }

  .name {
    font-weight: bold;
    margin: 0;
  }

  .detail {
    margin: 0.15rem 0 0.5rem;
    font-size: 0.9rem;
  }

  .uploads input {
    width: 100%;
  }

  .note {
    font-size: 0.9rem;
  }

  .actions {
    display: flex;
    gap: 0.5rem;
    margin: 0;
  }
</style>
