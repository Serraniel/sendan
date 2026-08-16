<script lang="ts">
  import { onMount } from "svelte";
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
        <button type="button" onclick={() => drop(upload.id)}>
          Forget this link
        </button>
      </li>
    {/each}
  </ul>

  <p>
    <button type="button" onclick={dropEverything}>Forget every link</button>
  </p>
  <p class="note">
    Forgetting a link removes it from this browser. It does not remove the
    upload: the file stays until it expires, runs out of downloads, or is
    deleted with its owner token.
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
</style>
