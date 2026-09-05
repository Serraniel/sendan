<script lang="ts">
  import { onMount } from "svelte";
  import { type Block, render } from "$lib/changelog";

  let blocks = $state<Block[]>([]);
  let loaded = $state(false);
  let failure = $state<string | null>(null);

  onMount(async () => {
    try {
      // The same file the footer used to link to directly, still served as a
      // plain file for anyone reading with curl. This page is a presentation of
      // it rather than a replacement.
      const response = await fetch("/changelog.md", { headers: { accept: "text/markdown" } });
      if (!response.ok) {
        throw new Error(String(response.status));
      }
      blocks = render(await response.text());
    } catch {
      // An instance can be built without the changelog, and a network can fail.
      // Saying so beats an empty page that looks like nothing ever changed.
      failure = "This instance did not return its changelog.";
    } finally {
      loaded = true;
    }
  });
</script>

<svelte:head>
  <title>What changed · Sendan</title>
</svelte:head>

<h1>What changed</h1>

<p class="muted">
  Every release of this instance's code, newest first. Served by the instance
  itself, so it describes the version that is answering you.
</p>

{#if !loaded}
  <p class="muted">Loading…</p>
{:else if failure !== null}
  <p class="failure">{failure}</p>
  <p class="muted small">
    The file is also served directly at <a href="/changelog.md">/changelog.md</a>.
  </p>
{:else}
  <div class="log">
    {#each blocks as block, index (index)}
      {#if block.kind === "heading" && block.level === 1}
        <!-- The file's own title, which this page already has. -->
      {:else if block.kind === "heading" && block.level === 2}
        <h2>{@html block.html}</h2>
      {:else if block.kind === "heading"}
        <h3>{@html block.html}</h3>
      {:else if block.kind === "list"}
        <ul>
          {#each block.items as item, i (i)}
            <li>{@html item}</li>
          {/each}
        </ul>
      {:else}
        <p>{@html block.html}</p>
      {/if}
    {/each}
  </div>
{/if}

<style>
  /*
    The rendered log. Its own rules rather than the page defaults, because a
    changelog is a dense list of short lines and inherits spacing meant for
    prose.
  */
  .log :global(h2) {
    margin-top: var(--space-6);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }

  .log :global(h3) {
    margin-top: var(--space-5);
    font-size: var(--text-base);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .log :global(ul) {
    margin: 0;
    padding-left: var(--space-5);
  }

  .log :global(li) {
    margin-bottom: var(--space-2);
    /* A commit subject with a long link should wrap rather than widen the page. */
    overflow-wrap: anywhere;
  }

  /* The commit and issue links are the noisiest thing here and the least
     important, so they read as references rather than as the sentence. */
  .log :global(li a) {
    color: var(--text-muted);
  }

  .log :global(li a:hover) {
    color: var(--accent);
  }

  .failure {
    color: var(--danger);
  }
</style>
