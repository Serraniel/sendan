<script lang="ts">
  import { onMount } from "svelte";
  import { type Build, fetchBuild, shortCommit, sourceIsExact } from "$lib/source";

  let { children } = $props();
  let build = $state<Build | null>(null);

  // Read after mount rather than during render: the footer is not worth
  // delaying the page for, and an instance that cannot answer should still
  // serve one that works.
  onMount(async () => {
    build = await fetchBuild();
  });
</script>

<main>
  {@render children()}
</main>

<footer>
  {#if build}
    <p>
      Sendan
      <span title={build.commit}>{build.version} ({shortCommit(build.commit)})</span>
      &middot;
      <a href={build.source} rel="noreferrer">source</a>
      &middot;
      {build.license}
    </p>

    {#if !sourceIsExact(build)}
      <!--
        A build from a modified tree has no commit that describes it, so the
        link above cannot be exact. Saying so is the difference between a
        transparency measure and a decoration.
      -->
      <p class="caveat">
        This instance was built from a modified working tree, so the source
        above may not be the code that is running.
      </p>
    {/if}
  {/if}
</footer>

<style>
  footer {
    font-size: 0.85rem;
  }

  .caveat {
    font-weight: bold;
  }
</style>
