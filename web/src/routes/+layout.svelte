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
  /*
    SvelteKit's screen-reader announcer carries its hiding rules in a style
    attribute, which style-src 'self' refuses - the framework's markup, not
    ours, and not something this side can stop it emitting. The same rules are
    given here so the element is hidden by a stylesheet the policy allows,
    rather than by an attribute it may block. Without this a blocked attribute
    would put a live region in the middle of the page.
  */
  :global(#svelte-announcer) {
    position: absolute;
    left: 0;
    top: 0;
    clip-path: inset(50%);
    overflow: hidden;
    white-space: nowrap;
    width: 1px;
    height: 1px;
  }

  footer {
    font-size: 0.85rem;
  }

  .caveat {
    font-weight: bold;
  }
</style>
