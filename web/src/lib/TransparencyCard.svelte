<script lang="ts">
  import { CAVEAT, type Protection, protectionLines } from "$lib/protection";

  interface Props {
    protection: Protection;
    /** Where this instance's corresponding source can be obtained, if known. */
    source?: string | null;
  }

  const { protection, source = null }: Props = $props();
  const lines = $derived(protectionLines(protection));
</script>

<!--
  Collapsed by default. Somebody who wants to know what protected their file
  will open it; putting it in the way of everybody else would make it furniture,
  and furniture does not get read.
-->
<details class="transparency">
  <summary>What protected this file</summary>

  <dl>
    {#each lines as line (line.label)}
      <dt>{line.label}</dt>
      <dd>
        {line.value}
        {#if line.caution}
          <!--
            Beside the fact it qualifies rather than at the foot of the card. A
            caution somewhere else is one that can be read past.
          -->
          <strong class="caution">{line.caution}</strong>
        {/if}
      </dd>
    {/each}
  </dl>

  <p class="caveat">
    {CAVEAT}
    {#if source}
      <a href={source} rel="noreferrer">The source and threat model are here.</a>
    {/if}
  </p>
</details>

<style>
  .transparency {
    margin: 1rem 0;
    font-size: 0.9rem;
  }

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

  .caution {
    display: block;
  }

  .caveat {
    border-top: 1px solid;
    padding-top: 0.5rem;
  }
</style>
