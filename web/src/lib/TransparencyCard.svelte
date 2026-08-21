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
  /* Quiet by design. It states what protected a file, which somebody consults
     rather than reads, so it sits below the action instead of competing with
     it. */
  .transparency {
    margin: var(--space-5) 0;
    padding: var(--space-4) var(--space-5);
    font-size: var(--text-sm);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--surface-raised);
  }

  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-1) var(--space-5);
    margin: 0;
  }

  dt {
    font-weight: 600;
    color: var(--text-muted);
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  @media (max-width: 26rem) {
    dl {
      grid-template-columns: 1fr;
    }

    dt {
      margin-top: var(--space-2);
    }
  }

  .caution {
    display: block;
    color: var(--danger);
    font-weight: 600;
  }

  .caveat {
    border-top: 1px solid var(--border);
    margin-top: var(--space-3);
    padding-top: var(--space-3);
    color: var(--text-muted);
  }
</style>
