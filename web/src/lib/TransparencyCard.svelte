<script lang="ts">
  import { assurances, CAVEAT, type Protection, protectionLines } from "$lib/protection";

  interface Props {
    protection: Protection;
    /** Where this instance's corresponding source can be obtained, if known. */
    source?: string | null;
  }

  const { protection, source = null }: Props = $props();
  const lines = $derived(protectionLines(protection));

  // The one fact on the list the instance does not report, and the only one the
  // browser can establish for itself. Read from the protocol rather than from
  // isSecureContext, which a browser sets true on localhost over plain HTTP.
  const secureTransport = $derived(
    typeof window === "undefined" ? true : window.location.protocol === "https:",
  );
  const claims = $derived(assurances(protection, secureTransport));
</script>

<!--
  The plain-language list is outside the fold and the parameters are inside it.
  Somebody who cannot act on "Argon2id, 64 KiB memory, 3 passes" can act on
  "no password was set, so anyone holding the link can open this file" - and
  that is the sentence that changes what they do next.
-->
<ul class="claims">
  {#each claims as claim (claim.claim)}
    <li class:holds={claim.holds}>
      <!--
        A mark as well as a colour. Colour alone says nothing to somebody who
        cannot tell these two apart, and this list is only worth showing if its
        answers are legible.
      -->
      <span class="mark" aria-hidden="true">{claim.holds ? "✓" : "✕"}</span>
      <span class="visually-hidden">{claim.holds ? "Yes:" : "No:"}</span>
      <span class="claim">
        <span class="what">{claim.claim}</span>
        <span class="why">{claim.because}</span>
      </span>
    </li>
  {/each}
</ul>

<!--
  Collapsed by default. Somebody who wants to know what protected their file
  will open it; putting it in the way of everybody else would make it furniture,
  and furniture does not get read.
-->
<details class="transparency">
  <summary>The same, in cryptographic terms</summary>

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
  .claims {
    list-style: none;
    margin: var(--space-5) 0 var(--space-3);
    padding: 0;
    display: grid;
    gap: var(--space-3);
    font-size: var(--text-sm);
  }

  .claims li {
    display: grid;
    grid-template-columns: 1.25rem 1fr;
    gap: var(--space-2);
    align-items: start;
  }

  .mark {
    /* Not a colour on its own: the glyph carries the answer where colour
       cannot. */
    color: var(--danger);
    font-weight: 700;
    line-height: 1.5;
  }

  .claims li.holds .mark {
    color: var(--positive);
  }

  .claim {
    display: grid;
    gap: 0.1rem;
  }

  .what {
    font-weight: 600;
  }

  .why {
    color: var(--text-muted);
  }

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
