<script lang="ts">
  import { onMount } from "svelte";
  import { isFatal, type MissingCapability, missingCapabilities } from "$lib/capabilities";

  let { children } = $props();

  // Checked after mount rather than during render. The check reads the
  // platform, and there is no platform until the page is running.
  let missing = $state<MissingCapability[] | null>(null);

  onMount(() => {
    missing = missingCapabilities();
  });

  const fatal = $derived(missing !== null && isFatal(missing));

  // An insecure context is not the browser's doing - a browser withholding
  // WebCrypto there is behaving correctly - and a heading that blamed it would
  // send the reader to change browsers over a configuration only the operator
  // can fix.
  const heading = $derived(
    missing?.some((one) => one.code === "insecure-context")
      ? "This instance is not set up to do this"
      : fatal
        ? "This browser cannot be used here"
        : "Some things will not work here",
  );
</script>

{#if missing !== null && missing.length > 0}
  <section class="check" role="alert">
    <h2>{heading}</h2>
    <dl>
      {#each missing as one (one.code)}
        <dt>{one.summary}</dt>
        <dd>{one.remedy}</dd>
      {/each}
    </dl>
  </section>
{/if}

<!--
  Rendered unless something fatal is missing. Missing WebAssembly costs
  password-protected files and nothing else, so the interface is still offered:
  refusing everything would withhold a service the browser can perform.
-->
{#if !fatal}
  {@render children()}
{/if}

<style>
  .check {
    border: 2px solid;
    padding: 0.5rem 1rem;
    margin-bottom: 1rem;
  }

  dt {
    font-weight: bold;
    margin-top: 0.5rem;
  }

  dd {
    margin: 0;
  }
</style>
