<script lang="ts">
  import { markSeen, unseen } from "$lib/banner";
  import type { Banner } from "$lib/instance";

  let { banner }: { banner: Banner | null } = $props();

  // Starts hidden and is revealed once storage has been consulted, so a notice
  // already dismissed does not flash on every page load.
  let dismissed = $state(true);

  $effect(() => {
    dismissed = banner === null ? true : !unseen(banner.text);
  });

  function dismiss() {
    if (banner !== null) markSeen(banner.text);
    dismissed = true;
  }
</script>

{#if banner !== null && !dismissed}
  <!--
    Text, never markup. The operator controls this string, and rendering it as
    HTML would be a scripting hole granted by configuration - one the content
    security policy could not save a page from, because the page would be doing
    it deliberately. Svelte escapes interpolation, which is exactly what is
    wanted here.

    A status region rather than an alert: it is a standing notice about the
    instance, not something that has just happened, and an alert interrupts a
    screen reader mid-sentence.
  -->
  <div class="banner" class:warning={banner.severity === "warning"} role="status">
    <p>{banner.text}</p>
    <button type="button" onclick={dismiss}>
      <span class="visually-hidden">Dismiss this notice</span>
      <span aria-hidden="true">✕</span>
    </button>
  </div>
{/if}

<style>
  .banner {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: var(--accent-quiet);
    border-bottom: 1px solid var(--border);
    font-size: var(--text-sm);
  }

  .banner.warning {
    background: var(--danger-quiet);
  }

  .banner p {
    margin: 0;
    flex: 1;
    max-width: none;
    /* An operator can write anything here, including one very long word. */
    overflow-wrap: anywhere;
  }

  .banner button {
    flex: none;
    min-height: 1.75rem;
    min-width: 1.75rem;
    padding: 0 var(--space-2);
    border: 0;
    background: transparent;
    color: var(--text-muted);
    line-height: 1;
  }

  .banner button:hover {
    color: var(--text);
  }
</style>
