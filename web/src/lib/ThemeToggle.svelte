<script lang="ts">
  import { onMount } from "svelte";
  import {
    applyChoice,
    labelFor,
    nextChoice,
    rememberChoice,
    resolve,
    storedChoice,
    type ThemeChoice,
  } from "$lib/theme";

  // Starts at "system" so the server-rendered markup and the first client
  // render agree. The stored value is read after mount; the inline script in
  // app.html has already applied it to the document by then, so nothing
  // changes visually at this point - only the label catches up.
  let choice = $state<ThemeChoice>("system");
  let systemDark = $state(false);

  onMount(() => {
    choice = storedChoice();

    const query = window.matchMedia("(prefers-color-scheme: dark)");
    systemDark = query.matches;

    // Following the system means following it as it changes, not as it was
    // when the page loaded.
    const onChange = (event: MediaQueryListEvent) => {
      systemDark = event.matches;
    };
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  });

  let showing = $derived(resolve(choice, systemDark));

  function advance() {
    choice = nextChoice(choice);
    rememberChoice(choice);
    applyChoice(choice, document.documentElement);
  }
</script>

<!--
  A button rather than a select: it has three states and one of them is
  "whatever you already chose elsewhere", which reads better as a cycle than as
  a list. The accessible name says what the theme is now, and aria-live is
  deliberately absent - the label changes as a result of a press the person
  just made, so announcing it again would be noise.
-->
<button type="button" class="theme" onclick={advance} title={labelFor(choice)}>
  <span class="visually-hidden">{labelFor(choice)}. Press to change.</span>
  <span aria-hidden="true">{#if choice === "system"}◐{:else if showing === "dark"}☾{:else}☀{/if}</span>
</button>

<style>
  .theme {
    /* Square, so the glyph sits centred rather than in a wide pill. */
    width: 2.75rem;
    min-width: 2.75rem;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    line-height: 1;
    background: transparent;
    border-color: var(--border);
  }

  .theme:hover {
    background: var(--surface-raised);
  }
</style>
