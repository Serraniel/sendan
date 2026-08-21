<script lang="ts">
  import { onMount } from "svelte";
  import { applyChoice, labelFor, opposite, rememberChoice, resolve, storedChoice } from "$lib/theme";

  // "system" until a choice is stored, which is where every browser starts and
  // is not a state the control offers. Reading it after mount keeps the
  // server-rendered markup and the first client render in agreement; the inline
  // script in app.html has already applied any stored choice to the document,
  // so nothing moves on screen at this point.
  let choice = $state<"system" | "light" | "dark">("system");
  let systemDark = $state(false);

  onMount(() => {
    choice = storedChoice();

    const query = window.matchMedia("(prefers-color-scheme: dark)");
    systemDark = query.matches;

    // Until something is chosen, following the system means following it as it
    // changes rather than as it was when the page loaded.
    const onChange = (event: MediaQueryListEvent) => {
      systemDark = event.matches;
    };
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  });

  const showing = $derived(resolve(choice, systemDark));

  function toggle() {
    const next = opposite(showing);
    choice = next;
    rememberChoice(next);
    applyChoice(next, document.documentElement);
  }
</script>

<!--
  One button, two states. The icon shows the theme it switches to rather than
  the one in effect, which is what makes a single glyph readable: a moon means
  "go dark", and it is beside a page that is plainly light.

  The name says the same thing in words, because a glyph alone is a guess.
-->
<button type="button" class="theme" onclick={toggle} title={labelFor(showing)}>
  <span class="visually-hidden">{labelFor(showing)}</span>
  <span aria-hidden="true">{showing === "dark" ? "☀" : "☾"}</span>
</button>

<style>
  .theme {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 2.75rem;
    min-width: 2.75rem;
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--text-muted);
    font-size: 1.05rem;
    line-height: 1;
    border-radius: var(--radius);
  }

  .theme:hover {
    color: var(--accent);
    background: var(--surface-raised);
  }
</style>
