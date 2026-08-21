<script lang="ts">
  import { onMount } from "svelte";
  import {
    applyChoice,
    labelFor,
    rememberChoice,
    resolve,
    storedChoice,
    type ThemeChoice,
  } from "$lib/theme";

  // Starts at "system" so the server-rendered markup and the first client
  // render agree. The stored value is read after mount; the inline script in
  // app.html has already applied it to the document by then, so nothing changes
  // visually here - only the control catches up with what is on screen.
  let choice = $state<ThemeChoice>("system");
  let systemDark = $state(false);

  onMount(() => {
    choice = storedChoice();

    const query = window.matchMedia("(prefers-color-scheme: dark)");
    systemDark = query.matches;

    // Following the system means following it as it changes, not as it was when
    // the page loaded.
    const onChange = (event: MediaQueryListEvent) => {
      systemDark = event.matches;
    };
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  });

  const showing = $derived(resolve(choice, systemDark));

  const options: Array<{ value: ThemeChoice; glyph: string; name: string }> = [
    { value: "system", glyph: "◐", name: "Follow your system" },
    { value: "light", glyph: "☀", name: "Light" },
    { value: "dark", glyph: "☾", name: "Dark" },
  ];

  function choose(next: ThemeChoice) {
    choice = next;
    rememberChoice(next);
    applyChoice(next, document.documentElement);
  }
</script>

<!--
  Three controls rather than one that cycles.

  A cycle was the wrong shape: from "follow your system" on a system already set
  to light, selecting light changes nothing visible, so the press looked broken
  and a second one was needed before anything happened. Every state here is one
  press away and shows which one is in effect, so a press that changes no colour
  is still visibly a press that did something.

  A radio group rather than buttons, because that is what this is: three
  exclusive choices, one selected. It also means the arrow keys work and a
  screen reader says "2 of 3" without any of it being written here.
-->
<fieldset class="theme" aria-describedby="theme-state">
  <legend class="visually-hidden">Theme</legend>
  {#each options as option (option.value)}
    <label class:selected={choice === option.value} title={option.name}>
      <input
        type="radio"
        name="theme"
        value={option.value}
        checked={choice === option.value}
        onchange={() => choose(option.value)}
      />
      <span aria-hidden="true">{option.glyph}</span>
      <span class="visually-hidden">{option.name}</span>
    </label>
  {/each}
</fieldset>

<!--
  What is in effect, in words, for anybody who cannot read it off the colours.
  Kept out of the options' own names on purpose: naming the resolved theme
  inside "follow your system" made two options answer to the same word, which
  is ambiguous to anybody selecting by name rather than by sight.

  Not announced: it changes as the result of a press just made.
-->
<span class="visually-hidden" id="theme-state">
  {labelFor(choice)}{#if choice === "system"}, showing {showing}{/if}
</span>

<style>
  .theme {
    display: inline-flex;
    gap: 0;
    margin: 0;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-raised);
    min-inline-size: 0;
  }

  .theme label {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    /* 40px each, so the group of three still clears a touch target vertically
       while staying narrow enough for a phone header. */
    width: 2.5rem;
    height: 2.5rem;
    border-radius: calc(var(--radius) - 1px);
    cursor: pointer;
    font-size: 1rem;
    line-height: 1;
    color: var(--text-muted);
  }

  .theme label:hover {
    color: var(--text);
    background: var(--surface);
  }

  .theme label.selected {
    background: var(--surface);
    color: var(--accent);
    box-shadow: inset 0 0 0 1px var(--border);
  }

  /* Invisible but not moved out of the way: it covers the whole control, so a
     press lands on the input itself rather than on the glyph drawn over it.
     A one-pixel input tucked into a corner is a control that a pointer, and a
     browser test, cannot actually hit. */
  .theme input {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    margin: 0;
    opacity: 0;
    cursor: pointer;
  }

  /* Drawn above the input, so it must not swallow the press. */
  .theme span[aria-hidden="true"] {
    pointer-events: none;
  }

  .theme label:focus-within {
    outline: 2px solid var(--focus);
    outline-offset: 2px;
  }
</style>
