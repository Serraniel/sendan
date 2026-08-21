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

  // Words rather than glyphs. A sun and a moon are guessable; a half-filled
  // circle for "whatever your system says" is not, and it was the state people
  // would most need explained. Three short words need no legend.
  const options: Array<{ value: ThemeChoice; label: string; name: string }> = [
    { value: "system", label: "Auto", name: "Follow your system" },
    { value: "light", label: "Light", name: "Light" },
    { value: "dark", label: "Dark", name: "Dark" },
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
      <span aria-hidden="true">{option.label}</span>
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
  /*
    Quiet by design. This is a preference, not an action, and it sits beside the
    only navigation on the page - a bordered widget there competed with the
    thing people came to do.

    So: no box, no background, no segments. Three small words, the one in effect
    picked out in the accent colour. Colour carries the state, and the word says
    which state it is, so neither has to be guessed.
  */
  .theme {
    display: inline-flex;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    border: 0;
    min-inline-size: 0;
  }

  .theme label {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 var(--space-2);
    /* Still a touch target, even without a visible edge. */
    min-height: 2.75rem;
    border-radius: var(--radius);
    cursor: pointer;
    font-size: var(--text-sm);
    color: var(--text-muted);
    white-space: nowrap;
  }

  .theme label:hover {
    color: var(--text);
  }

  .theme label.selected {
    color: var(--accent);
    font-weight: 650;
  }

  /* Colour alone would leave the state invisible to anybody who cannot
     distinguish these two, so the selected word is underlined as well. */
  .theme label.selected::after {
    content: "";
    position: absolute;
    left: var(--space-2);
    right: var(--space-2);
    bottom: 0.55rem;
    height: 2px;
    border-radius: 1px;
    background: var(--accent);
  }

  /* Invisible but not moved out of the way: it covers the whole control, so a
     press lands on the input itself rather than on the word drawn over it.
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
