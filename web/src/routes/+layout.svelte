<script lang="ts">
  import { onMount } from "svelte";
  import BrowserCheck from "$lib/BrowserCheck.svelte";
  import { type Build, fetchBuild, shortCommit, sourceIsExact } from "$lib/source";
  import { fetchInstancePolicy, nothingKnown } from "$lib/instance";
  import OperatorBanner from "$lib/OperatorBanner.svelte";
  import ThemeToggle from "$lib/ThemeToggle.svelte";
  import "../app.css";

  let { children } = $props();
  let build = $state<Build | null>(null);

  // Fetched here rather than per page, because a notice about the instance
  // belongs on every page. The send page asks for the same answer and gets it
  // from the browser's cache.
  let policy = $state(nothingKnown);

  // Read after mount rather than during render: the footer is not worth
  // delaying the page for, and an instance that cannot answer should still
  // serve one that works.
  onMount(async () => {
    build = await fetchBuild();
    policy = await fetchInstancePolicy();
  });
</script>

<!--
  Visible only once focused, and first in the order, so somebody arriving by
  keyboard can pass the header rather than tabbing through it on every page.
-->
<a class="skip" href="#main">Skip to content</a>

<OperatorBanner banner={policy.banner} />

<header>
  <div class="bar">
    <a class="wordmark" href="/">Sendan</a>
    <nav aria-label="Main">
      <a href="/uploads">Your uploads</a>
      <ThemeToggle />
    </nav>
  </div>
</header>

<main id="main" tabindex="-1">
  <BrowserCheck>
    {@render children()}
  </BrowserCheck>
</main>

<footer>
  {#if build}
    <p>
      Sendan
      <span title={build.commit}>{build.version} ({shortCommit(build.commit)})</span>
      &middot;
      <!--
        Opened elsewhere rather than in place: this leads off the instance
        entirely, and somebody who follows it with an upload in progress loses
        it. noopener as well as noreferrer, so the opened page gets no handle
        on this one.
      -->
      <a class="source" href={build.source} target="_blank" rel="noreferrer noopener">
        <!--
          A neutral mark rather than a host's logo, and that is a correctness
          decision before it is a trademark one: SENDAN_SOURCE_URL is the
          operator's to set, and an operator running modified code is obliged to
          point it at their own source. A logo would therefore be wrong exactly
          on the instances where this link matters most.

          Inline and aria-hidden: the policy allows no external image, a remote
          one would report every visitor to its host, and the word beside it is
          what names the link.
        -->
        <svg
          class="mark"
          viewBox="0 0 16 16"
          width="14"
          height="14"
          aria-hidden="true"
          focusable="false"
        >
          <path
            d="M4.5 2.5v7M4.5 13.5a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM4.5 2.5a2 2 0 1 0 0-.001M11.5 6.5a2 2 0 1 0 0-.001M11.5 6.5v1a3 3 0 0 1-3 3h-4"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
        source<span class="visually-hidden"> (opens in a new tab)</span>
      </a>
      &middot;
      <!--
        Reachable from every page, because a list kept only in this browser is
        one somebody has to be able to find again without a bookmark.
      -->
      <a href="/uploads">your uploads</a>
      &middot;
      <!--
        Served from the instance rather than only kept in the repository: what
        is distributed to a browser is the bundle, and the licences of the code
        inside it require their notices to travel with the copy.
      -->
      <a href="/third-party-notices.txt">{build.license}, and notices</a>
      &middot;
      <!--
        Served by this instance rather than linked to a forge: the source URL is
        the operator's to set and need not be a GitHub one, so a link built from
        it would guess at a layout most instances do not have. This way the
        changelog somebody reads belongs to the code answering them.
      -->
      <a href="/changelog.md">what changed</a>
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

  .skip {
    position: absolute;
    left: var(--space-2);
    top: -4rem;
    z-index: 2;
    padding: var(--space-2) var(--space-3);
    background: var(--surface-raised);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    transition: top 0.12s ease-out;
  }

  .skip:focus {
    top: var(--space-2);
  }

  header {
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }

  .bar,
  main,
  footer {
    /* One column, one gutter, everywhere. A page that sets its own width is a
       page that disagrees with the others at some viewport nobody tested. */
    max-width: var(--page);
    margin: 0 auto;
    padding-inline: var(--space-4);
  }

  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    min-height: 3.5rem;
  }

  .wordmark {
    font-weight: 700;
    font-size: var(--text-lg);
    letter-spacing: -0.02em;
    color: var(--text);
    text-decoration: none;
  }

  .wordmark:hover {
    color: var(--accent);
  }

  nav {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  nav a {
    padding: var(--space-2);
    border-radius: var(--radius);
    text-decoration: none;
    color: var(--text-muted);
    font-size: var(--text-sm);
    /* The link is a touch target as much as the button beside it. */
    display: inline-flex;
    align-items: center;
    min-height: 2.75rem;
  }

  nav a:hover {
    color: var(--accent);
    background: var(--surface-raised);
  }

  main {
    padding-block: var(--space-6) var(--space-7);
  }

  /* Removed rather than styled: focusing the region after the skip link should
     not draw a box around the whole page. */
  main:focus {
    outline: none;
  }

  footer {
    border-top: 1px solid var(--border);
    padding-block: var(--space-4) var(--space-6);
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  footer p {
    margin: 0;
  }

  .source {
    /* The mark sits on the text baseline rather than above it, and the pair
       never breaks across a line. */
    display: inline-flex;
    align-items: center;
    gap: 0.3em;
    white-space: nowrap;
  }

  .mark {
    /* Takes the link's colour, including on hover, because it is part of the
       link rather than an image beside one. */
    flex: none;
  }

  .caveat {
    margin-top: var(--space-2);
    color: var(--danger);
    font-weight: 600;
  }

  @media (max-width: 26rem) {
    /* At the narrowest widths the wordmark and the two controls stop fitting
       on one line together; the nav wraps beneath rather than shrinking the
       touch targets. */
    .bar {
      flex-wrap: wrap;
      padding-block: var(--space-2);
    }
  }
</style>
