<script lang="ts">
  import { encode, toPath, TooMuchData } from "$lib/qr";

  let { link, hasPassword }: { link: string; hasPassword: boolean } = $props();

  // Never throws outward: a link too long for a code is a page without a code,
  // not a page with an error on it.
  const code = $derived.by(() => {
    try {
      return toPath(encode(link));
    } catch (error) {
      if (error instanceof TooMuchData) return null;
      throw error;
    }
  });
</script>

{#if code !== null}
  <details class="code">
    <summary>Show a code to scan</summary>

    <!--
      Drawn here, from the link. Sending it to a service that renders codes
      would hand that service the key, which is the one thing this whole design
      exists to prevent.

      One path rather than a rectangle per module: a large code has thousands,
      and thousands of elements is a page that scrolls badly on a phone.
    -->
    <svg
      class="qr"
      viewBox="0 0 {code.size} {code.size}"
      width="220"
      height="220"
      role="img"
      aria-label="A code containing the link, including its key"
    >
      <rect width={code.size} height={code.size} fill="#ffffff" />
      <path d={code.path} fill="#000000" />
    </svg>

    <p class="note">
      The code contains the whole link, key included. Anybody who photographs it
      can open the file.
    </p>

    {#if hasPassword}
      <!--
        The point the feature could otherwise undo. A password is a second
        channel; a code that also carried it would collapse the two into one,
        and the code outlives the page this warning is on.
      -->
      <p class="note">
        <strong>The password is not in the code, and should not be.</strong> It
        protects this file because it travels separately — put both in one
        picture and whoever sees the picture has both.
      </p>
    {/if}
  </details>
{/if}

<style>
  .code {
    margin: var(--space-4) 0;
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }

  summary {
    cursor: pointer;
    color: var(--text-muted);
    font-size: var(--text-sm);
    min-height: 1.75rem;
  }

  summary:hover {
    color: var(--text);
  }

  /* Always on white, in both themes: a scanner wants dark modules on a light
     ground, and inverting them is a code many readers refuse. The quiet zone is
     part of the drawing rather than padding, for the same reason. */
  .qr {
    display: block;
    margin: var(--space-4) 0;
    max-width: 100%;
    height: auto;
    border-radius: 4px;
  }

  .note {
    font-size: var(--text-sm);
    color: var(--text-muted);
    margin-bottom: var(--space-2);
  }
</style>
