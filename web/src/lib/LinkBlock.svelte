<script lang="ts">
  /**
   * A download link, shown whole.
   *
   * One presentation rather than two. This began as a single-line readonly
   * field with the link repeated below it, because a field long enough to
   * scroll settles at the end - so the first thing under the word "Link" read
   * like a broken link, and the copy below existed to compensate (#255).
   *
   * Wrapping shows the whole link, `user-select: all` keeps the one gesture the
   * field was there for, and the fragment can be marked, which a field cannot
   * do. It is a component because two pages show the same link and only one of
   * them had learned this.
   */
  let { link, id }: { link: string; id?: string } = $props();

  // Split for display only. The fragment is shown apart from the rest so it is
  // visibly part of the link rather than something trailing off the end.
  const path = $derived(link === "" ? "" : link.slice(0, link.indexOf("#") + 1));
  const secret = $derived(link === "" ? "" : link.slice(link.indexOf("#") + 1));
</script>

<span {id} class="link"><span>{path}</span><strong>{secret}</strong></span>

<style>
  .link {
    display: block;
    /* The link is one unbroken token; without this it is the widest thing on
       the page at every width. */
    overflow-wrap: anywhere;
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    padding: var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-sunken);
    /* One click takes the whole link, which is what the field it replaced was
       for. Partial selection by a stray drag is not possible either. */
    user-select: all;
    -webkit-user-select: all;
  }

  .link strong {
    color: var(--accent);
  }
</style>
