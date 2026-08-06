<script lang="ts">
  import { page } from "$app/state";

  // The download flow is issue #36. What matters here is that the route exists
  // and renders for an identifier the server has never seen, which is what the
  // single-page fallback has to deliver.
  const id = $derived(page.params.id);
</script>

<h1>Download</h1>
<p>Upload <code>{id}</code>.</p>
<p>The download interface is not built yet.</p>
