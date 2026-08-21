<script lang="ts">
  import { formatSize } from "$lib/limits";
  import { formatDuration, type InstancePolicy } from "$lib/instance";

  let { policy, secure }: { policy: InstancePolicy; secure: boolean } = $props();

  /** One line, or nothing when the instance did not say. */
  type Rule = { label: string; value: string };

  const rules = $derived.by(() => {
    const out: Rule[] = [];

    if (policy.maxUploadSize !== null) {
      out.push({ label: "Largest upload", value: formatSize(policy.maxUploadSize) });
    }
    if (policy.defaultTtlSeconds !== null) {
      out.push({ label: "Kept by default", value: formatDuration(policy.defaultTtlSeconds) });
    }
    if (policy.maxTtlSeconds !== null) {
      out.push({ label: "Kept at most", value: formatDuration(policy.maxTtlSeconds) });
    }
    if (policy.allowInfiniteTtl !== null) {
      out.push({
        label: "Uploads that never expire",
        value: policy.allowInfiniteTtl ? "allowed" : "not allowed",
      });
    }
    if (policy.requireLimit !== null && policy.allowInfiniteTtl) {
      // Only meaningful where unlimited retention is permitted: otherwise every
      // upload already has a deadline and the rule can never bind.
      out.push({
        label: "A deadline or a download limit",
        value: policy.requireLimit ? "required" : "optional",
      });
    }
    if (policy.defaultMaxDownloads !== null) {
      out.push({
        label: "Downloads allowed by default",
        value:
          policy.defaultMaxDownloads === 0
            ? "no limit"
            : String(policy.defaultMaxDownloads),
      });
    }
    if (policy.compatEnabled !== null) {
      out.push({
        label: "Third-party client endpoints",
        value: policy.compatEnabled ? "served" : "not served",
      });
    }

    // Not reported by the instance: this one the browser can see for itself,
    // which makes it the only line here that does not depend on the instance
    // being honest.
    out.push({ label: "This connection", value: secure ? "encrypted" : "not encrypted" });
    return out;
  });
</script>

<!--
  Folded away by default. Most people uploading a file do not need this, and the
  ones who do are deciding whether to trust an instance at all - which is a
  deliberate act, not something to be interrupted with.
-->
<details class="rules">
  <summary>What this instance allows</summary>

  <dl>
    {#each rules as rule (rule.label)}
      <dt>{rule.label}</dt>
      <dd>{rule.value}</dd>
    {/each}
  </dl>

  <!--
    The honest caveat, and the reason this is not a security control: an
    instance can report whatever it likes. What does not depend on its honesty
    is the encryption, which happens here.
  -->
  <p class="caveat">
    Reported by the instance, so it is a convenience rather than a guarantee —
    an instance can say what it likes here. What does not depend on that is the
    encryption: the key is made and used in this browser, whatever the instance
    claims.
  </p>
</details>

<style>
  .rules {
    margin: var(--space-5) 0;
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: var(--text-sm);
  }

  summary {
    cursor: pointer;
    color: var(--text-muted);
    min-height: 1.75rem;
  }

  summary:hover {
    color: var(--text);
  }

  dl {
    display: grid;
    grid-template-columns: 1fr max-content;
    gap: var(--space-1) var(--space-4);
    margin: var(--space-4) 0 0;
  }

  dt {
    color: var(--text-muted);
  }

  dd {
    margin: 0;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .caveat {
    margin: var(--space-4) 0 0;
    padding-top: var(--space-3);
    border-top: 1px solid var(--border);
    color: var(--text-muted);
  }

  @media (max-width: 26rem) {
    dl {
      grid-template-columns: 1fr;
    }

    dd {
      text-align: left;
      margin-bottom: var(--space-2);
    }
  }
</style>
