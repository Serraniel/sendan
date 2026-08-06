// SPDX-License-Identifier: AGPL-3.0-or-later

/** What an instance reports about the code it is running. */
export interface Build {
  /** The release, or "dev" for a build the release tooling did not stamp. */
  version: string;
  /** The revision this binary was built from. */
  commit: string;
  /** Whether the working tree held uncommitted changes when it was built. */
  modified: boolean;
  /** Where the corresponding source can be obtained. */
  source: string;
  /** The licence the source is under. */
  license: string;
}

/**
 * Reads what the instance says it is running.
 *
 * AGPL §13 obliges the operator of a modified instance to offer its users the
 * source of the version they are talking to. The endpoint is the machine
 * readable half; this is what makes it visible rather than buried.
 *
 * It resolves to null rather than throwing. A footer is not worth an error
 * boundary, and an instance that cannot answer this is one whose upload page
 * should still work.
 */
export async function fetchBuild(fetcher: typeof fetch = fetch): Promise<Build | null> {
  try {
    const response = await fetcher("/api/source", { headers: { accept: "application/json" } });
    if (!response.ok) return null;
    return parseBuild(await response.json());
  } catch {
    return null;
  }
}

/**
 * Validates what came back.
 *
 * The response is JSON from the server, which is the party this whole report is
 * about, so its shape is checked rather than assumed. A footer that renders
 * `undefined` because a field was missing would be worse than one that renders
 * nothing.
 */
export function parseBuild(value: unknown): Build | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;

  const strings = ["version", "commit", "source", "license"] as const;
  for (const key of strings) {
    if (typeof v[key] !== "string") return null;
  }
  if (typeof v.modified !== "boolean") return null;

  return {
    version: v.version as string,
    commit: v.commit as string,
    modified: v.modified,
    source: v.source as string,
    license: v.license as string,
  };
}

/**
 * A short form of a revision, for display.
 *
 * Seven characters is what a person compares against a repository; the full
 * forty is in the title attribute for anyone who needs to paste it.
 */
export function shortCommit(commit: string): string {
  if (commit === "" || commit === "unknown") return "unknown";
  return commit.length > 7 ? commit.slice(0, 7) : commit;
}

/**
 * Whether the source link can correspond to what is running.
 *
 * A build from a modified tree has no commit that describes it, so no link can
 * be exact. Saying so is the difference between a transparency measure and a
 * decoration.
 */
export function sourceIsExact(build: Build): boolean {
  return !build.modified && build.commit !== "" && build.commit !== "unknown";
}
