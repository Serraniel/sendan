// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

import { describe, expect, it, vi } from "vitest";
import { explainRevoke, RevokeError, type RevokeFault, revokeUpload } from "./revoke";

const id = "anuploadidentifier0000";
const token = "b3duZXItdG9rZW4";

function answering(status: number) {
  return vi.fn(async () => new Response(null, { status }));
}

describe("removing an upload", () => {
  it("sends the owner token as a bearer credential, never in the path", async () => {
    const fetch = answering(204);
    await revokeUpload(id, token, { fetch }, "https://files.example.org");

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];

    expect(url).toBe(`https://files.example.org/api/uploads/${id}`);
    expect(url).not.toContain(token);
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${token}`);
  });

  // The instance answers alike for a wrong token and an upload that is not
  // there, so that asking about identifiers in turn reveals nothing. A client
  // that reported them differently would undo that.
  it.each([[401], [403], [404]])("reports %i as not being the owner", async (status) => {
    const err = await revokeUpload(id, token, { fetch: answering(status) }).catch((e) => e);
    expect(err).toBeInstanceOf(RevokeError);
    expect((err as RevokeError).fault).toBe("not-owner");
  });

  it("reports an instance that answered badly", async () => {
    const err = await revokeUpload(id, token, { fetch: answering(500) }).catch((e) => e);
    expect((err as RevokeError).fault).toBe("instance-error");
  });

  it("reports an instance it could not reach", async () => {
    const fetch = vi.fn(async () => {
      throw new TypeError("network");
    });
    const err = await revokeUpload(id, token, { fetch }).catch((e) => e);
    expect((err as RevokeError).fault).toBe("unreachable");
  });

  // Cancelling is not a failure to explain to somebody.
  it("passes an abort through untouched", async () => {
    const fetch = vi.fn(async () => {
      throw new DOMException("aborted", "AbortError");
    });
    const err = await revokeUpload(id, token, { fetch }).catch((e) => e);
    expect(err).toBeInstanceOf(DOMException);
  });

  it("explains every fault it can report", () => {
    const faults: RevokeFault[] = ["not-owner", "unreachable", "instance-error"];
    for (const fault of faults) {
      expect(explainRevoke(fault).length).toBeGreaterThan(20);
    }
  });

  // The two failures a person can act on differently: one means the file is
  // gone, the other means it is still there.
  it("says whether the upload is still there", () => {
    expect(explainRevoke("unreachable")).toContain("not been removed");
    expect(explainRevoke("instance-error")).toContain("still there");
  });
});
