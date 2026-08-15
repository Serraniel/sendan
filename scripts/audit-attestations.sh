#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Asserts that a built image carries the attestations it is published with.
#
# The release workflow asks BuildKit for a software bill of materials and SLSA
# provenance, and both arrive as flags on a build step. A flag that stops taking
# effect - renamed, moved, defaulted differently by a new action version - looks
# exactly like a flag that works: the build succeeds, the image is pushed, and
# what is missing is only discovered by the operator who tries to verify it, if
# anybody ever does.
#
# Nothing else checks this. `docker build` reports no error for an attestation
# it was never asked to make, and the release workflow runs on a tag, where
# there is nothing after it to catch anything.
#
# Every platform is checked rather than the first. Attestations are per-manifest,
# so an arm64 image with no provenance is a real outcome and one that an amd64
# check would not see.
#
# Takes an OCI layout, as `--output type=oci` produces it, because that is the
# artefact a build makes before it is pushed anywhere - so this runs on a pull
# request, against an image nobody has to publish first.
set -euo pipefail

cd "$(dirname "$0")/.."

archive="${1:?usage: audit-attestations.sh <image.tar>}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tar -xf "$archive" -C "$work"

python3 - "$work" <<'PY'
import json, sys, os

root = sys.argv[1]

# The predicate types the release is expected to carry. SPDX is the bill of
# materials; the SLSA one is what ties an image to the source and the workflow
# that built it, which is the half an operator checking a deployment needs.
WANTED = {
    "https://spdx.dev/Document": "SBOM",
    "https://slsa.dev/provenance/v1": "provenance",
}


def blob(digest):
    with open(os.path.join(root, "blobs", *digest.split(":"))) as f:
        return json.load(f)


index = blob(json.load(open(os.path.join(root, "index.json")))["manifests"][0]["digest"])

# Attestations do not sit next to the image they describe; they are separate
# manifests that name it, so the platforms have to be collected first and the
# attestations matched back onto them.
platforms, attested = {}, {}

for entry in index["manifests"]:
    annotations = entry.get("annotations", {})
    if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
        describes = annotations.get("vnd.docker.reference.digest")
        found = set()
        for layer in blob(entry["digest"])["layers"]:
            predicate = layer.get("annotations", {}).get("in-toto.io/predicate-type")
            if predicate in WANTED:
                found.add(predicate)
        attested[describes] = found
        continue

    platform = entry.get("platform", {})
    if platform.get("os") and platform.get("os") != "unknown":
        platforms[entry["digest"]] = f"{platform['os']}/{platform.get('architecture')}"

if not platforms:
    sys.exit("audit-attestations: no platform manifests in this image")

missing = False
for digest, name in sorted(platforms.items(), key=lambda kv: kv[1]):
    found = attested.get(digest, set())
    for predicate, label in WANTED.items():
        if predicate in found:
            print(f"  {name:16} {label}")
        else:
            print(f"  {name:16} {label}  MISSING")
            missing = True

if missing:
    sys.exit(
        "audit-attestations: an image was built without the attestations it is "
        "published with, so nobody could verify what it was built from"
    )

print(f"\nEvery platform ({len(platforms)}) carries an SBOM and SLSA provenance.")
PY
