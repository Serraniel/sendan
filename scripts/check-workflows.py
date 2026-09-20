#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Rejects a workflow GitHub would refuse to parse.
#
# YAML permits a duplicate key and most parsers quietly keep the last one, so
# `yaml.safe_load` reports a file as fine that GitHub answers with:
#
#     failed to parse workflow: (Line: 95, Col: 9): 'with' is already defined
#
# That reached main and left the release workflow undispatchable - it could not
# be started at all, which for a workflow that only ever runs by hand or by
# call is a failure nothing else notices. A run that never starts produces no
# red mark anywhere.

import re
import sys
from pathlib import Path

import yaml


class StrictLoader(yaml.SafeLoader):
    """A loader that refuses what GitHub refuses."""


def no_duplicates(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            mark = key_node.start_mark
            raise yaml.constructor.ConstructorError(
                None, None,
                f"'{key}' is already defined",
                mark,
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicates
)

def unpinned_images(text):
    """Container images named by tag rather than by digest.

    A tag is a name somebody else can repoint, which is why the Dockerfile pins
    its bases by digest and these workflows pin their actions by commit. The
    object store here was `quay.io/minio/minio:latest` until the project behind
    that name was archived underneath it.

    Matched on the reference rather than on the command, because a `docker run`
    long enough to need continuation lines puts the image on a line of its own.

    Only references carrying a registry host - a dot before the first slash.
    The bare Docker Hub form, `minio/minio`, is indistinguishable from a path
    and is not caught; naming the registry is the habit this repository already
    keeps.
    """
    reference = re.compile(
        r"(?<![\w/@.-])"
        r"(?P<ref>[a-z0-9-]+\.[a-z0-9.-]+/[\w./-]+(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?)"
    )
    # A Go module path is shaped exactly like an image reference, and
    # `go install aead.dev/minisign/cmd/minisign@latest` is not a container.
    go_tooling = re.compile(r"\bgo (?:install|run|get|build|tool)\b")

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or go_tooling.search(line):
            continue
        for match in reference.finditer(line):
            ref = match.group("ref")
            if "@sha256:" in ref:
                continue
            # A URL rather than an image: something addressed over http(s) is
            # fetched, not run.
            before = line[: match.start()]
            if before.rstrip().endswith(("//", "http:", "https:")) or "://" in before:
                continue
            yield number, ref


def unchecked_curls(text):
    """`curl` invocations that would write an error page to a file.

    Without --fail, curl treats a 404 or a 410 as a successful download and
    saves the body. That is how an archived project's notice page became an
    executable in this workflow, and how it then failed as a shell script
    rather than as a download.
    """
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or "curl " not in line:
            continue
        flags = re.findall(r"(?<![\w-])-{1,2}[A-Za-z-]+", line)
        if any(f == "--fail" or (f.startswith("-") and not f.startswith("--") and "f" in f) for f in flags):
            continue
        yield number, stripped[:70]


failed = 0
for path in sorted(Path(".github/workflows").glob("*.yml")):
    text = path.read_text()
    try:
        yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as error:
        print(f"{path}: {error}")
        failed = 1
        continue

    for number, ref in unpinned_images(text):
        print(f"{path}:{number}: {ref} is named by tag; pin it by digest")
        failed = 1

    for number, snippet in unchecked_curls(text):
        print(f"{path}:{number}: curl without --fail would save an error page: {snippet}")
        failed = 1

sys.exit(failed)
