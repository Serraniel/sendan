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

failed = 0
for path in sorted(Path(".github/workflows").glob("*.yml")):
    try:
        yaml.load(path.read_text(), Loader=StrictLoader)
    except yaml.YAMLError as error:
        print(f"{path}: {error}")
        failed = 1

sys.exit(failed)
