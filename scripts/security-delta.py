#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Compares two vulnerability scans and fails only on what the change adds.
#
# # Why this exists
#
# The scanners used to fail a pull request for anything they found, which
# conflates two unrelated facts: that a change introduces a vulnerability, and
# that the branch it targets already had one. Only the first is the change's
# doing, and only the first is something its author can act on.
#
# The second is not harmless noise either. On 15 October the scheduled scan went
# red on main for an HTTP/2 advisory, and for two days every open dependency
# bump inherited that failure. Four of them were read as broken when none of
# them had changed anything. A check that is red for reasons the reader cannot
# address is how people learn to scroll past red.
#
# So: new findings fail, pre-existing findings are reported and do not. What
# keeps that honest is the other half, in the workflow - the scheduled scan on
# main still fails on everything and opens an issue, so "pre-existing" means
# "already being chased" rather than "ignored".
#
# # Why it takes files rather than running the scanners
#
# Producing the two scans needs two checkouts and a toolchain; comparing them
# needs neither. Keeping those apart means this half can be tested with fixtures
# on a laptop, which is how both directions below were checked.
import argparse
import json
import sys


def govulncheck_ids(raw: str) -> dict[str, str]:
    """IDs govulncheck reports as reachable, mapped to a one-line description.

    Only findings with a function in the trace count. govulncheck also reports
    vulnerabilities in modules that are merely required, which it does not fail
    on itself: including them here would make this stricter than the tool it is
    reading, and would fail a pull request for a package nobody calls.
    """
    found: dict[str, str] = {}
    summaries: dict[str, str] = {}
    for line in _json_stream(raw):
        if osv := line.get("osv"):
            summaries[osv["id"]] = osv.get("summary", "").strip()
        finding = line.get("finding")
        if not finding:
            continue
        trace = finding.get("trace") or []
        if any(frame.get("function") for frame in trace):
            found[finding["osv"]] = ""
    return {k: summaries.get(k, "") for k in found}


def npm_audit_ids(raw: str) -> dict[str, str]:
    """Advisory IDs from `npm audit --json`, at high severity and above.

    Keyed by the advisory rather than by the package: the same advisory reached
    through a second path is not a new problem, and a dependency tree that
    reshuffles underneath an unchanged advisory must not read as a regression.
    """
    report = json.loads(raw) if raw.strip() else {}
    out: dict[str, str] = {}
    for pkg in (report.get("vulnerabilities") or {}).values():
        if pkg.get("severity") not in ("high", "critical"):
            continue
        for via in pkg.get("via") or []:
            # A string here means "vulnerable because a dependency is"; the
            # advisory itself appears as an object elsewhere in the report.
            if isinstance(via, dict) and via.get("source") is not None:
                out[str(via["source"])] = f"{via.get('title', '')} ({pkg.get('name', '?')})"
    return out


def _json_stream(raw: str):
    """govulncheck -format json emits concatenated objects, not one document."""
    decoder = json.JSONDecoder()
    index = 0
    while index < len(raw):
        if raw[index].isspace():
            index += 1
            continue
        obj, end = decoder.raw_decode(raw, index)
        yield obj
        index = end
    return


READERS = {"govulncheck": govulncheck_ids, "npm-audit": npm_audit_ids}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--format", required=True, choices=sorted(READERS))
    p.add_argument("--base", required=True, help="scan of the branch being targeted")
    p.add_argument("--head", required=True, help="scan of the proposed change")
    p.add_argument("--label", default="", help="what to call this scan in the output")
    args = p.parse_args()

    read = READERS[args.format]
    try:
        base = read(_slurp(args.base))
    except Exception as err:
        # A base that cannot be read is treated as clean, which makes every
        # head finding new and fails. The alternative - treating it as
        # containing everything - would let a real regression through whenever
        # the baseline scan breaks, and a scanner that fails open is furniture.
        print(f"could not read the base scan ({err}); every finding will count as new")
        base = {}
    head = read(_slurp(args.head))

    label = args.label or args.format
    added = {k: v for k, v in head.items() if k not in base}
    carried = {k: v for k, v in head.items() if k in base}
    fixed = sorted(k for k in base if k not in head)

    for ident in fixed:
        print(f"{label}: fixed by this change: {ident}")
    for ident, summary in sorted(carried.items()):
        print(f"{label}: already on the base branch, not this change's doing: {ident} {summary}".rstrip())
    for ident, summary in sorted(added.items()):
        print(f"{label}: INTRODUCED BY THIS CHANGE: {ident} {summary}".rstrip())

    if added:
        print()
        print(f"{label}: this change adds {len(added)} vulnerability "
              f"{'finding' if len(added) == 1 else 'findings'} that the base branch does not have.")
        return 1

    if carried:
        print()
        print(f"{label}: {len(carried)} finding(s) carried over from the base branch. "
              "The scheduled scan fails on those and opens an issue; this check "
              "is about what the change itself adds.")
    else:
        print(f"{label}: nothing found.")
    return 0


def _slurp(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    sys.exit(main())
