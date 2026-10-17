#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests for security-delta.py.
#
# The cases that matter are the two directions: a change that fixes something
# must pass, and a change that adds something must fail. A comparison that only
# ever passes would have been indistinguishable from a working one on the day
# it was written, because the branch it was written for fixed everything.
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "security-delta.py"

failures = 0


def gv(*findings: dict) -> str:
    """A govulncheck stream: concatenated objects, not one document."""
    out = [json.dumps({"config": {"scanner_name": "govulncheck"}})]
    for f in findings:
        out.append(json.dumps({"osv": {"id": f["osv"], "summary": f.get("summary", "")}}))
        out.append(json.dumps({"finding": f}))
    return "".join(out)


def reachable(osv: str, summary: str = "") -> dict:
    return {"osv": osv, "summary": summary,
            "trace": [{"module": "m", "package": "p", "function": "F"}]}


def module_only(osv: str) -> dict:
    return {"osv": osv, "trace": [{"module": "m", "version": "v1"}]}


def npm(*advisories: tuple[int, str]) -> str:
    vulns = {}
    for n, (ident, severity) in enumerate(advisories):
        vulns[f"pkg{n}"] = {"name": f"pkg{n}", "severity": severity,
                            "via": [{"source": ident, "title": f"advisory {ident}"}]}
    return json.dumps({"vulnerabilities": vulns})


def run(fmt: str, base: str, head: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        b, h = pathlib.Path(d) / "b.json", pathlib.Path(d) / "h.json"
        b.write_text(base)
        h.write_text(head)
        p = subprocess.run([sys.executable, str(SCRIPT), "--format", fmt,
                            "--base", str(b), "--head", str(h)],
                           capture_output=True, text=True)
        return p.returncode, p.stdout


def check(name: str, got, want) -> None:
    global failures
    if got != want:
        print(f"  FAIL {name}: got {got!r}, want {want!r}")
        failures += 1
    else:
        print(f"  ok   {name}")


# --- the two directions, which are the point ------------------------------

code, out = run("govulncheck", gv(reachable("GO-1")), gv())
check("a change that fixes a finding passes", code, 0)
check("  and says so", "fixed by this change: GO-1" in out, True)

code, out = run("govulncheck", gv(), gv(reachable("GO-1")))
check("a change that adds a finding fails", code, 1)
check("  and names it", "INTRODUCED BY THIS CHANGE: GO-1" in out, True)

# --- what must not fail ----------------------------------------------------

code, out = run("govulncheck", gv(reachable("GO-1")), gv(reachable("GO-1")))
check("a finding on both sides does not fail the change", code, 0)
check("  and is attributed to the base", "already on the base branch" in out, True)

code, _ = run("govulncheck", gv(), gv(module_only("GO-9")))
check("a module-level finding does not fail", code, 0)

# A finding that moves to a different package is the same finding.
moved = {"osv": "GO-1", "trace": [{"module": "other", "package": "q", "function": "G"}]}
code, _ = run("govulncheck", gv(reachable("GO-1")), gv(moved))
check("the same advisory reached another way does not fail", code, 0)

# --- npm ------------------------------------------------------------------

code, _ = run("npm-audit", npm((1, "high")), npm())
check("npm: a fixed advisory passes", code, 0)

code, out = run("npm-audit", npm(), npm((1, "high")))
check("npm: a new advisory fails", code, 1)

code, _ = run("npm-audit", npm(), npm((1, "moderate")))
check("npm: below high severity does not fail", code, 0)

code, _ = run("npm-audit", npm((1, "high")), npm((1, "high")))
check("npm: a carried advisory does not fail", code, 0)

# --- failing closed --------------------------------------------------------
#
# A baseline that cannot be read must not excuse a finding. The alternative is
# a scanner that goes quiet exactly when its own machinery breaks.
code, out = run("govulncheck", "{ this is not json", gv(reachable("GO-1")))
check("an unreadable base still fails on a finding", code, 1)
check("  and says why", "could not read the base scan" in out, True)

code, _ = run("govulncheck", "", gv())
check("an empty base with a clean head passes", code, 0)

print()
if failures:
    print(f"security-delta: {failures} test(s) failed")
    sys.exit(1)
print("security-delta: all tests passed")
