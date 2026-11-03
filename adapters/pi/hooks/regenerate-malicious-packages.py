#!/usr/bin/env python3
"""regenerate-malicious-packages.py: rebuild malicious-packages.json from ossf/malicious-packages.

    /usr/bin/python3 -I adapters/pi/hooks/regenerate-malicious-packages.py [output path]

It asks GitHub for the head commit of main, reads the tarball of that commit as a stream (nothing is extracted, no
name from the tarball becomes a path) and keeps the OSV reports under osv/malicious/ for the three ecosystems the
install guard judges (npm, PyPI, crates.io). A row is [ecosystem, name, versions or "all", MAL id].

OSV reads a report's `versions` and `ranges` together, so a range with no upper bound affects versions nobody has
listed yet: such a report, or one with no version at all, is "all". Only a report whose ranges are all bounded
keeps its list of versions. The output replaces the old file only once it is complete.
"""
import json
import os
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone

REPO = "ossf/malicious-packages"
ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi", "crates.io": "crates"}
UPPER_BOUNDS = ("fixed", "last_affected", "limit")
HERE = os.path.dirname(os.path.abspath(__file__))


def affected_versions(affected: dict):
    versions = affected.get("versions") or []
    for r in affected.get("ranges") or []:
        if not any(k in e for e in r.get("events") or [] for k in UPPER_BOUNDS):
            return "all"
    return sorted(set(versions)) or "all"


def rows_of(report: dict) -> list:
    mal = report.get("id")
    if report.get("withdrawn") or not isinstance(mal, str) or not mal.startswith("MAL-"):
        return []
    rows = []
    for affected in report.get("affected") or []:
        pkg = affected.get("package") or {}
        eco, name = ECOSYSTEMS.get(pkg.get("ecosystem")), pkg.get("name")
        if eco and name and isinstance(name, str):
            rows.append([eco, name, affected_versions(affected), mal])
    return rows


def rows_of_tarball(stream) -> tuple:
    """(rows sorted, reports read). A report that is not JSON stops the run: a partial base would look complete."""
    rows, reports = [], 0
    with tarfile.open(fileobj=stream, mode="r|gz") as tar:
        for member in tar:
            path = member.name.split("/", 1)[-1]
            if member.isfile() and path.startswith("osv/malicious/") and path.endswith(".json"):
                reports += 1
                rows += rows_of(json.load(tar.extractfile(member)))
    return sorted(rows, key=lambda r: (r[0], r[1], r[3])), reports


def main(argv: list) -> int:
    output = argv[0] if argv else os.path.join(HERE, "..", "data", "malicious-packages.json")
    with urllib.request.urlopen("https://api.github.com/repos/%s/commits/main" % REPO, timeout=60) as r:
        head = json.load(r)
    sha = head["sha"]
    with urllib.request.urlopen("https://codeload.github.com/%s/tar.gz/%s" % (REPO, sha), timeout=600) as r:
        rows, reports = rows_of_tarball(r)
    if not rows:
        print("no row read from %s at %s: the base is left as it is" % (REPO, sha), file=sys.stderr)
        return 1
    meta = {"source": "https://github.com/%s" % REPO, "license": "Apache-2.0", "commit": sha,
            "commit_date": head["commit"]["committer"]["date"],
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "fields": ["ecosystem", "name", "versions or all", "MAL id"]}
    tmp = output + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(meta, ensure_ascii=False)[:-1] + ',\n"packages": [\n')
        f.write(",\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows))
        f.write("\n]}\n")
    os.replace(tmp, output)
    print("%s at %s (%s): %d reports, %d rows -> %s" % (REPO, sha, meta["commit_date"], reports, len(rows), output))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
