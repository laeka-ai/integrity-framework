"""The README's links, anchors and tables must hold before it is read on GitHub.

README_UNDER_TEST points the checks at a copy (red controls); links still resolve from the repo root.
"""
import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
README = Path(os.environ.get("README_UNDER_TEST") or ROOT / "README.md")
# Counts of the Status column; a change of count is a decision, made here and in the README together.
EXPECTED_STATUS = {"proven": 19}
# "N passed" lines that report one test file (CONTRIBUTING.md's worked mutation example), not the whole suite.
SINGLE_FILE_RUNS = {("CONTRIBUTING.md", "7"), ("CONTRIBUTING.md", "8")}
NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20}


def numbered_lines():
    """(line number, text) outside fenced code blocks, plus the number of fence markers."""
    out, fences, fenced = [], 0, False
    for n, line in enumerate(README.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("```"):
            fences += 1
            fenced = not fenced
        elif not fenced:
            out.append((n, line))
    return out, fences


def cells(line):
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def tables(lines):
    """Runs of consecutive lines starting with a pipe."""
    found, run, last = [], [], None
    for n, line in lines:
        if line.startswith("|"):
            if run and n != last + 1:
                found.append(run)
                run = []
            run.append((n, line))
            last = n
        elif run:
            found.append(run)
            run = []
    return found + ([run] if run else [])


def slug(title):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", title)
    return re.sub(r"[^\w\- ]", "", title.strip().lower()).replace(" ", "-")


class TestReadme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines, cls.fences = numbered_lines()
        cls.targets = [
            (n, t)
            for n, line in cls.lines
            for t in re.findall(r"\]\(\s*<?([^)\s>]+)", line) + re.findall(r'(?:src|href)="([^"]+)"', line)
        ]
        layer = [t for t in tables(cls.lines) if cells(t[0][1])[:2] == ["Layer", "Status"]]
        cls.layer_rows = [(n, cells(line)) for n, line in layer[0][2:]] if len(layer) == 1 else None

    def test_code_fences_are_closed(self):
        self.assertEqual(self.fences % 2, 0, "README.md: a code fence is left open")

    def test_relative_links_reach_a_file_that_ships(self):
        relative = [(n, t) for n, t in self.targets if not re.match(r"[a-z][a-z0-9+.-]*:|#", t)]
        self.assertTrue(relative)
        for n, t in relative:
            path = unquote(t.split("#")[0])
            self.assertTrue((ROOT / path).exists(), "README.md:%d: link to a missing path: %s" % (n, t))
        linked = {t for _, t in relative}
        for doc in ("docs/canary-layer.md", "docs/quarantine-layer.md"):
            self.assertIn(doc, linked)

    def test_internal_anchors_reach_a_heading(self):
        slugs = {slug(m.group(1)) for _, line in self.lines for m in [re.match(r"#{1,6}\s+(.*)", line)] if m}
        anchors = [(n, t) for n, t in self.targets if t.startswith("#")]
        self.assertTrue(anchors)
        for n, t in anchors:
            self.assertIn(t[1:], slugs, "README.md:%d: anchor without a heading: %s" % (n, t))

    def test_tables_are_valid_gfm(self):
        found = tables(self.lines)
        self.assertTrue(found)
        for table in found:
            (n0, head), rows = table[0], table[1:]
            width = len(cells(head))
            self.assertTrue(rows, "README.md:%d: table without a delimiter row" % n0)
            for cell in cells(rows[0][1]):
                self.assertRegex(cell, r"^:?-+:?$", "README.md:%d: not a delimiter row" % rows[0][0])
            for n, line in rows:
                self.assertTrue(line.rstrip().endswith("|"), "README.md:%d: row not closed by a pipe" % n)
                self.assertEqual(len(cells(line)), width, "README.md:%d: %d cells expected" % (n, width))

    def test_layer_status_counts(self):
        self.assertIsNotNone(self.layer_rows, "README.md: exactly one Layer/Status table expected")
        for n, row in self.layer_rows:
            self.assertGreaterEqual(len(row), 2, "README.md:%d: row without a Status cell" % n)
        for status, expected in EXPECTED_STATUS.items():
            hits = [n for n, row in self.layer_rows if row[1].split(",")[0] == status]
            self.assertEqual(
                len(hits), expected, "README.md: %d rows '%s', %d expected, at lines %s" % (len(hits), status, expected, hits)
            )
        self.assertEqual(len(self.layer_rows), sum(EXPECTED_STATUS.values()), "README.md: a row has an unknown Status")

    def test_prose_proven_count_matches_the_table(self):
        text = " ".join(line for _, line in self.lines)
        m = re.search(r"(\w+) layers are \*\*proven\*\*", text)
        self.assertTrue(m, "README.md: the sentence counting proven layers is gone")
        self.assertEqual(NUMBER_WORDS.get(m.group(1).lower()), EXPECTED_STATUS["proven"])

    def test_no_layer_is_left_in_flight(self):
        stale = [n for n, line in self.lines if re.search(r"being built|planned", line)]
        self.assertEqual(stale, [], "README.md: 'being built' or 'planned' left at lines %s" % stale)

    def test_skill_guard_row_absent(self):
        self.assertIsNotNone(self.layer_rows)
        named = [n for n, row in self.layer_rows if re.search(r"skill.?guard", " ".join(row), re.I)]
        self.assertEqual(
            named, [], "README.md: Skill Guard is not announced before the real scanner is in place; rows at lines %s" % named
        )

    def test_test_counts_are_the_collected_count(self):
        raw = README.read_text(encoding="utf-8")
        claims = re.findall(r"tests-(\d+)%20passing", raw) + re.findall(r"# (\d+) tests\b", raw)
        self.assertEqual(len(claims), 2, "README.md: the badge and the Start here count are both expected")
        self.assertEqual(len(set(claims)), 1, "README.md: the badge and the Start here count differ: %s" % claims)
        # Checked here, not in a test of its own: one more test would change the very count the docs cite.
        try:
            tracked = subprocess.run(
                ["git", "ls-files", "-z", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            tracked = ""  # not a git checkout (a release archive): the docs are checked where they are edited
        stray = [
            "%s:%d: %s passed" % (doc, n, cited)
            for doc in filter(None, tracked.split("\0"))
            for n, line in enumerate((ROOT / doc).read_text(encoding="utf-8").splitlines(), 1)
            for cited in re.findall(r"\b(\d+) passed\b", line)
            if cited != claims[0] and (doc, cited) not in SINGLE_FILE_RUNS
        ]
        self.assertEqual(stray, [], "the README says %s tests" % claims[0])
        if importlib.util.find_spec("pytest") is None:
            self.skipTest("pytest is not importable here: the README's count is not checked against the collection")
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"], cwd=ROOT, capture_output=True, text=True
        )
        m = re.search(r"^(\d+) tests? collected", run.stdout, re.M)
        self.assertTrue(run.returncode == 0 and m, "pytest did not collect cleanly:\n" + run.stdout[-500:])
        self.assertEqual(set(claims), {m.group(1)}, "README.md: pytest collects %s tests" % m.group(1))


if __name__ == "__main__":
    unittest.main()
