"""The Pi adapter as a whole: the example wires guards that ship, every guard keeps its page
and its test, the adapter page cites tests that exist, and no relative link of README.md or
docs/ is broken. With the four guard suites beside it, ONE offline command proves the adapter
(stdlib only, no network, no model):

    python3 -m unittest discover -s tests -p 'test_pi_*.py'
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PI = ROOT / "adapters" / "pi"
PAGE = ROOT / "docs" / "pi-adapter.md"

FENCE = re.compile(r"^\s*(```|~~~).*?^\s*\1", re.S | re.M)
LINK = re.compile(r"""\]\(\s*<?([^)\s>]+)|\b(?:href|src)=["']([^"']+)""")


def broken_links(md):
    """The relative link targets of one markdown file that are not on disk."""
    # shortcut: #fragments and reference-style links ([text][ref]) are not checked,
    # upgrade when README.md or docs/ start to rely on either.
    text = re.sub(r"`[^`\n]*`", "", FENCE.sub("", md.read_text(encoding="utf-8")))
    bad = []
    for m in LINK.finditer(text):
        target = (m.group(1) or m.group(2)).split("#")[0].split("?")[0]
        if not target or re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
            continue  # same-page anchor, or an absolute URL
        if not (md.parent / target).exists():
            bad.append(target)
    return bad


class TestPiAdapter(unittest.TestCase):
    def test_example_wires_guards_that_ship_under_isolated_python(self):
        # /opt/pi-guard stands for the copy of this repository (docs/install-pi.md, step 1).
        text = (PI / "hooks.example.yaml").read_text(encoding="utf-8")
        wired = re.findall(r"event: (\S+)\n\s+actions:\n\s+- bash: /usr/bin/python3 -I /opt/pi-guard/(\S+)", text)
        self.assertEqual(len(wired), text.count("- bash:"), "an action is not `python3 -I` on a guard")
        for _, rel in wired:
            self.assertTrue((ROOT / rel).is_file(), "hooks.example.yaml wires a missing file: %s" % rel)
        # No wildcard in pi-yaml-hooks: the write guard must sit on BOTH writing tools.
        self.assertEqual({(event, Path(rel).stem) for event, rel in wired},
                         {("tool.before.bash", "bash-boundary"), ("tool.before.bash", "install-guard"),
                          ("tool.before.write", "write-guard"), ("tool.before.edit", "write-guard")})

    def test_every_guard_keeps_its_page_and_its_test(self):
        self.assertTrue(PAGE.is_file(), "docs/pi-adapter.md is missing")
        page = PAGE.read_text(encoding="utf-8")
        guards = {p.stem for p in (PI / "hooks").glob("*.py")} - {"regenerate-malicious-packages"}
        self.assertTrue(guards)
        for g in sorted(guards):
            self.assertTrue((ROOT / "docs" / "gates" / ("pi-%s.md" % g)).is_file(), "no gate page: %s" % g)
            self.assertTrue((ROOT / "tests" / ("test_pi_%s.py" % g.replace("-", "_"))).is_file(), "no test: %s" % g)
            self.assertIn("(gates/pi-%s.md)" % g, page, "docs/pi-adapter.md does not link the page of %s" % g)

    def test_page_is_linked_from_the_readme_and_cites_tests_that_exist(self):
        self.assertTrue(PAGE.is_file(), "docs/pi-adapter.md is missing")
        self.assertIn("(docs/pi-adapter.md)", (ROOT / "README.md").read_text(encoding="utf-8"))
        defined = set()
        for t in (ROOT / "tests").glob("test_pi_*.py"):
            defined |= set(re.findall(r"def (test_\w+)\(", t.read_text(encoding="utf-8")))
        cited = set(re.findall(r"`(test_\w+)`", PAGE.read_text(encoding="utf-8")))
        self.assertTrue(cited, "the page cites no test")
        self.assertEqual(cited - defined, set(), "the page cites tests that do not exist")

    def test_no_broken_relative_link_in_readme_or_docs(self):
        bad = {}
        for md in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
            targets = broken_links(md)
            if targets:
                bad[str(md.relative_to(ROOT))] = targets
        self.assertEqual(bad, {})

    def test_link_check_sees_a_broken_link(self):
        with tempfile.TemporaryDirectory() as d:
            md = Path(d) / "a.md"
            md.write_text("[ok](a.md) [gone](b.md#x) <img src='c.png'> `[code](d.md)` [web](https://example.org)\n")
            self.assertEqual(broken_links(md), ["b.md", "c.png"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_tool_call_helper_suite(self):
        r = subprocess.run(["node", "--test", str(ROOT / "tests" / "pi-tool-call.test.mjs")],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
