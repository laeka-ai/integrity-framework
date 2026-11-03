import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "adapters" / "pi" / "hooks" / "fail-closed.py"


def run(*args):
    return subprocess.run([sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, timeout=30)


class TestPiFailClosed(unittest.TestCase):
    def test_list_names_four_pinned_sites(self):
        r = run("list")
        self.assertEqual(r.returncode, 0)
        lines = r.stdout.strip().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(len(line.split()) == 3 for line in lines))

    def test_check_on_empty_dir_is_neither_patched_nor_original(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run("check", d).returncode, 2)

    def test_apply_refuses_a_file_that_is_not_the_pinned_original(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            for rel in [l.split()[0] for l in run("list").stdout.splitlines()]:
                p = Path(src) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("not upstream")
            r = run("apply", src, out)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("refused", r.stderr)
            self.assertFalse(any(Path(out).rglob("*.js")))


if __name__ == "__main__":
    unittest.main()
