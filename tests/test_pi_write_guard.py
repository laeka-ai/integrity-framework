import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parent.parent / "adapters" / "pi" / "hooks" / "write-guard.py"


def run(env, payload):
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    e = {"PATH": os.environ["PATH"], **env}
    return subprocess.run([sys.executable, "-I", str(GUARD)], input=raw,
                          capture_output=True, text=True, env=e, timeout=20)


class TestPiWriteGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name).resolve()
        (t / "workshop").mkdir()
        (t / "gates").mkdir()
        (t / "gates" / "gate.py").write_text("x")
        self.t = t
        self.env = {"PI_WORKSHOP": str(t / "workshop"), "PI_JOURNAL": str(t / "journal")}

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, path, key="path"):
        return run(self.env, {"tool_name": "write", "tool_args": {key: str(path)}})

    def test_inside_workshop_allowed(self):
        self.assertEqual(self.call(self.t / "workshop" / "a.css").returncode, 0)

    def test_outside_blocked(self):
        r = self.call(self.t / "gates" / "gate.py")
        self.assertEqual(r.returncode, 2)
        self.assertIn("outside the workshop", r.stderr)

    def test_symlink_into_gates_blocked(self):
        link = self.t / "workshop" / "x.css"
        link.symlink_to(self.t / "gates" / "gate.py")
        r = self.call(link)
        self.assertEqual(r.returncode, 2)
        self.assertIn("actually points to", r.stderr)

    def test_unreadable_context_fails_closed(self):
        self.assertEqual(run(self.env, "not json").returncode, 2)
        self.assertEqual(run(self.env, {"tool_args": {}}).returncode, 2)

    def test_truncated_context_fails_closed(self):
        self.assertEqual(run(self.env, {"_pi_hooks_truncated": True}).returncode, 2)
        args = {"_pi_hooks_tool_args_truncated": True, "_pi_hooks_tool_args_dropped": ["path"]}
        self.assertEqual(run(self.env, {"tool_args": args}).returncode, 2)


if __name__ == "__main__":
    unittest.main()
