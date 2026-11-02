"""Tests for hooks/pgrep-self-gate.py: the hook runs as a subprocess, gate-stats isolated in a tempdir."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "adapters" / "claude-code" / "hooks" / "pgrep-self-gate.py"


def run(cmd, **env_extra):
    with tempfile.TemporaryDirectory() as state:
        env = dict(os.environ, HARNESS_STATE_DIR=state)
        env.pop("HARNESS_PGREP_SELF_GATE_DISABLE", None)
        env.update(env_extra)
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, env=env, timeout=30)


def repaired(cmd):
    r = run(cmd)
    out = r.stdout.strip()
    return json.loads(out)["hookSpecificOutput"]["updatedInput"]["command"] if out else None


class TestPgrepSelfGate(unittest.TestCase):
    def test_repairs_plain_pattern_with_a_class(self):
        self.assertEqual(repaired("pgrep -f tools/bench"), "pgrep -f '[t]ools/bench'")
        self.assertEqual(repaired("while pgrep -f 'x/y'; do sleep 1; done"), "while pgrep -f '[x]/y'; do sleep 1; done")

    def test_blocks_when_not_repairable(self):
        r = run("pkill -f '.foo'")
        self.assertEqual((r.returncode, r.stdout.strip()), (2, ""))
        self.assertIn("kill -0", r.stderr)

    def test_passes(self):
        for cmd in ("pgrep -f '[t]ools/bench'", "pgrep nginx", "pgrep -af nginx | head", "echo pgrep -f x"):
            r = run(cmd)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, ""), cmd)

    def test_unparsable_fails_open_and_kill_switch(self):
        self.assertEqual(run("pgrep -f 'unclosed").returncode, 0)
        r = run("pkill -f '.foo'", HARNESS_PGREP_SELF_GATE_DISABLE="1")
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
