"""Tests for hooks/set-e-inert-gate.py: the hook runs as a subprocess, gate-stats isolated in a tempdir."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "adapters" / "claude-code" / "hooks" / "set-e-inert-gate.py"


def run(cmd, **env_extra):
    with tempfile.TemporaryDirectory() as state:
        env = dict(os.environ, HARNESS_STATE_DIR=state, **env_extra)
        env.pop("HARNESS_SET_E_INERT_GATE_DISABLE", None)
        env.update(env_extra)
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, env=env, timeout=30)


class TestSetEInertGate(unittest.TestCase):
    def test_blocks_set_e_first(self):
        for cmd in ("set -e; false; echo x", "set -euo pipefail\nls", "set -o errexit && ls", "set -Ee; ls"):
            r = run(cmd)
            self.assertEqual(r.returncode, 2, cmd)
            self.assertIn("bash -euo pipefail -c", r.stderr)

    def test_passes_the_rest(self):
        for cmd in ("echo hi", "set -u; ls", "ls && set -e", "bash -ec 'false; echo x'",
                    "bash <<'EOF'\nset -e\nfalse\nEOF", "echo \"it's\"; ls"):
            self.assertEqual(run(cmd).returncode, 0, cmd)

    def test_unparsable_fails_open(self):
        self.assertEqual(run("echo 'unclosed").returncode, 0)

    def test_kill_switch(self):
        self.assertEqual(run("set -e; ls", HARNESS_SET_E_INERT_GATE_DISABLE="1").returncode, 0)


if __name__ == "__main__":
    unittest.main()
