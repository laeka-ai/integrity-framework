#!/usr/bin/env python3
"""Tests for promised-fix-detect.py and promised-fix-claim-gate.py (subprocess, stdin JSON, isolated state)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "adapters" / "claude-code" / "hooks"
REC = {"id": "spend-b-20261109100000", "label": "spend-b", "words": ["plan B"], "state": "armed", "last": None}


class TestPromisedFixHooks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.env = dict(os.environ, PROMISED_FIX_DIR=str(self.d), HARNESS_GATE_STATS=str(self.d / "s.jsonl"))

    def tearDown(self):
        self.tmp.cleanup()

    def run_hook(self, name, payload):
        return subprocess.run([sys.executable, str(HOOKS / name)], input=json.dumps(payload),
                              capture_output=True, text=True, env=self.env, timeout=30)

    def test_detect_reask_prints_and_journals_first_ask_silent(self):
        (self.d / "labels.json").write_text(json.dumps({"spend-b": ["plan B"]}))
        p = {"prompt": "fix plan B spending"}
        r1 = self.run_hook("promised-fix-detect.py", p)
        self.assertEqual((r1.returncode, r1.stdout), (0, ""))
        r2 = self.run_hook("promised-fix-detect.py", p)
        self.assertEqual(r2.returncode, 0)
        self.assertIn("spend-b", r2.stdout)
        self.assertIn('"reask"', (self.d / "journal.jsonl").read_text())

    def test_detect_fail_open_on_garbage(self):
        r = subprocess.run([sys.executable, str(HOOKS / "promised-fix-detect.py")], input="not json",
                           capture_output=True, text=True, env=self.env, timeout=30)
        self.assertEqual(r.returncode, 0)

    def test_gate_blocks_unproven_claim_allows_green_and_unrelated(self):
        (self.d / "records.jsonl").write_text(json.dumps(REC) + "\n")
        say = {"tool_name": "Bash", "tool_input": {"command": "chat 'plan B is fixed'"}}
        r = self.run_hook("promised-fix-claim-gate.py", say)
        self.assertEqual(r.returncode, 2)
        self.assertIn("spend-b", r.stderr)
        other = {"tool_name": "Bash", "tool_input": {"command": "chat 'plan C is fixed'"}}
        self.assertEqual(self.run_hook("promised-fix-claim-gate.py", other).returncode, 0)
        (self.d / "records.jsonl").write_text(json.dumps(REC) + "\n" + json.dumps(dict(REC, last="GREEN", state="closed")) + "\n")
        self.assertEqual(self.run_hook("promised-fix-claim-gate.py", say).returncode, 0)

    def test_gate_ignores_file_content_of_write_and_edit(self):
        (self.d / "records.jsonl").write_text(json.dumps(REC) + "\n")
        for tool, key in (("Write", "content"), ("Edit", "new_string")):
            r = self.run_hook("promised-fix-claim-gate.py", {"tool_name": tool, "tool_input": {key: "plan B is fixed"}})
            self.assertEqual(r.returncode, 0, tool)

    def test_detect_masks_secret_in_asks(self):
        key = "sk-" + "a1B2c3D4e5F6g7H8"
        self.run_hook("promised-fix-detect.py", {"prompt": "use " + key + " for plan B"})
        asks = (self.d / "asks.jsonl").read_text()
        self.assertNotIn(key, asks)
        self.assertIn("plan B", asks)

    def test_gate_no_records_allows(self):
        r = self.run_hook("promised-fix-claim-gate.py", {"tool_input": {"command": "fixed"}})
        self.assertEqual(r.returncode, 0)

    def test_settings_example_wires_both_hooks(self):
        s = (HOOKS.parent / "settings.example.json").read_text()
        for n in ("promised-fix-detect.py", "promised-fix-claim-gate.py"):
            self.assertIn(n, s)


if __name__ == "__main__":
    unittest.main()
