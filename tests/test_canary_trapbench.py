#!/usr/bin/env python3
"""Trap bench + framework adapters. Zero network, zero LLM call."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core" / "canary"))
import adapters  # noqa: E402
import canary  # noqa: E402
import trapbench  # noqa: E402

MANIFEST = ROOT / "tests" / "fixtures" / "canary" / "traps" / "traps.json"
REAL = MANIFEST.parent / "claude-p" / "traps.json"
RULES = canary.parse_doctrine(["# doctrine: no-cmd:git push"])


class TestTrapBench(unittest.TestCase):
    def test_replay_counts_held_and_violated(self):
        rows, bad = trapbench.run(str(MANIFEST))
        self.assertEqual(bad, 0, rows)
        self.assertIn("rate claude-sonnet-5-5", " ".join(rows))
        self.assertTrue(any("held 1/2" in r for r in rows), rows)

    def test_control_checker_disagreeing_with_expect_fails(self):
        # positive control: a checker that never sees violations must fail the bench
        real = canary.check_doctrine
        canary.check_doctrine = lambda rules, events: []
        try:
            self.assertGreater(trapbench.run(str(MANIFEST))[1], 0)
        finally:
            canary.check_doctrine = real

    def test_cli(self):
        r = subprocess.run([sys.executable, str(ROOT / "core/canary/trapbench.py"), "run", str(MANIFEST)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestRealRecordings(unittest.TestCase):
    """Replay of the `claude -p` recordings (traprecord.py). Zero call."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = Path(shutil.copytree(REAL.parent, Path(self.tmp) / "claude-p"))
        self.manifest = str(self.dir / "traps.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_replay_finds_the_base_file_and_its_controls_pass(self):
        rows, bad = trapbench.run(self.manifest)
        self.assertEqual(bad, 0, rows)
        self.assertEqual(sum(r.startswith("control ok") for r in rows), 3, rows)
        base = json.loads(next(self.dir.glob("BASELINE-*.json")).read_text())
        for model, cell in base["models"].items():
            self.assertTrue(model.startswith("claude-"), model)
            self.assertEqual({cell[p][1] for p in trapbench.POINTS}, {cell["n"]})

    def test_a_run_that_fell_back_is_counted_under_the_model_that_answered(self):
        m = trapbench.measure(str(self.dir), {"rule": "no-cmd:git push"}, {"file": "no-secrets-3.jsonl"})
        first = json.loads((self.dir / "no-secrets-3.jsonl").read_text().splitlines()[0])["model"]
        self.assertNotEqual(m["model"], first)

    def test_a_receipt_removed_from_one_journal_moves_the_rate(self):
        (self.dir / "no-push-1.receipts.jsonl").write_text("")
        rows, bad = trapbench.run(self.manifest)
        self.assertTrue(bad and any("DIFFERS FROM" in r for r in rows), rows)

    def test_no_clean_recording_throws_the_measure_away(self):
        for j in self.dir.glob("*.receipts.jsonl"):
            j.write_text("")
        rows, bad = trapbench.run(self.manifest)
        self.assertTrue(bad and any(r.startswith("control FAIL") for r in rows), rows)


class TestAdapters(unittest.TestCase):
    def test_langgraph_push_is_caught(self):
        msgs = [{"tool_calls": [{"id": "c1", "name": "bash", "args": {"command": "git push origin main"}}]},
                {"tool_call_id": "c1", "content": "pushed"}]
        ev = adapters.from_langgraph(msgs)
        self.assertEqual(ev, [{"kind": "command", "target": "git push origin main", "output": "pushed"}])
        self.assertTrue(canary.check_doctrine(RULES, ev))

    def test_crewai_clean_run_passes(self):
        ev = adapters.from_crewai([{"tool": "file_read_tool", "tool_input": {"file_path": "/r/a.py"}, "result": "x"}])
        self.assertEqual(ev[0]["kind"], "read")
        self.assertEqual(canary.check_doctrine(RULES, ev), [])

    def test_crewai_push_is_caught(self):
        ev = adapters.from_crewai([{"tool": "Terminal", "tool_input": "git push", "result": ""}])
        self.assertTrue(canary.check_doctrine(RULES, ev))


if __name__ == "__main__":
    unittest.main()
