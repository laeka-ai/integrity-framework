#!/usr/bin/env python3
"""Tests for adapters/claude-code/hooks/quarantine-check.py and the WebFetch /
WebSearch mapping of _transcript.tool_events. The hook runs as a SUBPROCESS with
its payload on stdin; transcripts are written to a temporary directory."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "adapters" / "claude-code" / "hooks" / "quarantine-check.py"
sys.path.insert(0, str(HOOK.parent))
from _transcript import tool_events  # noqa: E402

PAGE = "The committee found that the retention rate improved by twelve percent in 2025."
URL = "https://example.org/study"


def _use(i, name, inp):
    return {"message": {"role": "assistant", "content": [{"type": "tool_use", "id": i, "name": name, "input": inp}]}}


def _res(i, text):
    return {"message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": i, "content": text}]}}


FETCH = [_use("f1", "WebFetch", {"url": URL, "prompt": "summarise"}), _res("f1", PAGE)]


class TestToolEvents(unittest.TestCase):
    def test_web_tools_map_to_reader_kinds(self):
        evs = FETCH + [_use("s1", "WebSearch", {"query": "retention study"}), _res("s1", "1. " + URL)]
        got = tool_events(evs)
        self.assertEqual([(e["kind"], e["target"]) for e in got],
                         [("fetch", URL), ("search", "retention study")])
        self.assertEqual(got[0]["output"], PAGE)


class HookCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.journal = self.d / "q.jsonl"
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.d),
                    "HARNESS_STATE_DIR": str(self.d / "state"), "HARNESS_GATE_STATS": str(self.d / "stats.jsonl"),
                    "QUARANTINE_JOURNAL": str(self.journal)}

    def tearDown(self):
        self.tmp.cleanup()

    def run_hook(self, report, events=FETCH, event="SubagentStop", **env):
        tp = self.d / "agent.jsonl"
        tp.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        p = {"hook_event_name": event, "session_id": "s1", "agent_transcript_path": str(tp),
             "transcript_path": str(self.d / "parent.jsonl")}
        if event == "SubagentHandback":
            p["tool_input"] = {"message": report}
        else:
            p["last_assistant_message"] = report
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(p), capture_output=True,
                              text=True, timeout=30, env=dict(self.env, **env))

    def rows(self):
        return [json.loads(l) for l in self.journal.read_text().splitlines()] if self.journal.exists() else []

    def test_grounded_quote_passes_and_journals(self):
        r = self.run_hook('"%s" (%s)' % (PAGE[:60], URL))
        self.assertEqual(r.returncode, 0)
        self.assertTrue(self.rows()[0]["passed"])

    def test_invented_quote_diagnostic_exit0(self):
        r = self.run_hook('The page says "the committee recommended shutting down every office now".')
        self.assertEqual(r.returncode, 0)
        self.assertFalse(self.rows()[0]["passed"])

    def test_block_mode_exit2_names_the_quote(self):
        r = self.run_hook('The page says "the committee recommended shutting down every office now".',
                          QUARANTINE_MODE="block")
        self.assertEqual(r.returncode, 2)
        self.assertIn("recommended shutting down", r.stderr)

    def test_block_mode_keeps_blocking_on_retry(self):
        # the host caps consecutive stop-hook blocks itself; the hook must not self-exempt
        tp = self.d / "a.jsonl"
        tp.write_text(json.dumps(FETCH[0]) + "\n")
        p = {"hook_event_name": "SubagentStop", "agent_transcript_path": str(tp), "stop_hook_active": True,
             "last_assistant_message": 'It says "an entirely invented sentence from nowhere".'}
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(p), capture_output=True, text=True,
                           env=dict(self.env, QUARANTINE_MODE="block"))
        self.assertEqual(r.returncode, 2)

    def test_handback_reads_tool_input_message(self):
        r = self.run_hook('"a made up sentence that no page ever said"', event="SubagentHandback",
                          QUARANTINE_MODE="block")
        self.assertEqual(r.returncode, 2)

    def test_parent_copy_does_not_ground(self):
        # only the sub-agent transcript counts: no agent_transcript_path -> skipped, exit 0
        p = {"hook_event_name": "SubagentStop", "transcript_path": str(self.d / "x"),
             "last_assistant_message": '"a made up sentence that no page ever said"'}
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(p), capture_output=True, text=True,
                           env=dict(self.env, QUARANTINE_MODE="block"))
        self.assertEqual(r.returncode, 0)

    def test_link_from_the_brief_is_accepted(self):
        # the first user entry is the brief: its URLs are trusted for links
        brief = {"message": {"role": "user", "content": [{"type": "text", "text": "Read https://example.org/brief"}]}}
        report = "Source: https://example.org/brief"
        r = self.run_hook(report, events=[brief] + FETCH, QUARANTINE_MODE="block")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(self.rows()[0]["passed"])
        r = self.run_hook(report, events=FETCH, QUARANTINE_MODE="block")  # no brief: link unseen
        self.assertEqual(r.returncode, 2)
        self.assertIn("link unseen", r.stderr)

    def test_garbage_stdin_fails_open(self):
        r = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True, env=self.env)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
