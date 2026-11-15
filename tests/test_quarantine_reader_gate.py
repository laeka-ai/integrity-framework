#!/usr/bin/env python3
"""Tests for adapters/claude-code/hooks/quarantine-reader-gate.py. The hook runs
as a SUBPROCESS with its payload on stdin: no network, no model. The reader's
name is read from the layer's agent file, never guessed."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADAPTER = ROOT / "adapters" / "claude-code"
HOOK = ADAPTER / "hooks" / "quarantine-reader-gate.py"
READER = re.search(r"^name:\s*(\S+)", (ADAPTER / "agents" / "researcher.example.md").read_text(encoding="utf-8"),
                   re.M).group(1)
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")
BLOCKED = "BLOCKED (quarantine-reader gate)"


def call(tool, agent_type=None, agent_id=None):
    """A PreToolUse payload: a sub-agent call carries agent_id AND agent_type,
    the main thread never carries agent_id."""
    p = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": tool,
         "tool_input": {"command": "true", "file_path": "/tmp/x"}}
    if agent_type:
        p["agent_type"] = agent_type
    if agent_id:
        p["agent_id"] = agent_id
    return p


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.stats = self.d / "stats.jsonl"
        # strict stdin, as under an operator's UTF-8 locale: the C locale of a
        # bare env decodes anything and would hide a crash on undecodable bytes
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.d),
                    "HARNESS_STATE_DIR": str(self.d / "state"), "HARNESS_GATE_STATS": str(self.stats),
                    "PYTHONIOENCODING": "utf-8:strict"}

    def tearDown(self):
        self.tmp.cleanup()

    def run_hook(self, stdin, hook=HOOK, **env):
        if not isinstance(stdin, (str, bytes)):
            stdin = json.dumps(stdin)
        if isinstance(stdin, str):
            stdin = stdin.encode()
        self.stats.unlink(missing_ok=True)   # one run, one journal line
        return subprocess.run([sys.executable, str(hook)], input=stdin, capture_output=True,
                              timeout=30, env=dict(self.env, **env))

    def journal(self):
        rows = [json.loads(l) for l in self.stats.read_text().splitlines()] if self.stats.exists() else []
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["hook"], "quarantine-reader")
        return rows[0]["result"]

    def assertBlocked(self, r):
        err = r.stderr.decode()
        self.assertEqual(r.returncode, 2, err)
        self.assertTrue(err.startswith(BLOCKED), err)   # a missing hook file also exits 2
        self.assertEqual(err.count("\n"), 1, err)       # a one-line reason
        self.assertEqual(self.journal(), "block")

    def assertPassed(self, r, result):
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr, b"")
        self.assertEqual(self.journal(), result)

    def test_reader_write_tools_are_refused(self):
        for tool in WRITE_TOOLS:
            with self.subTest(tool=tool):
                r = self.run_hook(call(tool, READER, "a1"))
                self.assertBlocked(r)
                self.assertIn(tool, r.stderr.decode())

    def test_reader_read_tools_pass(self):
        for tool in ("Read", "Grep", "WebFetch", "WebSearch"):
            with self.subTest(tool=tool):
                self.assertPassed(self.run_hook(call(tool, READER, "a1")), "pass")

    def test_reader_call_without_a_tool_name_is_refused(self):
        self.assertBlocked(self.run_hook({"agent_id": "a1", "agent_type": READER}))

    def test_parent_bash_passes(self):
        self.assertPassed(self.run_hook(call("Bash")), "skip-not-reader")

    def test_other_subagent_write_passes(self):
        self.assertPassed(self.run_hook(call("Write", "general-purpose", "a2")), "skip-not-reader")

    def test_main_thread_of_an_agent_session_passes(self):
        # `--agent <reader>`: agent_type without agent_id is the main thread, not a sub-agent
        self.assertPassed(self.run_hook(call("Bash", READER)), "skip-not-reader")

    def test_unreadable_payload_with_the_reader_type_is_refused(self):
        whole = json.dumps(call("Bash", READER, "a1"))
        for bad in (whole[:-9], "[%s]" % whole, b"\xff" + whole.encode(), "[" * 100000 + whole):
            with self.subTest(bad=bad[:12]):
                self.assertBlocked(self.run_hook(bad))

    def test_unreadable_payload_without_agent_field_fails_open(self):
        for bad in ("not json", "", "[]", json.dumps(call("Bash"))[:-9],
                    json.dumps(call("Write", "general-purpose", "a2"))[:-9]):
            with self.subTest(bad=bad[:12]):
                self.assertPassed(self.run_hook(bad), "fail-open")

    def test_reader_name_can_be_set_for_a_deployment(self):
        self.assertBlocked(self.run_hook(call("Write", "chercheur", "a1"), QUARANTINE_READER="chercheur"))
        self.assertPassed(self.run_hook(call("Write", READER, "a1"), QUARANTINE_READER="chercheur"),
                          "skip-not-reader")

    def test_reader_name_matches_whatever_its_case_or_padding(self):
        for name in (READER.upper(), READER.title(), " %s " % READER, "\t%s\n" % READER.upper()):
            with self.subTest(name=name):
                self.assertBlocked(self.run_hook(call("Write", name, "a1")))
                # same answer when the payload is cut short
                self.assertBlocked(self.run_hook(json.dumps(call("Bash", name, "a1"))[:-9]))
        self.assertBlocked(self.run_hook(call("Bash", "CHERCHEUR", "a1"), QUARANTINE_READER=" Chercheur "))
        # a longer name that merely contains the reader's is another agent
        self.assertPassed(self.run_hook(call("Write", READER + "-notes", "a1")), "skip-not-reader")

    def test_refuses_without_the_journal_helper(self):
        # fail-closed path: the verdict does not depend on core/common/_hook.py
        alone = Path(shutil.copy(HOOK, self.d))
        r = self.run_hook(call("Bash", READER, "a1"), hook=alone)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertTrue(r.stderr.decode().startswith(BLOCKED), r.stderr)


if __name__ == "__main__":
    unittest.main()
