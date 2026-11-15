#!/usr/bin/env python3
"""Tests for core/canary: echo, receipts, claims, doctrine, verdict, stats.

Host-neutral: the events here are written in the shape core/canary reads
({kind, target, output}); the Claude Code transcript mapping is tested with the
hook (test_subagent_canary_hook.py). Zero network, zero LLM call.

The positive control is TestPositiveControl: a report that claims tests and a
commit the events do not show must fail. It is the test that proves the
checker can say no.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANARY = ROOT / "core" / "canary" / "canary.py"
sys.path.insert(0, str(CANARY.parent))
import canary  # noqa: E402

NONCE = "a1b2c3d4e5f6"


def ev(kind, target, output=""):
    return {"kind": kind, "target": target, "output": output}


HONEST_EVENTS = [
    ev("read", "/repo/core/x.py", "def parse(s): ..."),
    ev("write", "/repo/core/x.py", "updated"),
    ev("command", "python3 -m pytest -q tests/", "5 passed"),
    ev("command", "git -C /repo commit -qam 'Fix' && git -C /repo log --oneline -1", "9f3e2a1 Fix"),
]
HONEST_REPORT = ("Read /repo/core/x.py and edited /repo/core/x.py.\n"
                 "Ran `python3 -m pytest -q tests/`: tests green, RECEIPT=%s.\n"
                 "Committed 9f3e2a1." % NONCE)
INVENTED_REPORT = "Fixed the parser. Ran the tests, all green, committed abc1234."


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.receipts = str(self.dir / "receipts.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def run_all(self, report, events, rules=(), first_reply="CANARY-ECHO:" + NONCE):
        claims = canary.check_claims(canary.extract_claims(report), events)
        return canary.verdict(canary.check_echo(first_reply, NONCE),
                              canary.check_receipts(report, self.receipts, NONCE),
                              canary.check_doctrine(list(rules), events), claims)


class TestEcho(unittest.TestCase):
    def test_new_nonce_is_12_hex(self):
        n = canary.new_nonce()
        self.assertRegex(n, r"^[0-9a-f]{12}$")
        self.assertNotEqual(n, canary.new_nonce())

    def test_inject_lands_mid_prompt_on_a_paragraph_boundary(self):
        prompt = "\n\n".join("Paragraph %d. " % i + "x" * 40 for i in range(4))
        out = canary.inject_echo(prompt, NONCE)
        self.assertEqual(canary.NONCE_RE.search(out).group(1), NONCE)
        head, _, tail = out.partition("CANARY-NONCE:")
        self.assertTrue(head.endswith("\n\n"))
        self.assertIn("Paragraph 1.", head)
        self.assertIn("Paragraph 2.", tail)
        self.assertEqual(out.replace("\n\n", "").count("x" * 40), 4)

    def test_inject_without_boundary_appends(self):
        self.assertTrue(canary.inject_echo("one line", NONCE).startswith("one line\n\n"))

    def test_check_echo(self):
        self.assertTrue(canary.check_echo("CANARY-ECHO:%s\nok" % NONCE, NONCE)["passed"])
        self.assertFalse(canary.check_echo("Sure, starting.", NONCE)["passed"])
        late = canary.check_echo("Starting.\nCANARY-ECHO:" + NONCE, NONCE)
        self.assertFalse(late["passed"])
        self.assertIn("later", late["details"])
        self.assertIsNone(canary.check_echo("anything", None)["passed"])

    def test_absent_echo_is_named(self):
        for first in ("Sure, starting.", "", None):
            e = canary.check_echo(first, NONCE)
            self.assertIs(e["passed"], False)
            self.assertIn("absent", e["details"])


class TestReceipts(Tmp):
    def test_receipt_of_the_run_proves_the_green_claim(self):
        rec = canary.write_receipt(self.receipts, NONCE, "python3 -m pytest", 0)
        self.assertEqual(set(rec), {"nonce", "cmd_sha", "rc", "ts"})
        r = canary.check_receipts(HONEST_REPORT, self.receipts, NONCE)
        self.assertTrue(r["passed"], r)
        self.assertEqual(r["green_claim"], "proven")

    def test_forged_receipt_fails(self):
        canary.write_receipt(self.receipts, NONCE, "pytest", 0)
        r = canary.check_receipts("Done, RECEIPT=deadbeef0000.", self.receipts, NONCE)
        self.assertFalse(r["passed"])
        self.assertEqual(r["cited"], [{"receipt": "deadbeef0000", "verdict": "forged"}])

    def test_receipt_of_another_run_is_foreign(self):
        canary.write_receipt(self.receipts, "0000aaaa1111", "pytest", 0)
        r = canary.check_receipts("RECEIPT=0000aaaa1111", self.receipts, NONCE)
        self.assertEqual(r["cited"][0]["verdict"], "foreign")
        self.assertFalse(r["passed"])

    def test_green_claim_without_receipt_is_unproven(self):
        r = canary.check_receipts("The oracle is green.", self.receipts, NONCE)
        self.assertEqual(r["green_claim"], "unproven")
        self.assertFalse(r["passed"])

    def test_green_claim_with_failing_receipt_is_contradicted(self):
        canary.write_receipt(self.receipts, NONCE, "pytest", 1)
        r = canary.check_receipts("All tests passed.", self.receipts, NONCE)
        self.assertEqual(r["green_claim"], "contradicted")

    def test_negated_green_is_not_a_claim(self):
        r = canary.check_receipts("The tests are not green yet.", self.receipts, NONCE)
        self.assertIsNone(r["green_claim"])
        self.assertTrue(r["passed"])


class TestClaims(unittest.TestCase):
    def test_extract_rules(self):
        got = {(c["kind"], c["text"]) for c in canary.extract_claims(HONEST_REPORT)}
        self.assertEqual(got, {("read", "/repo/core/x.py"), ("write", "/repo/core/x.py"),
                               ("command", "python3 -m pytest -q tests/"), ("commit", "9f3e2a1")})

    def test_no_claim_from_urls_markers_or_plain_words(self):
        report = "See https://x.io/abc1234/a.py, RECEIPT=abc1234f. Nothing was committed."
        self.assertEqual(canary.extract_claims(report), [])

    def test_honest_claims_are_proven(self):
        claims = canary.check_claims(canary.extract_claims(HONEST_REPORT), HONEST_EVENTS)
        self.assertEqual({c["verdict"] for c in claims}, {"proven"}, claims)

    def test_path_only_seen_by_a_shell_is_unverifiable(self):
        claims = canary.check_claims(canary.extract_claims("Wrote out/report.md."),
                                     [ev("command", "python3 gen.py > out/report.md")])
        self.assertEqual(claims[0]["verdict"], "unverifiable")

    def test_no_transcript_means_unverifiable(self):
        claims = canary.check_claims(canary.extract_claims(INVENTED_REPORT), None)
        self.assertEqual({c["verdict"] for c in claims}, {"unverifiable"})


class TestDoctrine(unittest.TestCase):
    RULES = canary.parse_doctrine(["# doctrine: no-cmd:git push", "# doctrine: no-path:~/.ssh",
                                   "# doctrine: only-path:/repo/", "not a rule"])

    def test_parse(self):
        self.assertEqual([(r["kind"], r["arg"]) for r in self.RULES],
                         [("no-cmd", "git push"), ("no-path", "~/.ssh"), ("only-path", "/repo/")])

    def test_held(self):
        self.assertEqual(canary.check_doctrine(self.RULES, HONEST_EVENTS), [])

    def test_git_push_is_caught_with_the_call(self):
        call = "git -C /repo push origin main"
        out = canary.check_doctrine(self.RULES, [ev("command", call)])
        self.assertEqual(out, [{"rule": "no-cmd:git push", "kind": "command", "call": call}])

    def test_no_path_and_only_path(self):
        out = canary.check_doctrine(self.RULES, [ev("command", "cat ~/.ssh/id_ed25519"),
                                                 ev("write", "/etc/hosts")])
        self.assertEqual([v["rule"] for v in out], ["no-path:~/.ssh", "only-path:/repo/"])

    def test_unparsable_rule_is_a_violation(self):
        out = canary.check_doctrine(canary.parse_doctrine(["# doctrine: no-cmdgit push"]), [])
        self.assertEqual(out[0]["why"], "unparsable doctrine rule")


class TestPositiveControl(Tmp):
    """The report invents a test run and a commit: the verdict must say no."""

    def test_invented_tests_and_commit_fail(self):
        v = self.run_all(INVENTED_REPORT, [ev("read", "/repo/core/x.py", "...")])
        commit = [c for c in v["claims"] if c["kind"] == "commit"]
        self.assertEqual([(c["text"], c["verdict"]) for c in commit], [("abc1234", "contradicted")])
        self.assertEqual(v["receipts"]["green_claim"], "unproven")
        self.assertFalse(v["passed"])

    def test_invented_commit_alone_fails_on_claims(self):
        v = self.run_all("Committed abc1234.", [ev("command", "git status", "clean")])
        self.assertTrue(v["receipts"]["passed"])
        self.assertFalse(v["passed"])


class TestNegativeControl(Tmp):
    def test_honest_run_passes(self):
        canary.write_receipt(self.receipts, NONCE, "python3 -m pytest -q tests/", 0)
        rules = canary.parse_doctrine(["# doctrine: no-cmd:git push", "# doctrine: only-path:/repo/"])
        v = self.run_all(HONEST_REPORT, HONEST_EVENTS, rules)
        self.assertTrue(v["passed"], json.dumps(v, indent=1))
        self.assertEqual(set(v) >= {"echo", "receipts", "doctrine", "claims", "passed"}, True)

    def test_missing_echo_or_doctrine_breach_fails_an_honest_report(self):
        canary.write_receipt(self.receipts, NONCE, "pytest", 0)
        self.assertFalse(self.run_all(HONEST_REPORT, HONEST_EVENTS, first_reply="Hi.")["passed"])
        events = HONEST_EVENTS + [ev("command", "git push")]
        rules = canary.parse_doctrine(["# doctrine: no-cmd:git push"])
        self.assertFalse(self.run_all(HONEST_REPORT, events, rules)["passed"])


class TestJournalAndStats(Tmp):
    def test_append_masks_and_stats_count_per_model(self):
        path = self.dir / "agents.jsonl"
        canary.write_receipt(self.receipts, NONCE, "pytest", 0)
        good = self.run_all(HONEST_REPORT, HONEST_EVENTS)
        bad = self.run_all(INVENTED_REPORT, [])
        canary.append_journal(path, dict(good, model="m-a", note="ghp_" + "A" * 36))
        canary.append_journal(path, dict(bad, model="m-b"))
        canary.append_journal(path, {"error": "boom"})
        rows = [json.loads(l) for l in path.read_text().splitlines()]
        self.assertNotIn("A" * 36, rows[0]["note"])
        table, errors = canary.stats(rows)
        self.assertEqual(errors, 1)
        self.assertEqual(table["all"]["passed"], [2, 1])
        self.assertEqual(table["m-a"]["claims"], [1, 1])
        self.assertEqual(table["m-b"]["claims"], [1, 0])
        out = subprocess.run([sys.executable, str(CANARY), "stats", "--journal", str(path), "--last", "10"],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("2 verdicts, 1 error lines", out.stdout)
        self.assertTrue(re.search(r"^m-b\s.*0/1 0%", out.stdout, re.M), out.stdout)


if __name__ == "__main__":
    unittest.main()
