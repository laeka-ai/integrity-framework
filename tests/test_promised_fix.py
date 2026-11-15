#!/usr/bin/env python3
"""Tests for core/promised_fix: detect, arm, verdict, next_pass, claim_blocked,
append_journal, stats.

Host-neutral: records and journal lines are written by hand in the shape the
core produces. Zero network, zero timer, zero process.

The positive controls are the TestClaimGate tests named test_refuses_*: each
must fail if claim_blocked always returns "" (the gate can say no).
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "core" / "promised_fix"))
import promised_fix as pf  # noqa: E402

T0 = datetime(2026, 11, 9, 14, 56, 20, tzinfo=timezone(timedelta(hours=-5)))
WORDS = ["plan B", "account B", "spend", "tokens"]
LABELS = {"spend-b": WORDS, "site": ["landing page", "site"]}


def at(hours):
    return T0 + timedelta(hours=hours)


def armed(**kw):
    return dict(pf.arm("spend-b", "probes/spend-b", 2119, T0, words=WORDS), **kw)


class TestDetect(unittest.TestCase):
    def test_second_request_is_detected_with_its_count(self):
        self.assertEqual(pf.detect(["The spend on plan B is too high."], "Still too much spend, fix it.", LABELS),
                         ("spend-b", 2))

    def test_count_includes_every_earlier_request(self):
        history = ["plan B burns", "tokens again", "unrelated", "spend!"]
        self.assertEqual(pf.detect(history, "the spend, 4th time", LABELS), ("spend-b", 4))

    def test_first_request_is_not_a_reask(self):
        self.assertIsNone(pf.detect(["the site is slow"], "The spend on plan B is too high.", LABELS))

    def test_text_without_label_words_is_not_detected(self):
        self.assertIsNone(pf.detect(["spend", "spend"], "please answer shorter", LABELS))

    def test_whole_words_only(self):
        self.assertIsNone(pf.detect(["overspending"], "spend is high", LABELS))

    def test_most_requested_label_wins(self):
        history = ["site down", "spend high", "spend again"]
        self.assertEqual(pf.detect(history, "the site and the spend", LABELS), ("spend-b", 3))


class TestArm(unittest.TestCase):
    def test_record(self):
        r = pf.arm("spend-b", "probes/spend-b", 2119, T0, words=WORDS)
        self.assertEqual(r["id"], "spend-b-20261109145620")
        self.assertEqual((r["label"], r["probe"], r["reply_to"], r["words"]), ("spend-b", "probes/spend-b", 2119, WORDS))
        self.assertEqual((r["state"], r["last"], r["final"]), ("armed", None, False))
        self.assertEqual(r["t0"], "2026-11-09T14:56:20-05:00")

    def test_passes_at_one_and_two_hours(self):
        r = armed()
        self.assertEqual(r["planned"], [1, 2])
        self.assertEqual(r["next"], at(1).isoformat())
        self.assertEqual(pf.next_pass(r, pf.INCONCLUSIVE, at(1))["next"], at(2).isoformat())

    def test_no_words_is_refused(self):
        for words in ([], None):
            with self.assertRaises(ValueError):
                pf.arm("spend-b", "probe", 1, T0, words=words)


class TestVerdict(unittest.TestCase):
    def test_three_verdicts(self):
        self.assertEqual([pf.verdict(rc) for rc in (0, 1, 3)], [pf.GREEN, pf.RED, pf.INCONCLUSIVE])

    def test_unknown_rc_is_never_green(self):
        for rc in (2, 4, 124, 127, 255, -9, None, "0", "", False, 0.0, [0]):
            self.assertEqual(pf.verdict(rc), pf.INCONCLUSIVE, repr(rc))


class TestNextPass(unittest.TestCase):
    def test_pass_one_never_closes(self):
        for v in (pf.GREEN, pf.RED):
            r = pf.next_pass(armed(), v, at(1))
            self.assertEqual((r["state"], r["last"], r["last_pass"], r["next"]), ("armed", v, 1, at(2).isoformat()))

    def test_green_or_red_at_pass_two_closes(self):
        for v in (pf.GREEN, pf.RED):
            r = pf.next_pass(pf.next_pass(armed(), pf.INCONCLUSIVE, at(1)), v, at(2))
            self.assertEqual((r["state"], r["last"], r["final"], r["next"]), ("closed", v, False, None))

    def test_inconclusive_reschedules_up_to_the_ceiling(self):
        r = pf.next_pass(armed(), pf.INCONCLUSIVE, at(1))
        for h, nxt in ((2, 4), (4, 8), (8, 24), (24, 72)):
            r = pf.next_pass(r, pf.INCONCLUSIVE, at(h))
            self.assertEqual((r["state"], r["next"]), ("armed", at(nxt).isoformat()), h)
        self.assertEqual(r["planned"], [1, 2, 3, 4, 5, 6])
        r = pf.next_pass(r, pf.INCONCLUSIVE, at(72))
        self.assertEqual((r["state"], r["last"], r["final"], r["next"]), ("closed", pf.INCONCLUSIVE, True, None))

    def test_green_after_reschedule_closes(self):
        r = pf.next_pass(pf.next_pass(armed(), pf.INCONCLUSIVE, at(2)), pf.GREEN, at(4))
        self.assertEqual((r["state"], r["last"], r["last_pass"]), ("closed", pf.GREEN, 3))

    def test_overdue_passes_collapse_into_the_latest(self):
        r = pf.next_pass(armed(), pf.INCONCLUSIVE, at(30))
        self.assertEqual((r["last_pass"], r["next"]), (5, at(72).isoformat()))
        self.assertEqual(pf.next_pass(armed(), pf.INCONCLUSIVE, at(100))["final"], True)

    def test_early_timer_within_slack_judges_its_pass(self):
        self.assertEqual(pf.next_pass(armed(), pf.GREEN, at(2) - timedelta(minutes=1))["state"], "closed")

    def test_unknown_verdict_is_inconclusive(self):
        r = pf.next_pass(armed(), "PASS", at(2))
        self.assertEqual((r["last"], r["state"]), (pf.INCONCLUSIVE, "armed"))

    def test_not_armed_is_unchanged_and_input_untouched(self):
        d = armed(state="disarmed")
        self.assertEqual(pf.next_pass(d, pf.GREEN, at(2)), d)
        a = armed()
        pf.next_pass(a, pf.INCONCLUSIVE, at(2))
        self.assertEqual((a["planned"], a["last"]), ([1, 2], None))


class TestClaimGate(unittest.TestCase):
    CLAIM = "The spend on account B is fixed."

    def test_refuses_before_green(self):
        why = pf.claim_blocked(self.CLAIM, [armed()])
        self.assertIn("spend-b is not proven (last verdict none)", why)

    def test_refuses_after_red(self):
        self.assertIn("last verdict RED", pf.claim_blocked("tokens: corrigé", [armed(last=pf.RED, state="closed")]))

    def test_refuses_when_the_latest_arming_is_not_green(self):
        old = armed(last=pf.GREEN, state="closed")
        new = dict(pf.arm("spend-b", "p", 2200, at(48), words=WORDS))
        self.assertTrue(pf.claim_blocked(self.CLAIM, [new, old]))

    def test_passes_after_green(self):
        self.assertEqual(pf.claim_blocked(self.CLAIM, [armed(last=pf.GREEN)]), "")

    def test_passes_when_the_latest_arming_is_green(self):
        old = armed()
        new = dict(pf.arm("spend-b", "p", 2200, at(48), words=WORDS), last=pf.GREEN)
        self.assertEqual(pf.claim_blocked(self.CLAIM, [new, old]), "")

    def test_fixed_outside_the_label_passes(self):
        self.assertEqual(pf.claim_blocked("The landing page is fixed.", [armed()]), "")

    def test_disarmed_passes(self):
        self.assertEqual(pf.claim_blocked(self.CLAIM, [armed(state="disarmed")]), "")

    def test_no_claim_word_passes(self):
        self.assertEqual(pf.claim_blocked("Spend on plan B: lowered the cap, measuring.", [armed()]), "")

    def test_malformed_records_are_skipped(self):
        self.assertEqual(pf.claim_blocked(self.CLAIM, [None, "x", {"label": "spend-b"}, {}]), "")


class TestJournalAndStats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sub", "journal.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def lines(self):
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_one_json_line_per_entry_secrets_masked(self):
        pf.append_journal(self.path, {"event": "arm", "id": "a", "t0": T0.isoformat()})
        pf.append_journal(self.path, {"id": "a", "verdict": pf.RED, "probe_out": "key sk-abcdefghijklmnop"})
        rows = self.lines()
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["event"], rows[1]["verdict"]), ("arm", pf.RED))
        self.assertIn("ts", rows[0])
        self.assertNotIn("sk-abcdefghijklmnop", rows[1]["probe_out"])

    def test_default_path_from_promised_fix_dir(self):
        old = os.environ.get("PROMISED_FIX_DIR")
        os.environ["PROMISED_FIX_DIR"] = self.tmp.name
        try:
            pf.append_journal(None, {"event": "arm"})
        finally:
            os.environ.pop("PROMISED_FIX_DIR") if old is None else os.environ.__setitem__("PROMISED_FIX_DIR", old)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "journal.jsonl")))

    def test_stats(self):
        for e in ({"event": "arm", "id": "a", "t0": at(0).isoformat()},
                  {"id": "a", "verdict": pf.INCONCLUSIVE, "ts": at(1).isoformat()},
                  {"id": "a", "verdict": pf.GREEN, "ts": at(2).isoformat()},
                  {"event": "arm", "id": "b", "t0": at(0).isoformat()},
                  {"id": "b", "verdict": pf.RED, "ts": at(4).isoformat()},
                  {"id": "b", "verdict": pf.GREEN, "ts": at(8).isoformat()},
                  {"event": "arm", "id": "c", "t0": at(0).isoformat()},
                  {"id": "c", "verdict": "??", "ts": at(1).isoformat()}):
            pf.append_journal(self.path, e)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("not json\n[1]\n")
        self.assertEqual(pf.stats(self.path), {"armings": 3, pf.GREEN: 2, pf.RED: 1, pf.INCONCLUSIVE: 2,
                                               "median_hours_to_verdict": 3.0})

    def test_stats_of_a_missing_journal(self):
        self.assertEqual(pf.stats(self.path), {"armings": 0, pf.GREEN: 0, pf.RED: 0, pf.INCONCLUSIVE: 0,
                                               "median_hours_to_verdict": None})


if __name__ == "__main__":
    unittest.main()
