#!/usr/bin/env python3
"""promised_fix.py -- the Promised-Fix Verifier core: a fix asked for twice is
proven over time by a measured probe, never by the agent's word.

WHY: an agent that answers "fixed" two minutes after a request has proven the
local symptom (a green bench, a commit), not the goal, which often needs hours
of measurement. When a human asks for the same fix a second time, the layer
arms a probe, runs it at +1 h and +2 h, and keeps the word "fixed" off that
problem until the probe says GREEN.

  detect(history, text, labels)   is this human message a re-ask? -> (label, count) or None
  arm(label, probe, reply_to, now, words=...)   a new arming record, passes at +1 h and +2 h
  verdict(rc)                     probe exit code -> GREEN (0), RED (1), INCONCLUSIVE (anything else)
  next_pass(record, verdict, now) the record after a pass: closed, rescheduled, or inconclusive final
  claim_blocked(text, records)    why a "fixed" claim must not be said, or "" if it may
  append_journal(path, entry)     one JSON line
  stats(journal)                  armings, GREEN, RED, INCONCLUSIVE, median hours to a verdict

Host-neutral and pure except append_journal and stats: no clock read, no
timer, no process. The adapter runs the probe, schedules the passes at
record["next"], stores the records and speaks the verdicts.

A probe is a command the adapter runs with `--t0 <record t0>`; its exit code is
the verdict. Unknown codes are INCONCLUSIVE: nothing is GREEN by default.

Environment:
  PROMISED_FIX_DIR  state directory; the default journal is $PROMISED_FIX_DIR/journal.jsonl
                    (else $HARNESS_STATE_DIR/promised-fix/journal.jsonl)
"""
import json
import os
import re
import statistics
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, "common"))
from _hook import STATE_DIR, mask_secrets  # noqa: E402

GREEN, RED, INCONCLUSIVE = "GREEN", "RED", "INCONCLUSIVE"
PASSES_H = (1, 2, 4, 8, 24, 72)    # pass k runs at t0 + PASSES_H[k - 1] hours; 72 h is the ceiling
SLACK = timedelta(minutes=2)       # a timer firing a little early still judges its own pass
CLAIM = re.compile(r"corrigé|réglé|résolu|fixed", re.I)


def journal_path():
    d = os.environ.get("PROMISED_FIX_DIR") or os.path.join(STATE_DIR, "promised-fix")
    return os.path.join(d, "journal.jsonl")


def _says(text, words):
    return any(re.search(r"(?<!\w)%s(?!\w)" % re.escape(w), text, re.I) for w in words or ())


def detect(history, text, labels):
    """`labels` maps a label to its words ({"spend-b": ["plan B", "spend"]}).
    `history` holds the human's earlier messages (strings), oldest first; the
    caller picks the window (the Pod uses 14 days). Returns (label, count) when
    `text` names a label that at least one earlier message named too, `count`
    counting `text`: count >= 2 means arming is recommended. None otherwise.
    Two labels named: the one asked for most often wins."""
    best = None
    for label, words in labels.items():
        if not _says(text, words):
            continue
        count = 1 + sum(1 for h in history if _says(h, words))
        if count >= 2 and (best is None or count > best[1]):
            best = (label, count)
    return best


def _due(record, k):
    return datetime.fromisoformat(record["t0"]) + timedelta(hours=PASSES_H[k - 1])


def arm(label, probe, reply_to, now, *, words):
    """A new arming record; `now` is an aware datetime. `words` are the label's
    words, kept in the record because claim_blocked reads only records."""
    if not label or not words:
        raise ValueError("arm: a label and at least one word are required (no word = an open gate)")
    t0 = now.isoformat(timespec="seconds")
    r = {"id": "%s-%s" % (label, now.strftime("%Y%m%d%H%M%S")), "label": label, "words": list(words),
         "probe": probe, "reply_to": reply_to, "t0": t0, "planned": [1, 2], "state": "armed", "last": None,
         "final": False}
    r["next"] = _due(r, 1).isoformat(timespec="seconds")
    return r


def verdict(rc):
    if type(rc) is not int:     # False == 0 and 0.0 == 0: only a real exit code can be GREEN
        return INCONCLUSIVE
    return {0: GREEN, 1: RED}.get(rc, INCONCLUSIVE)


def next_pass(record, verdict, now):
    """The record after the pass due at `now` (the latest pass whose time has
    come, so overdue passes collapse into one). Pass 1 never closes: pass 2 is
    already planned. From pass 2 on, GREEN or RED closes; INCONCLUSIVE plans the
    next pass (4, 8, 24 h) up to the 72 h ceiling, where it closes as
    inconclusive final. `record["next"]` is the time to schedule, or None.
    A record that is not armed comes back unchanged."""
    r = dict(record, planned=list(record.get("planned") or []))
    if r.get("state") != "armed":
        return r
    if verdict not in (GREEN, RED):
        verdict = INCONCLUSIVE
    k = max([1] + [j for j in range(1, len(PASSES_H) + 1) if _due(r, j) <= now + SLACK])
    r.update(last=verdict, last_pass=k, next=None)
    if verdict == INCONCLUSIVE and 2 <= k < len(PASSES_H):
        r["planned"].append(k + 1)
        r["next"] = _due(r, k + 1).isoformat(timespec="seconds")
    elif k >= 2:
        r.update(state="closed", final=verdict == INCONCLUSIVE)
    else:
        r["next"] = _due(r, 2).isoformat(timespec="seconds")
    return r


def claim_blocked(text, records):
    """The reason `text` must not be said, or "" if it may. It is blocked when
    it says fixed|corrigé|réglé|résolu and names a word of a label whose LATEST
    arming (ids end in their arming time) is neither GREEN nor disarmed."""
    if not CLAIM.search(text):
        return ""
    latest = {}
    for r in records:
        if isinstance(r, dict) and r.get("label") and r.get("id"):
            if r["label"] not in latest or str(r["id"]) > str(latest[r["label"]]["id"]):
                latest[r["label"]] = r
    for label, r in latest.items():
        if r.get("state") != "disarmed" and r.get("last") != GREEN and _says(text, r.get("words")):
            return ("Promised-Fix: %s is not proven (last verdict %s); say what was done, not that it is fixed"
                    % (label, r.get("last") or "none"))
    return ""


def append_journal(path, entry):
    """Append one JSON line (default path: journal_path()); strings are
    scrubbed here, in the writer (ARCHITECTURE 2.2)."""
    path = path or journal_path()
    rec = {"ts": datetime.now().astimezone().isoformat(timespec="seconds")}
    rec.update({k: mask_secrets(v, 500) if isinstance(v, str) else v for k, v in entry.items()})
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def stats(journal):
    """Over a journal file: armings (lines with "event": "arm" and "t0"),
    GREEN, RED, INCONCLUSIVE (pass lines, by "verdict"), and the median hours
    from an arming's t0 to its first GREEN or RED pass ("ts"). Unreadable
    lines are skipped; a missing file counts zero."""
    rows = []
    try:
        with open(journal, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if isinstance(d, dict):
                    rows.append(d)
    except OSError:
        pass
    out = {"armings": 0, GREEN: 0, RED: 0, INCONCLUSIVE: 0, "median_hours_to_verdict": None}
    t0, first = {}, {}
    for d in rows:
        try:
            if d.get("event") == "arm":
                t0[d["id"]] = datetime.fromisoformat(d["t0"])
                out["armings"] += 1
            elif "verdict" in d:
                v = d["verdict"] if d["verdict"] in (GREEN, RED) else INCONCLUSIVE
                out[v] += 1
                if v != INCONCLUSIVE and d.get("id") not in first:
                    first[d.get("id")] = datetime.fromisoformat(d["ts"])
        except (KeyError, TypeError, ValueError):
            continue
    delays = []
    for i in first.keys() & t0.keys():
        try:
            delays.append((first[i] - t0[i]).total_seconds() / 3600)
        except TypeError:   # one naive and one aware timestamp
            continue
    if delays:
        out["median_hours_to_verdict"] = round(statistics.median(delays), 2)
    return out
