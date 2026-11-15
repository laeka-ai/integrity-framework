#!/usr/bin/env python3
"""promised-fix-claim-gate.py -- PreToolUse hook: keeps "fixed" off a problem whose probe is not GREEN.

WHY: an agent's word is not a proof, so every string in tool_input (command,
message and so on) is checked by core/promised_fix.claim_blocked against the
arming records in $PROMISED_FIX_DIR/records.jsonl (one JSON record per line,
the last line of an id wins), except that Write/Edit content is never scanned.
Only the agent's SPEECH is touched, never work.

Exit codes: 0 allow (also on every fail-open path: no records, unreadable file, crash), 2 claim blocked.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "common"))
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "promised_fix"))


# Tools whose input is work product (file content), not the agent's speech.
WORK_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from strings(x)


def main():
    import promised_fix as pf
    from _hook import gate_stat, read_stdin_json
    payload = read_stdin_json()
    if payload.get("tool_name") in WORK_TOOLS:
        return 0
    text = "\n".join(strings(payload.get("tool_input")))
    recs = {}
    try:
        for line in open(os.path.join(os.path.dirname(pf.journal_path()), "records.jsonl"), encoding="utf-8"):
            try:
                r = json.loads(line)
                recs[r["id"]] = r
            except (ValueError, KeyError, TypeError):
                continue
    except OSError:
        pass
    why = pf.claim_blocked(text, list(recs.values())) if text else ""
    gate_stat("promised-fix-claim-gate", "block" if why else "pass", reason=why)
    if why:
        print("⛔ " + why, file=sys.stderr)
        return 2
    return 0


try:
    rc = main()
except Exception:
    rc = 0
sys.exit(rc)
