#!/usr/bin/env python3
"""promised-fix-detect.py -- UserPromptSubmit hook: spots a fix the human asks for a second time.

WHY: core/promised_fix.py holds the logic; this hook only maps the Claude Code
prompt to it. It logs each prompt to $PROMISED_FIX_DIR/asks.jsonl, reads the
label words from $PROMISED_FIX_DIR/labels.json ({"spend-b": ["plan B", ...]}),
and on a re-ask (14-day window) journals a `reask` line and tells the agent to
arm a probe. It never arms by itself (a probe is a decision) and never blocks.

Exit code: 0, always (fail-open; a crash writes nothing and lets the prompt through).
"""
import json
import os
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "common"))
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "promised_fix"))
WINDOW = timedelta(days=14)


def main():
    import promised_fix as pf
    from _hook import gate_stat, mask_secrets, read_stdin_json
    text = str(read_stdin_json().get("prompt") or "")
    d = os.path.dirname(pf.journal_path())
    try:
        labels = json.load(open(os.path.join(d, "labels.json"), encoding="utf-8"))
    except (OSError, ValueError):
        labels = {}
    asks, history, now = os.path.join(d, "asks.jsonl"), [], datetime.now().astimezone()
    try:
        for line in open(asks, encoding="utf-8"):
            try:
                a = json.loads(line)
                if now - datetime.fromisoformat(a["ts"]) <= WINDOW:
                    history.append(a["text"])
            except (ValueError, KeyError, TypeError):
                continue
    except OSError:
        pass
    hit = pf.detect(history, text, labels) if labels and text else None
    if text:
        os.makedirs(d, exist_ok=True)
        with open(asks, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now.isoformat(timespec="seconds"), "text": mask_secrets(text, 2000)}, ensure_ascii=False) + "\n")
    if hit:
        pf.append_journal(None, {"event": "reask", "label": hit[0], "count": hit[1]})
        print("Promised-Fix: the human has now asked %d times about '%s'. Arm a probe (tools/preuve-correction armer); "
              "do not say it is fixed until the probe is GREEN." % (hit[1], hit[0]))
    gate_stat("promised-fix-detect", "reask" if hit else "pass")


try:
    main()
except Exception:
    pass
sys.exit(0)
