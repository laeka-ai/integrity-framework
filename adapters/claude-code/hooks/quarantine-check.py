#!/usr/bin/env python3
"""quarantine-check.py -- SubagentStop (and SubagentHandback) hook: confronts a
reader sub-agent's report with the web tool events of its own run.
DIAGNOSTIC by default. The checks live in core/quarantine/quarantine.py; this
hook only maps the Claude Code payload to them.

Report: `last_assistant_message` (SubagentStop) or `tool_input.message`
(SubagentHandback). Events: `agent_transcript_path`, the sub-agent's own file
(`transcript_path` is the parent's and never grounds a quote). Without
`agent_transcript_path` the run is skipped. The brief (first user entry) is the
trusted text for links.

Environment:
- QUARANTINE_JOURNAL  verdict journal (default: $HARNESS_STATE_DIR/quarantine-runs.jsonl)
- QUARANTINE_MODE=block  exit 2 when the verdict fails (default: diagnostic, exit 0)

Exit codes:
  0  diagnostic mode, every fail-open path (a crash writes an `error` line)
  2  QUARANTINE_MODE=block and the verdict did not pass; stderr names the
     offending quotes and links so the sub-agent can correct. No stop_hook_active
     exemption: the host caps consecutive stop-hook blocks itself
     (CLAUDE_CODE_STOP_HOOK_BLOCK_CAP, 8).

Claude Code's native scan ("instruction-shaped pattern") overlaps `orders` only.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "common"))
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "quarantine"))
try:
    import quarantine
    from _hook import gate_stat
    from _transcript import assistant_text_blocks, load_transcript, tool_events
except Exception:
    sys.exit(0)   # fail-open: a broken helper must never break a session

HOOK = "quarantine-check"


def main():
    data = json.load(sys.stdin)
    path = data.get("agent_transcript_path")
    if not path:
        gate_stat(HOOK, "skip-no-agent-transcript")
        return 0
    events = load_transcript(path, limit=0)
    if data.get("hook_event_name") == "SubagentHandback":
        report = (data.get("tool_input") or {}).get("message") or ""
    else:
        report = data.get("last_assistant_message") or ""
    first = next((ev for ev in events if (ev.get("message") or {}).get("role") == "user"), None)
    brief = assistant_text_blocks(first) if first else ""
    v = quarantine.check_report(
        str(report), tool_events(events), trusted_text=brief,
        event=data.get("hook_event_name"), session_id=data.get("session_id"),
        agent_id=data.get("agent_id"), transcript=path)
    quarantine.append_journal(quarantine.journal_path(), v)
    gate_stat(HOOK, "pass" if v["passed"] else "fail")
    if v["passed"] or os.environ.get("QUARANTINE_MODE") != "block":
        return 0
    bad = ["quote %s: %r" % (q["verdict"], str(q["text"])[:120])
           for q in v["quotes"]["items"] if q["verdict"] in ("ungrounded", "misattributed")]
    bad += ["link unseen: " + i["url"] for i in v["links"]["items"] if i["verdict"] == "unseen"]
    bad += ["tool outside fetch/search: %s" % h["kind"] for h in v["hands"]]
    sys.stderr.write(
        "BLOCKED (quarantine-check): the report is not anchored in what you read.\n  %s\n"
        "Quote only text your WebFetch/WebSearch returned, under the URL it came from, "
        "and cite only URLs you saw; remove the rest.\n"
        "Way out: unset QUARANTINE_MODE (diagnostic mode, exit 0).\n" % "\n  ".join(bad))
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        try:
            quarantine.append_journal(quarantine.journal_path(), {"error": repr(exc)[:300]})
        except Exception:
            pass
        sys.exit(0)   # diagnostic: a crash never breaks a session
