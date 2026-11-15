#!/usr/bin/env python3
"""subagent-canary.py -- SubagentStop (and Stop) hook: confronts a delegated
agent's report with what its transcript shows it did. DIAGNOSTIC by default.

WHY: a sub-agent's "tests green, committed abc1234" is read by the parent as
fact. The checks themselves live in core/canary/canary.py and read evidence
the agent does not write: the tool calls of its transcript and the receipts
journal. This hook only maps the Claude Code transcript to that evidence.

Armed by the brief: the FIRST user entry of the transcript carries
`CANARY-NONCE:<hex>` (placed by canary.inject_echo) and/or `# doctrine:` lines.
A transcript with neither is not a canary run: skipped, nothing journalled
but the gate-stats line.

Transcript: `agent_transcript_path` when the host gives it (the sub-agent's
own file on SubagentStop), else `transcript_path`.

Environment:
- CANARY_JOURNAL   verdict journal (default: $HARNESS_STATE_DIR/canary-agents.jsonl)
- CANARY_RECEIPTS  receipts journal (default: $HARNESS_STATE_DIR/canary-receipts.jsonl)
- CANARY_MODE=block  exit 2 when the verdict fails (default: diagnostic, exit 0)

Exit codes:
  0  always in diagnostic mode, on every fail-open path (a crash writes an
     `error` line to the journal), and on a stop_hook_active retry
  2  CANARY_MODE=block and the verdict did not pass
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "common"))
sys.path.insert(0, os.path.join(HERE, os.pardir, os.pardir, os.pardir, "core", "canary"))
try:
    import canary
    from _hook import gate_stat
    from _transcript import assistant_text_blocks, load_transcript, tool_events
except Exception:
    sys.exit(0)   # fail-open: a broken helper must never break a session

HOOK = "subagent-canary"


def _role(ev):
    msg = ev.get("message") if isinstance(ev, dict) else None
    return msg.get("role") if isinstance(msg, dict) else None


def main():
    data = json.load(sys.stdin)
    path = data.get("agent_transcript_path") or data.get("transcript_path")
    events = load_transcript(path, limit=0)
    users = [ev for ev in events if _role(ev) == "user"]
    brief = assistant_text_blocks(users[0]) if users else ""
    m = canary.NONCE_RE.search(brief)
    nonce = m.group(1) if m else None
    rules = canary.parse_doctrine(brief.splitlines())
    if not nonce and not rules:
        gate_stat(HOOK, "skip-unarmed")
        return 0

    replies = [ev for ev in events if _role(ev) == "assistant"]
    texts = [t for t in (assistant_text_blocks(ev) for ev in replies) if t.strip()]
    report = texts[-1] if texts else ""
    calls = tool_events(events)
    model = next((ev["message"].get("model") for ev in replies if ev["message"].get("model")), None)
    v = canary.verdict(
        canary.check_echo(texts[0] if texts else "", nonce),
        canary.check_receipts(report, canary.receipts_path(), nonce),
        canary.check_doctrine(rules, calls),
        canary.check_claims(canary.extract_claims(report), calls),
        event=data.get("hook_event_name"), session_id=data.get("session_id"),
        agent_id=data.get("agent_id"), model=model, nonce=nonce, transcript=path)
    canary.append_journal(canary.journal_path(), v)
    gate_stat(HOOK, "pass" if v["passed"] else "fail")
    if v["passed"] or os.environ.get("CANARY_MODE") != "block" or data.get("stop_hook_active"):
        return 0
    failed = [p for p in ("echo", "receipts", "doctrine", "claims") if canary._point_ok(v, p) is False]
    sys.stderr.write(
        "BLOCKED (subagent-canary): the report does not match the transcript; "
        "failed points: %s.\n"
        "The verdict line with each claim's evidence is in %s.\n"
        "Fix the report so every claim names a tool call that happened (or "
        "remove the claim), keep the doctrine, and cite only receipts of this run.\n"
        "Way out: unset CANARY_MODE (diagnostic mode, exit 0).\n"
        % (", ".join(failed), canary.journal_path()))
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        try:
            canary.append_journal(canary.journal_path(), {"error": repr(exc)[:300]})
        except Exception:
            pass
        sys.exit(0)   # diagnostic: a crash never breaks a session
