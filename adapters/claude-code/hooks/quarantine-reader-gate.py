#!/usr/bin/env python3
"""PreToolUse gate on Write|Edit|MultiEdit|NotebookEdit|Bash: the Quarantine
reader sub-agent gets no write tool and no shell.

WHY (defence in depth, no incident behind it): the reader ingests text nobody
vouches for, so it is the agent an injected page talks to. What takes its
hands away is the `tools:` line of its agent file, enforced by the host. That
is one line: a copy of the file with a wider list, or a host that stops
honouring it, gives the hands back SILENTLY. This gate is the second lock, on
the tool call itself. It does not replace the list: see the shortcut below.

Who is the reader: a call made INSIDE a sub-agent (`agent_id` is present)
whose `agent_type`, case and surrounding spaces ignored, is the reader's name.
`agent_type` without `agent_id` is the main thread of an `--agent` session,
not the quarantined sub-agent, and passes.

WORKAROUND to hand the agent: none. The reader reports what it read and the
parent, which has hands, does the writing.

Environment:
- QUARANTINE_READER  the reader's agent name in this deployment
                     (default: researcher, as in agents/researcher.example.md)

No disarm variable: a lock the session can switch off is not a second lock.
To retire the gate, unwire it from the settings.

Exit codes:
  0  not the reader, or a tool outside REFUSED_TOOLS, or an unreadable payload
     that does not name the reader (fail-open, as every gate here)
  2  BLOCK -- a refused tool, or a reader call this gate cannot read
     (fail-CLOSED for the reader, and only for the reader)
"""
import json
import os
import re
import sys

try:  # before the helper taps stdin: an undecodable byte must not raise in read()
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, os.pardir, "core", "common"))
try:
    from _hook import gate_stat
except Exception:
    def gate_stat(*a, **kw):  # no helper, no journal: the verdict does not depend on it
        pass

HOOK = "quarantine-reader"
# shortcut: a deny-list of the write tools this repo names, so a write tool the
# host or an MCP server adds later passes; turn it into an allow-list once the
# reader's tool list is frozen per deployment.
REFUSED_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit", "Bash")
READER = (os.environ.get("QUARANTINE_READER") or "").strip().casefold() or "researcher"
# Bounded on purpose: this runs over a payload that could not be parsed.
AGENT_TYPE = re.compile(r'"agent_type"\s{0,8}:\s{0,8}("(?:[^"\\]|\\.){0,200}")')


def is_reader(agent_type) -> bool:
    return isinstance(agent_type, str) and agent_type.strip().casefold() == READER


def names_the_reader(raw: str) -> bool:
    """An unparsed payload that carries the reader's agent_type anywhere."""
    for m in AGENT_TYPE.finditer(raw):
        try:
            if is_reader(json.loads(m.group(1))):
                return True
        except Exception:
            continue
    return False


def block(why: str, what: str):
    """Exit 2. `what` is our own text or a name from REFUSED_TOOLS, never a
    piece of the payload: this line is read back by the agent."""
    gate_stat(HOOK, "block", why=why)
    try:
        sys.stderr.write(
            f"BLOCKED (quarantine-reader gate): {what} is refused to the reader "
            "sub-agent, which reads untrusted content and has no hands. Report "
            "what you read; the parent agent does the writing.\n")
    finally:
        sys.exit(2)


def main():
    try:
        raw = "" if sys.stdin.isatty() else sys.stdin.read()
    except Exception:
        raw = ""
    try:
        data = json.loads(raw)
    except Exception:  # RecursionError included: a payload nested too deep
        data = None
    if not isinstance(data, dict):
        if names_the_reader(raw):
            block("unreadable", "a tool call this gate cannot read")
        gate_stat(HOOK, "fail-open")
        sys.exit(0)  # unreadable and no reader named: never block blindly
    if "agent_id" not in data or not is_reader(data.get("agent_type")):
        gate_stat(HOOK, "skip-not-reader")
        sys.exit(0)
    tool = data.get("tool_name")
    if not isinstance(tool, str) or not tool:
        block("no-tool-name", "a call without a tool name")
    if tool in REFUSED_TOOLS:
        block(tool, tool)
    gate_stat(HOOK, "pass")
    sys.exit(0)


if __name__ == "__main__":
    main()
