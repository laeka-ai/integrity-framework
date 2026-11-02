#!/usr/bin/env python3
"""PreToolUse gate on Bash: blocks a command whose FIRST instruction is `set -e`.

WHY (measured): inside the agent's Bash tool, `set -e` stops nothing.

    set -e; false; echo AFTER        -> prints AFTER
    bash -ec 'false; echo AFTER'     -> stops, rc=1

A command like `set -euo pipefail; git checkout -b x; generate; git commit` goes on after the
failed checkout and commits on the wrong branch. It BELIEVES it is protected, which is what makes
it dangerous.

What is read: the Bash tool command only, and its FIRST instruction. A `set -e` inside a heredoc or a
real script (`bash <<'EOF'`, `bash script.sh`) works and is not blocked. A `set -e` that is not first
is journaled (`not-first`) without blocking, to measure what the rule lets through.

Instead: chain with `&&`, or wrap in `bash -ec '...'` (or `bash -euo pipefail -c '...'`).

Re-check on every host update: replay `set -e; false; echo AFTER` in the real Bash tool. If it stops,
`set -e` works again and this gate must be disarmed (it would block valid commands).

Heredoc bodies are stripped before parsing (quoted text is not an instruction). Fail-open on
unreadable input or an unparsable command (journaled `unparsable`).

Disarm (one session): HARNESS_SET_E_INERT_GATE_DISABLE=1
"""
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, os.pardir, "core", "common"))
try:
    from _hook import gate_stat
except Exception:
    def gate_stat(*a, **k):
        pass

STEM = "set-e-inert"
SEPARATORS = {"|", "||", "&&", ";", ";;", "&", "(", ")", "\n"}


def strip_heredocs(cmd: str) -> str:
    out, end = [], None
    for line in cmd.split("\n"):
        if end is not None:
            if line.strip() == end:
                end = None
            continue
        out.append(line)
        m = re.search(r"<<-?\s*(['\"]?)([A-Za-z_]\w*)\1", line)
        if m:
            end = m.group(2)
    return "\n".join(out)


def segments(cmd: str):
    """Shell instructions, heredocs stripped, quotes respected. None if unparsable."""
    cmd = strip_heredocs(cmd)
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace = " \t\r"          # a newline separates two instructions, like `;`
        toks = list(lex)
    except ValueError:
        return None
    segs, cur = [], []
    for t in toks:
        if t in SEPARATORS:
            if cur:
                segs.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def arms_errexit(seg) -> bool:
    """True if the instruction is `set` and arms errexit: short cluster with e (-e, -eu, -Ee), or -o errexit."""
    if not seg or seg[0] != "set":
        return False
    args = seg[1:]
    for i, a in enumerate(args):
        if a == "--":
            return False
        if a == "-o" and i + 1 < len(args) and args[i + 1] == "errexit":
            return True
        if a.startswith("-") and not a.startswith("--") and len(a) > 1 and "e" in a[1:]:
            return True
    return False


def verdict(cmd: str) -> str:
    """'first' (block), 'not-first' (journaled), 'unparsable' (journaled, fail-open), or ''."""
    segs = segments(cmd)
    if segs is None:
        return "unparsable"
    if not segs:
        return ""
    if arms_errexit(segs[0]):
        return "first"
    if any(arms_errexit(s) for s in segs[1:]):
        return "not-first"
    return ""


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        gate_stat(STEM, "fail-open")
        return 0
    if data.get("tool_name") != "Bash":
        return 0
    if os.environ.get("HARNESS_SET_E_INERT_GATE_DISABLE") == "1":
        gate_stat(STEM, "skip-disabled")
        return 0
    cmd = (data.get("tool_input") or {}).get("command") or ""
    v = verdict(cmd)
    if v == "":
        gate_stat(STEM, "pass")
        return 0
    if v in ("unparsable", "not-first"):
        gate_stat(STEM, v, cmd=cmd[:120])
        return 0
    gate_stat(STEM, "block", why="set -e first, inert in the Bash tool", cmd=cmd[:120])
    sys.stderr.write(
        "BLOCKED (set-e-inert-gate): in the Bash tool, `set -e` stops nothing "
        "(`set -e; false; echo AFTER` prints AFTER). Your command would go on after a failure while "
        "believing it is protected. Chain the steps with `&&`, or wrap them: bash -euo pipefail -c '...'.\n"
        "Session kill-switch: HARNESS_SET_E_INERT_GATE_DISABLE=1\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
