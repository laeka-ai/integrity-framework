#!/usr/bin/env python3
"""PreToolUse gate on Bash: repairs (updatedInput, pattern as a character class) or blocks `pgrep -f PATTERN` / `pkill -f PATTERN` when the pattern matches itself.

WHY (measured): the Bash tool runs `bash -c '<the whole command>'`. The `pgrep -f` pattern is therefore written
in that bash's own command line, and pgrep finds it every time. A wait like
`while pgrep -f 'tools/bench'; do sleep 30; done` never ends, and `pkill -f` kills its own shell.

What passes: a pattern with a character class (`pgrep -f '[t]ools/bench'`), because the text `[t]ools` does not
match itself. Or wait on a PID: `while kill -0 $PID; do sleep 30; done`.

Heredoc bodies are stripped (a script sent to `bash <<EOF` runs in another process). Fail-open on unreadable input
or an unparsable command, journaled `unparsable`.

Needs a host that honors PreToolUse `updatedInput` without a permissionDecision for the repair; otherwise only the block applies.

Disarm (one session): HARNESS_PGREP_SELF_GATE_DISABLE=1
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, os.pardir, "core", "common"))
try:
    from _hook import gate_stat
except Exception:
    def gate_stat(*a, **k):
        pass

from importlib import import_module
segments = import_module("set-e-inert-gate").segments

STEM = "pgrep-self"


_LONG = {"--full": "f", "--count": "c", "--quiet": "q", "--list-full": "l", "--list-name": "l"}
_TAKES_VALUE = set("dgGPstTuUFO")   # short options whose value must not be read as flags (`-ualice`, `-u alice`)


def letters(seg):
    """Option letters of a pgrep/pkill call: short clusters stop at a value-taking letter; long ones are mapped."""
    out, i = set(), 1
    while i < len(seg):
        a = seg[i]
        if a in _LONG:
            out.add(_LONG[a])
        elif a.startswith("-") and not a.startswith("--"):
            for j, ch in enumerate(a[1:], 1):
                if ch in _TAKES_VALUE:
                    i += 1 if j == len(a) - 1 else 0   # value is the next token only when the letter ends the cluster
                    break
                out.add(ch)
        i += 1
    return out


_LOOP_WORDS = {"while", "until", "for", "do", "then", "if", "elif", "else", "done", "fi", "break"}


def self_matching_pattern(seg, simple=True):
    """The offending pattern of `pgrep|pkill ... -f ... MOTIF`, or None. simple: no loop and no &&/|| in the command."""
    bare = simple and bool(seg) and os.path.basename(seg[0]) == "pgrep"   # bare, not a loop/if condition
    discarded = "/dev/null" in seg
    while seg and seg[0] in ("while", "until", "if", "!", "then", "do", "else", "exec", "timeout"):
        seg = seg[1:] if seg[0] != "timeout" else seg[2:]
    if not seg or os.path.basename(seg[0]) not in ("pgrep", "pkill"):
        return None
    redir = next((i for i, a in enumerate(seg) if a[0] in "<>&;()|"), len(seg))   # `>/dev/null`, `2>&1`, `);`
    seg = seg[:redir - 1] if redir < len(seg) and seg[redir - 1].isdigit() else seg[:redir]
    lt = letters(seg)
    if "f" not in lt:
        return None
    # A bare listing (`pgrep -af X | head`) only shows one extra line: allowed.
    # A listing whose output is thrown away, or that sits in a loop / before `&&` `||`, is a wait: blocked.
    if bare and not discarded and lt & set("la") and not lt & set("cq"):
        return None
    patterns = [a for a in seg[1:] if not a.startswith("-")]
    if not patterns or "[" in patterns[-1]:
        return None
    return patterns[-1]


def matches_itself(m, cmd):
    """True si pattern m (simple `X=val` variables expanded) occurs in the text of cmd, hence in the bash -c.
    Measured false positive: `bench-(a|x)` or `"$B/"` do not match their own line.
    shortcut: regex Python, pas ERE ; on any doubt (unknown variable, POSIX class, invalid regex): True."""
    if "[:" in m:
        return True
    def val(v):
        a = re.search(r"(?<![\w$])" + re.escape(v.group(1)) + r"=([^\s;&|'\"]*)", cmd)
        return a.group(1) if a else v.group(0)
    m = re.sub(r"\$\{?(\w+)\}?", val, m)
    if "$" in m:
        return True
    try:
        return re.search(m, cmd) is not None
    except re.error:
        return True


def offending(cmd: str):
    """Offending patterns of cmd (list), or None if unparsable."""
    segs = segments(cmd)
    if segs is None:
        return None
    # shortcut: segments() drops the separators, so any `&&`/`||` in the text blocks the listing (over-blocks `X | head || true`)
    simple = not any(s[0] in _LOOP_WORDS for s in segs) and "&&" not in cmd and "||" not in cmd
    ms = (self_matching_pattern(s, simple) for s in segs)
    return [m for m in ms if m and matches_itself(m, cmd)]


def verdict(cmd: str):
    ms = offending(cmd)
    return "unparsable" if ms is None else (ms[0] if ms else "")


def as_class(m):
    """`banc-x|claude.*-p` -> `[b]anc-x|[c]laude.*-p` (each top-level branch); None if a branch does not start with a plain character."""
    out, depth, cur = [], 0, ""
    for ch in m + "|":
        if ch == "|" and depth == 0:
            if not re.match(r"[A-Za-z0-9_/]", cur):
                return None
            out.append("[" + cur[0] + "]" + cur[1:])
            cur = ""
            continue
        depth += (ch in "([") - (ch in ")]")
        cur += ch
    return "|".join(out)


def repair(cmd: str):
    """Command rewritten with a class in each offending pattern, or None (the block stays). The output is re-judged by verdict()."""
    ms = offending(cmd)
    if not ms:
        return None
    repls = []
    for p in re.finditer(r"\b(?:pgrep|pkill)(?:\s+--?[A-Za-z][\w-]*)*\s+(['\"]?)", cmd):
        for m in ms:
            q, end = p.group(1), p.end()
            if not cmd.startswith(m, end):
                continue
            nxt = cmd[end + len(m):end + len(m) + 1]
            if (q and nxt != q) or (not q and (nxt not in ("", " ", ";", "&", "|", ")", "\n", "<", ">") or not re.fullmatch(r"[\w./:@%+=,-]+", m))):
                continue
            c = as_class(m)
            if c is None:
                return None
            repls.append((end, end + len(m), c if q else "'" + c + "'"))
            break
    for a, b, c in sorted(repls, reverse=True):
        cmd = cmd[:a] + c + cmd[b:]
    return cmd if repls and verdict(cmd) == "" else None


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        gate_stat(STEM, "fail-open")
        return 0
    if data.get("tool_name") != "Bash":
        return 0
    if os.environ.get("HARNESS_PGREP_SELF_GATE_DISABLE") == "1":
        gate_stat(STEM, "skip-disabled")
        return 0
    cmd = (data.get("tool_input") or {}).get("command") or ""
    v = verdict(cmd)
    if v == "":
        gate_stat(STEM, "pass")
        return 0
    if v == "unparsable":
        gate_stat(STEM, "unparsable", cmd=cmd[:120])
        return 0
    fix = repair(cmd)
    if fix:
        gate_stat(STEM, "repair", cmd=cmd[:120])
        # shortcut: needs a host that honors PreToolUse updatedInput without permissionDecision, else upgrade to block only
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "updatedInput": {**data["tool_input"], "command": fix}}}))
        return 0
    gate_stat(STEM, "block", why="pgrep -f matches itself", cmd=cmd[:120])
    a, b = v[0], v[1:]
    sys.stderr.write(
        f"BLOCKED (pgrep-self-gate): the pattern \"{v}\" is written in the command line of the bash that runs your "
        "command, so pgrep -f always finds it (a wait never ends; pkill -f kills your own shell). "
        f"Write it with a class: '[{a}]{b}', or wait on a PID: while kill -0 $PID; do sleep 30; done.\n"
        "Session kill-switch: HARNESS_PGREP_SELF_GATE_DISABLE=1\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
