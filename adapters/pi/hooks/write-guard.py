#!/usr/bin/env python3
"""write-guard.py: an agent writes ONLY inside its workshop.

Hook for the file-writing tools (`tool.before.write`, `tool.before.edit`). A hook
that only covers `tool.before.bash` leaves the agent free to rewrite its own gate,
its instructions or its launcher with the write tool, and the refused `rm -rf`
then passes. This closes that door.

THE RULE IS "OUTSIDE THE WORKSHOP", NOT "NO WRITING". Writing is the agent's job.
What is forbidden is writing anywhere but WORKSHOP (plus the optional JOURNAL).

WHY `realpath` AND NOT A PREFIX COMPARISON. A prefix check is bypassed in two
commands:

    ln -s /agent/gates/destructive-gate.py /agent/workshop/x.css
    write /agent/workshop/x.css      <- the REQUESTED path is inside the workshop

The `ln -s` is neither destructive nor privileged, so the bash gate lets it pass;
the write then follows the link and lands on the gate. We therefore decide on the
RESOLVED path (`os.path.realpath`: follows links at every component, also when the
target does not exist yet or when a PARENT directory is the link). The workshop is
resolved the same way.

FAIL-CLOSED: unreadable input, a missing path or any failure gives exit 2. pi-yaml-hooks
blocks ONLY on exit 2; any other code lets the call run.

Env: PI_WORKSHOP (default /srv/agent/workshop), PI_JOURNAL (default
/srv/agent/journal), WRITE_GUARD_TRACE (optional file, one JSON line per allowed write).
The defaults are examples: set them to your own layout.
"""
from __future__ import annotations

import json
import os
import sys

WORKSHOP = os.environ.get("PI_WORKSHOP", "/srv/agent/workshop")
JOURNAL = os.environ.get("PI_JOURNAL", "/srv/agent/journal")

# Keys where the various tools keep their path. All are tried rather than assuming one:
# if Pi renames the field, we want to block for lack of a path, not pass by inattention.
PATH_KEYS = ("path", "file_path", "filePath", "target", "filename")


def refuse(why: str) -> None:
    sys.stderr.write(
        "BLOCKED [write-guard] write refused: %s\n"
        "   I write only in the workshop (%s).\n"
        "   No permission is missing: it is the only place where what I make belongs.\n"
        % (why, WORKSHOP))
    sys.exit(2)


def inside_workshop(path: str) -> bool:
    """True if the RESOLVED path is the workshop or the journal, or lives inside one."""
    target = os.path.realpath(path)
    for root in (WORKSHOP, JOURNAL):
        r = os.path.realpath(root)
        if target == r or target.startswith(r + os.sep):
            return True
    return False


def main() -> int:
    try:
        raw = sys.stdin.read()
    except Exception as exc:  # noqa: BLE001
        refuse("cannot read the hook context (%s)" % exc)
    try:
        ctx = json.loads(raw or "")
    except Exception:
        refuse("unreadable hook context: I cannot know where this writes")
    if not isinstance(ctx, dict) or "_pi_hooks_truncated" in ctx:
        refuse("unreadable or truncated hook context: I cannot know where this writes")
    args = ctx.get("tool_args") or ctx.get("toolArgs") or {}
    if not isinstance(args, dict):
        refuse("unreadable tool arguments")
    # Past 64 KiB of tool arguments, pi-yaml-hooks (as patched by fail-closed.py) keeps the
    # short fields and names the dropped ones. If a path key was dropped, the real path is
    # unknown here, and judging the next key would judge the wrong path.
    if "_pi_hooks_tool_args_truncated" in args:
        dropped = args.get("_pi_hooks_tool_args_dropped")
        if not isinstance(dropped, list) or any(k in dropped for k in PATH_KEYS):
            refuse("path too long for the guard to read: I cannot know where this writes")

    path = ""
    for k in PATH_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            path = v.strip()
            break
    if not path:
        refuse("no path in the request: I cannot tell where this writes")
    # A relative path is read from the working directory, which the launcher sets to the workshop.
    if not os.path.isabs(path):
        path = os.path.join(os.environ.get("PWD", WORKSHOP), path)

    try:
        ok = inside_workshop(path)
    except Exception as exc:  # noqa: BLE001
        refuse("cannot resolve the path (%s)" % exc)
    if not ok:
        real = os.path.realpath(path)
        detail = '"%s" leads outside the workshop' % path
        if real != os.path.abspath(path):
            # Symlink case: NAME the real destination, or the refusal looks arbitrary.
            detail += ' (it actually points to "%s")' % real
        refuse(detail)

    trace = os.environ.get("WRITE_GUARD_TRACE")
    if trace:
        try:
            with open(trace, "a", encoding="utf-8") as f:
                f.write(json.dumps({"tool": ctx.get("tool_name"), "path": path,
                                    "resolved": os.path.realpath(path),
                                    "verdict": "allowed"}) + "\n")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
