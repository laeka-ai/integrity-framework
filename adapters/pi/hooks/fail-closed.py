#!/usr/bin/env python3
"""fail-closed.py: the fail-closed patch of pi-yaml-hooks 2026.8.11, as data.

pi-yaml-hooks blocks a tool call only when a `tool.before.*` hook exits with code 2. Every other end lets
the call through: a hook past its timeout (`timed_out`), a hook that exits 1, a hook killed by a signal
(code null, mapped to 127), a hook whose evaluation throws, and a tool call that arrives without a session
id (the hooks never run). Read in the upstream code. So an agent that kills its
own guard process (same uid) sees its command pass. This patch closes those ends for `tool.before.*` ONLY:
any end other than exit 0 blocks. Other events are untouched (a failed `session.idle` hook stays a log line).

The patch is four exact text replacements (the fourth, in session-state.js, keeps the short fields of
truncated tool arguments: see SITES). Each original file must have its pinned sha256 (the 2026.8.11
dist as published), each old text must occur exactly once, and each patched file must come out
at its pinned sha256: a different upstream file, or a drift in this script, is a refusal, never a guess.

  fail-closed.py apply <pi-yaml-hooks dir> <out dir>   writes the 4 patched files under <out dir>, same
                                                       relative paths; <pi-yaml-hooks dir> is not touched
  fail-closed.py check <pi-yaml-hooks dir>             rc 0 if the 4 files there are the patched ones,
                                                       rc 1 if they are the originals, rc 2 otherwise
  fail-closed.py list                                  the relative paths and both pins, one line each
"""
import hashlib
import os
import sys

SITES = [
    {
        "path": "dist/core/bash-executor.js",
        "before": "140a5e400ace6d1bcea88c44be8dd8d1903e02e4398621bf37f6f753a4f48c74",
        "edits": [
            ('        return { ...result, status: "timed_out", blocking: false };\n',
             '        return { ...result, status: "timed_out", blocking: isBlockingToolBeforeEvent(context.event) };\n'),
            ('    return { ...result, status: "failed", blocking: false };\n}\n',
             '    return { ...result, status: "failed", blocking: isBlockingToolBeforeEvent(context.event) };\n}\n'),
        ],
    },
    {
        "path": "dist/core/runtime/dispatch.js",
        "before": "d90e74b981e1bf497dc979eccf918ea63c52e224a54877780a5732ee8f3a7205",
        "edits": [
            ('        logHookFailure(hook.event, hook.source.filePath, error);\n'
             '        return { blocked: false };\n'
             '    }\n'
             '    if (!decision.matched) {\n',
             '        logHookFailure(hook.event, hook.source.filePath, error);\n'
             '        if (String(hook.event).startsWith("tool.before.")) {\n'
             '            return { blocked: true, blockReason: "Blocked: the guard hook could not be evaluated" };\n'
             '        }\n'
             '        return { blocked: false };\n'
             '    }\n'
             '    if (!decision.matched) {\n'),
        ],
    },
    {
        "path": "dist/pi/register-adapter.js",
        "before": "4ccbe81d7f39fef37f80aeebffcf5f3821123d437930a6b940f1506700c849db",
        "edits": [
            ('    pi.on("tool_call", async (event, ctx) => {\n'
             '        rememberContext(ctx.cwd, ctx);\n'
             '        const sessionId = safeGetSessionId(ctx.sessionManager);\n'
             '        if (!sessionId)\n'
             '            return;\n',
             '    pi.on("tool_call", async (event, ctx) => {\n'
             '        rememberContext(ctx.cwd, ctx);\n'
             '        const sessionId = safeGetSessionId(ctx.sessionManager);\n'
             '        if (!sessionId)\n'
             '            return { block: true, reason: "Blocked: no session id, the guard hooks cannot run" };\n'),
        ],
    },
    # Past 64 KiB of tool_args, the
    # hook got a placeholder with NO field at all: a 66 KB write lost its path, so the write guard refused every
    # write past 64 KiB, and the Bash adapter judged "". The cap does not move. The placeholder now keeps each
    # short top-level field (4 KiB at most, 16 KiB in all: a write keeps its path) and NAMES every field it
    # drops in `_pi_hooks_tool_args_dropped`, so that a guard refuses when a field it reads is missing (a long
    # `path` dropped next to a short `file_path` must not let the guard judge the wrong one). The marker keys
    # are written after the kept fields: a tool argument cannot overwrite them.
    {
        "path": "dist/core/session-state.js",
        "before": "30bb42168f229869f36f2224029cb898763a49b65dcddc7e4286552cd2642bb9",
        "edits": [
            ('    return {\n'
             '        _pi_hooks_tool_args_truncated: true,\n'
             '        _pi_hooks_tool_args_original_byte_length: Buffer.byteLength(json, "utf8"),\n',
             '    const kept = Object.create(null);\n'
             '    const dropped = [];\n'
             '    let keptBytes = 0;\n'
             '    if (redacted && typeof redacted === "object" && !Array.isArray(redacted)) {\n'
             '        for (const [k, v] of Object.entries(redacted)) {\n'
             '            const n = Buffer.byteLength(JSON.stringify(k) + ":" + (JSON.stringify(v) ?? "null"), "utf8");\n'
             '            if (n <= 4 * 1024 && keptBytes + n <= 16 * 1024) {\n'
             '                kept[k] = v;\n'
             '                keptBytes += n;\n'
             '            }\n'
             '            else {\n'
             '                dropped.push(k);\n'
             '            }\n'
             '        }\n'
             '    }\n'
             '    return {\n'
             '        ...kept,\n'
             '        _pi_hooks_tool_args_truncated: true,\n'
             '        _pi_hooks_tool_args_dropped: dropped,\n'
             '        _pi_hooks_tool_args_original_byte_length: Buffer.byteLength(json, "utf8"),\n'),
        ],
    },
]

# The patched pins, written once the first build was read and benched (see the bench's control); None means
# "not pinned yet", and apply then refuses: an unpinned result never leaves this script.
PATCHED = {
    "dist/core/bash-executor.js": "d932428de5f9b20399a05c4da28ed6db68a15c515584ceed8276e030c3586d56",
    "dist/core/runtime/dispatch.js": "7b4cbf0f5bddd0b2ebd33b96c91f25dcc4b1b3feef70de4d6ffeca9e7450a34d",
    "dist/pi/register-adapter.js": "d77818ef7cfddd7dcbd962ce112c280f31ea9015d684dae202cad87a71673ad7",
    "dist/core/session-state.js": "460df657af84fb79acce7e5d70efb80c3f18451a0f979ff169d4c21429aba878",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def patched_bytes(site, original):
    if sha(original) != site["before"]:
        raise SystemExit(f"refused: {site['path']} is not the pinned original ({sha(original)[:16]})")
    text = original.decode("utf-8")
    for old, new in site["edits"]:
        n = text.count(old)
        if n != 1:
            raise SystemExit(f"refused: {site['path']}: an old text occurs {n} times, not once")
        text = text.replace(old, new)
    return text.encode("utf-8")


def apply(src, out, allow_unpinned=False):
    for site in SITES:
        with open(os.path.join(src, site["path"]), "rb") as f:
            new = patched_bytes(site, f.read())
        pin = PATCHED[site["path"]]
        if pin is None and not allow_unpinned:
            raise SystemExit(f"refused: {site['path']}: no patched pin yet ({sha(new)})")
        if pin is not None and sha(new) != pin:
            raise SystemExit(f"refused: {site['path']}: patched sha {sha(new)[:16]} is not the pin {pin[:16]}")
        dest = os.path.join(out, site["path"])
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".tmp"
        with open(tmp, "wb") as f:
            f.write(new)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)
        print(f"{sha(new)}  {site['path']}")


def check(src):
    state = set()
    for site in SITES:
        try:
            with open(os.path.join(src, site["path"]), "rb") as f:
                h = sha(f.read())
        except OSError:
            return 2
        if PATCHED[site["path"]] is not None and h == PATCHED[site["path"]]:
            state.add("patched")
        elif h == site["before"]:
            state.add("original")
        else:
            return 2
    if state == {"patched"}:
        return 0
    if state == {"original"}:
        return 1
    return 2


def main(argv):
    if len(argv) == 3 and argv[0] == "apply":
        apply(argv[1], argv[2])
        return 0
    if len(argv) == 3 and argv[0] == "apply-unpinned":   # first build only, to read the result and pin it
        apply(argv[1], argv[2], allow_unpinned=True)
        return 0
    if len(argv) == 2 and argv[0] == "check":
        return check(argv[1])
    if argv == ["list"]:
        for site in SITES:
            print(f"{site['path']} {site['before']} {PATCHED[site['path']]}")
        return 0
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
