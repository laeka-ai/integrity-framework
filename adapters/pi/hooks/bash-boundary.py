#!/usr/bin/env python3
"""bash-boundary.py: the Bash frontier of an unattended Pi agent.

Translates the pi-yaml-hooks payload (`tool_args.command`) into the Claude Code hook
payload (`tool_name` + `tool_input.command`), pipes it to the ONE shared gate
(adapters/claude-code/hooks/destructive-command-gate.py, unmodified) and PROPAGATES its
exit code (2 = block) and stderr. There is no second copy of the gate's rules.

WHY A HARDER MODE THAN CLAUDE CODE. In Claude Code the gate is an anti-drift net: behind
it stand the product's own classifier and a human in the session. An unattended Pi agent
has neither, so the gate is the last wall, and three escape hatches built for a human
become doors for the agent:

  1. the authorization TAG inside the command. The gate answers `authorized` and the
     command passes; worse, the gate's refusal message TEACHES the syntax to the model
     (a model copied it on the next turn). Here the tag is STRIPPED from every form
     submitted to the gate, and the refusal never shows its syntax.
  2. the kill switch variable and the gate's tuning variables in the environment. The
     gate runs under `python3 -I` with a CLOSED environment list (PATH, HOME, LANG,
     LC_ALL): a variable that is not on the list cannot loosen it.
  3. a prefix before the command (`FOO=1 rm -rf X`, `env rm -rf X`, `/bin/rm`): the
     verb is no longer in command position for the gate's pattern. The command is
     NORMALISED (prefixes, absolute binary path, quoted verb) before the gate sees it.

Also, in this order:
  * truncated or unreadable context: refused (fail-closed);
  * a COMPUTED verb (`$(printf rm)`, backticks, `$X`, `eval`) is refused: a pod agent
    has no reason to compute its verbs, and chasing the endless syntax race is lost;
  * the contents of `bash -c "..."` and `eval "..."` (up to 3 levels) are submitted too:
    the gate erases string literals before analysing, so it cannot see inside them;
  * the only authorization that counts comes from the HOST: a JSON-lines file the agent
    mounts READ-ONLY, each entry bound to the sha256 of the EXACT command and carrying
    an expiry. No valid entry: refusal.
  * the gate file's sha256 is compared with a reference on EVERY call, if the reference
    exists (a write that reached the gate mid-session would otherwise disarm it).

Not covered here, on purpose: a shell parser that unwraps heredocs and command
substitutions inside quotes. A gate that has one (see ARCHITECTURE.md, "Pi adapter")
is stronger; this one does not, and says so.

Exit: 0 allow, 2 block. pi-yaml-hooks blocks ONLY on 2, so every failure of this script
exits 2, never 1.

Env: PI_BASH_GATE (path of the gate; default: the shared gate in this repository),
PI_GATE_SHA (reference sha256 file), PI_HOST_AUTHORIZATIONS (default
/opt/host-authorizations/authorizations.jsonl), PI_BOUNDARY_JOURNAL (verdict journal;
default ~/.agent/boundary-verdicts.jsonl), PI_BOUNDARY_TRACE (optional debug trace).
"""
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone

AUTH_FILE = os.environ.get("PI_HOST_AUTHORIZATIONS", "/opt/host-authorizations/authorizations.jsonl")
DEFAULT_GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                            "claude-code", "hooks", "destructive-command-gate.py")
GATE = os.environ.get("PI_BASH_GATE", DEFAULT_GATE)
CLOSED_ENV = ("PATH", "HOME", "LANG", "LC_ALL")

# Recognised in order to be REMOVED, never to be believed.
TAG = re.compile(r"\[DESTRUCTIVE-AUTHORIZED\s+reason=[^\]]{3,}\]", re.IGNORECASE)
_LAUNCHERS = r"(?:/\S*/)?(?:env|sudo|nohup|command|timeout|nice|ionice)"
PREFIXES = re.compile(
    r"^(?:\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S*)\s+"
    r"|" + _LAUNCHERS + r"(?:\s+-\S+|\s+\d+(?:\.\d+)?[smhd]?)*\s+))+")
ABSOLUTE_BINARY = re.compile(r"^\s*/\S*/([A-Za-z0-9_.-]+)")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "eval"}
LAUNCHER_VERBS = {"sudo", "doas", "env", "command", "exec", "nohup", "nice",
                  "time", "timeout", "stdbuf", "ionice", "xargs"}


def verdict(decision, code, command="", reason=""):
    """Journal EVERY verdict (fixed path, not a per-caller one), then exit with the code."""
    j = os.environ.get("PI_BOUNDARY_JOURNAL", os.path.expanduser("~/.agent/boundary-verdicts.jsonl"))
    try:
        os.makedirs(os.path.dirname(j), exist_ok=True)
        with open(j, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "decision": decision,
                                "code": code, "command": (command or "")[:300],
                                "reason": (reason or "")[:200]}) + "\n")
    except Exception:
        pass
    sys.exit(code)


def envelopes(cmd):
    """Contents of `... -c <string>` and `eval <string>` carried by cmd; None if unparseable."""
    try:
        tokens = shlex.split(cmd, comments=False, posix=True)
    except ValueError:
        return None
    found, i = [], 0
    while i < len(tokens):
        name = os.path.basename(tokens[i])
        if name == "eval" and i + 1 < len(tokens):
            found.append(" ".join(tokens[i + 1:]))
            break
        if name in _SHELLS and i + 2 < len(tokens) and tokens[i + 1] == "-c":
            found.append(tokens[i + 2])
            i += 3
            continue
        i += 1
    return found


def _normalise_segment(seg):
    seg = PREFIXES.sub("", seg)
    return ABSOLUTE_BINARY.sub(lambda m: " " + m.group(1), seg, count=1)


def _unquote_verb(seg):
    """`"rm" -rf X` -> `rm -rf X` WITHOUT unquoting the arguments (the gate erases string
    literals, so a quoted verb is invisible to it; `grep -r "rm -rf" .` keeps its quotes)."""
    try:
        return shlex.join(shlex.split(seg))
    except Exception:
        return seg


def normalise(cmd):
    stripped = TAG.sub(" ", cmd)
    parts = re.split(r"(\s*(?:&&|\|\||[;&|])\s*)", stripped)
    return "".join(p if i % 2 else _normalise_segment(_unquote_verb(p)) for i, p in enumerate(parts))


def _mask_quotes(cmd):
    """Replace the inside of each quoted string by X (same length), so a metacharacter inside
    a string is text, not structure."""
    out, i, n = [], 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c in "'\"":
            j = i + 1
            while j < n and cmd[j] != c:
                j += 1
            out.append("X" * (min(j, n - 1) - i + 1))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def computed_verb(cmd):
    """The reason, if a command VERB is the product of an expansion (or eval); else None.
    Only the verb is judged: `$` in an ARGUMENT (`echo "$HOME"`) is legitimate."""
    cmd = _mask_quotes(cmd)
    for seg in re.split(r"(?:&&|\|\||[;&|\n])", cmd):
        toks = seg.strip().split()
        i = 0
        while i < len(toks):
            t = toks[i].lstrip("(){")
            if not t:
                i += 1
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
                i += 1
                continue
            if t.split("/")[-1] in LAUNCHER_VERBS:
                i += 1
                while i < len(toks) and re.match(r"^(?:-\S+|\d\S*|[A-Za-z_][A-Za-z0-9_]*=\S*)$", toks[i]):
                    i += 1
                continue
            break
        if i >= len(toks):
            continue
        verb = toks[i].lstrip("(){")
        if not verb:
            continue
        if "$" in verb or "`" in verb:
            return 'the verb "%s" is computed (an expansion): not allowed here' % verb
        if verb == "eval":
            return '"eval" runs a computed string: not allowed here'
    return None


def forms_to_judge(cmd, depth=3):
    """The normalised command PLUS the content of each `bash -c` / `eval` it carries.
    None if unreadable or nested deeper than `depth` (fail-closed at the caller)."""
    seen, todo, out = set(), [cmd], []
    for _ in range(depth):
        nxt = []
        for c in todo:
            n = normalise(c)
            if n not in seen:
                seen.add(n)
                out.append(n)
            inner = envelopes(c)
            if inner is None:
                return None
            nxt.extend(x for x in inner if x.strip())
        todo = nxt
        if not todo:
            break
    return None if todo else out


def host_authorization(command):
    """(True, entry) IFF the HOST authorized THIS exact command, unexpired. Fail-closed."""
    sha = hashlib.sha256(command.strip().encode("utf-8")).hexdigest()
    try:
        if not os.path.isfile(AUTH_FILE):
            return False, None
        now = datetime.now(timezone.utc)
        with open(AUTH_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                except Exception:
                    continue
                if not isinstance(e, dict) or e.get("command_sha256") != sha:
                    continue
                exp = e.get("expires_at")
                if exp:
                    try:
                        if datetime.fromisoformat(exp.replace("Z", "+00:00")) < now:
                            continue
                    except Exception:
                        continue
                return True, e
    except Exception:
        return False, None
    return False, None


def gate_fingerprint_ok():
    ref = os.environ.get("PI_GATE_SHA")
    if not (ref and os.path.isfile(ref)):
        return True  # nothing to compare: we do not pretend
    try:
        expected = open(ref, encoding="utf-8").read().split()[0].strip()
        h = hashlib.sha256()
        with open(GATE, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
        return h.hexdigest() == expected
    except Exception:
        return False


def unreadable(d):
    if not isinstance(d, dict):
        return "the hook context is not a JSON object"
    if "_pi_hooks_truncated" in d:
        return "the hook context was truncated"
    a = d.get("tool_args") or d.get("toolArgs")
    if not isinstance(a, dict):
        return "the tool arguments are not an object"
    if "_pi_hooks_tool_args_truncated" in a:
        return "the tool arguments were truncated"
    if not isinstance(a.get("command"), str):
        return "no command in the tool arguments"
    return ""


def main():
    if not gate_fingerprint_ok():
        sys.stderr.write("BLOCKED [bash-boundary] the gate CHANGED since the reference was taken:\n"
                         "   everything is blocked until a human looks.\n")
        verdict("refused-gate-changed", 2)
    raw = sys.stdin.read()
    try:
        d = json.loads(raw or "{}")
    except Exception:
        d = None
    why = unreadable(d)
    if why:
        sys.stderr.write("BLOCKED [bash-boundary] cannot read this command (%s).\n"
                         "   If it is too long to be judged, write the file with the write tool,\n"
                         "   then run the command on its own.\n" % why)
        verdict("refused-unreadable", 2, "", why)
    command = (d.get("tool_args") or d.get("toolArgs"))["command"]
    seen = normalise(command)

    reason = computed_verb(command)
    if reason:
        sys.stderr.write("BLOCKED [bash-boundary] %s.\n   Write the verb plainly (no $(...), no backticks, no eval).\n" % reason)
        verdict("refused-computed-verb", 2, command, reason)

    ok, auth = host_authorization(seen)
    if ok:
        sys.stderr.write("[bash-boundary] host authorization found for this exact command (%s): allowed\n"
                         % (auth.get("by") or "host"))
        verdict("allowed-host-authorization", 0, command, auth.get("by") or "")

    forms = forms_to_judge(command)
    if forms is None:
        sys.stderr.write("BLOCKED [bash-boundary] this command cannot be analysed (nested shell\n"
                         "   or unclosed quotes). Write it as simple steps, one per call.\n")
        verdict("refused-unanalysable", 2, command)
    forms = [TAG.sub(" ", f) for f in forms]

    env = {k: os.environ[k] for k in CLOSED_ENV if k in os.environ}
    r = None
    for form in forms:
        try:
            r = subprocess.run(["/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable,
                                "-I", GATE],
                               input=json.dumps({"tool_name": "Bash", "tool_input": {"command": form}}),
                               capture_output=True, text=True, timeout=20, env=env)
        except Exception as exc:
            sys.stderr.write("BLOCKED [bash-boundary] the bridge to the gate failed (%s): fail-closed\n" % exc)
            verdict("refused-gate-failure", 2, command, str(exc))
        if r.returncode != 0:
            break
    trace = os.environ.get("PI_BOUNDARY_TRACE")
    if trace:
        try:
            with open(trace, "a", encoding="utf-8") as f:
                f.write(json.dumps({"command": command[:200], "normalised": seen[:200],
                                    "gate_rc": r.returncode, "stderr": r.stderr[:300]}) + "\n")
        except Exception:
            pass
    if r.returncode != 0:
        # Never show the tag syntax: a refusal that teaches its bypass is not a refusal.
        sys.stderr.write("BLOCKED [bash-boundary] this command is destructive or privileged.\n"
                         "   You cannot authorize yourself: the authorization comes from a human,\n"
                         "   outside this agent. Tell the person WHAT you want to do and WHY,\n"
                         "   and wait for their decision.\n")
        verdict("refused-by-gate", 2, command, (r.stderr or "")[:200])
    verdict("allowed", 0, command)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001  any crash must be exit 2, never 1
        sys.stderr.write("BLOCKED [bash-boundary] internal failure (%s): fail-closed\n" % type(exc).__name__)
        sys.exit(2)
