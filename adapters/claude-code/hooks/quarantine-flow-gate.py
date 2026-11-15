#!/usr/bin/env python3
"""PreToolUse gate on Bash: the PARENT agent does not send to the network what
only the Quarantine reader said.

WHY (brief 72, point 5, "effects after reading"; no incident behind it): the
reader has no hands (agents/researcher.example.md and quarantine-reader-gate.py),
so an injected page can only act through the parent, by getting the parent to
copy a URL, a host or a piece of text from the reader's report into a shell
command that leaves the machine. This gate is a CaMeL-lite taint check on
strings, done on the parent's own Bash call.

Design:
- Untrusted text, read from the parent's transcript (`transcript_path`):
  the results of the parent's Agent/Task calls whose `subagent_type` is the
  reader (case and surrounding spaces ignored); the report of a reader run in
  the background, which comes back as a user line typed by no one (an `origin`
  key, e.g. `task-notification`; its `<tool-use-id>` says whose report it is,
  and a line without one counts as the reader's); and any compaction summary,
  which stands in for the lines it replaced, the reader's included.
- Trusted text: what a human typed, i.e. the parent transcript's user
  messages that are not tool results, meta lines, compaction summaries or
  lines with an `origin`.
- Tainted: a host, or a run of 24 characters or more (whitespace runs folded
  to one space, case ignored), found in the untrusted text and NOT in the
  human's text.
- Network-bound command: it names a network tool, a URL scheme, /dev/tcp or
  /dev/udp, or an interpreter's network module (list below, over-inclusive on
  purpose: a wrong "network" only matters when the command is also tainted).
- Verdicts:
    network-bound AND tainted (host or 24-char run)  -> REFUSED (exit 2)
    local AND tainted                                -> FLAGGED: journal line
                                                        and a stderr note, exit 0
    otherwise                                        -> pass
  Brief 72 says the 24-char run is "flagged"; this gate refuses it when the
  command can send it out, because a flag does not stop the leak, and only
  flags it when the command stays local (a file name or a title copied into
  grep or a note is the ordinary case, not a leak).
- Sub-agent calls (`agent_id` present) pass: the reader's Bash is refused by
  quarantine-reader-gate.py, other sub-agents are out of this gate's scope.
- Unknown id (fail-closed): a background report whose `<tool-use-id>` names no
  tool call left in the transcript (the call went in a compaction) counts as the
  reader's; the journal line says `unknown-id`.
- Two steps, closed for the shell: a local command that carries tainted text and
  writes it to a file by redirect or `tee` records that file name, per session,
  in the state dir; a later network-bound command naming that file is REFUSED
  (`curl -d @notes.md ...`, `scp notes.md ...`), even when a compaction left
  nothing of the reader. A local command naming a recorded file and writing by
  redirect or `tee` records its target too (`cat notes.md > b.md`).
- A malformed entry is REFUSED (fail-closed, unlike most gates here): payload
  that is not a JSON object, a Bash call without a string command or without
  a session id, or no readable transcript (the gate cannot tell what the reader said).

What this gate does NOT cover:
- A leak in two steps by any other road than a shell redirect or `tee`: a Write
  tool call, `cp`/`mv` of a tainted file (`cp notes.md d.md`, then `d.md` sent),
  an interpreter writing the file, or a `git push` of a tainted commit carry no
  file name this gate recorded; nor does an upload naming the file by a glob
  (`curl -d @note?.md`) or by a variable built from parts (`f=notes; curl -d
  @$f.md`); a variable holding the whole name (`f=notes.md; curl -d @$f`) is
  seen. The flagged journal line is the trace. shortcut: file names written by
  `>`/`tee` and matched as typed, lift it when the Write tool gets a PostToolUse
  taint hook (copies, interpreters) and when the flagged journal shows a glob
  or variable upload (expand them against the recorded names then).
- Text the reader's output was turned into: encoded, translated, cut under 24
  characters, or rewritten by the parent.
- After a compaction, the summary is all the gate has of the lines it replaced:
  a host or run the summary dropped is not seen, and one it kept is refused
  on a network command even when the human had typed it before, until the
  human types it again.

The refusal never quotes the tainted piece: this line is read back by the
agent, and quoting it would hand the injection back.

WORKAROUND to hand the agent: ask the human. A host or text the human types in
the conversation is trusted from then on.

Environment:
- QUARANTINE_READER  the reader's agent name (default: researcher)
No disarm variable: to retire the gate, unwire it from the settings.

Exit codes: 0 pass or flagged, 2 BLOCK.
"""
import json
import os
import re
import sys

try:  # before anything taps stdin: an undecodable byte must not raise in read()
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, os.pardir, "core", "common"))
from _transcript import load_transcript
try:
    from _hook import gate_stat, STATE_DIR
except Exception:
    STATE_DIR = os.environ.get("HARNESS_STATE_DIR") or os.path.join(os.path.expanduser("~"), ".harness")

    def gate_stat(*a, **kw):  # no helper, no journal: the verdict does not depend on it
        pass

HOOK = "quarantine-flow"
RUN = 24
READER = (os.environ.get("QUARANTINE_READER") or "").strip().casefold() or "researcher"
URL_HOST = re.compile(r"[a-z][a-z0-9+.-]{0,15}://(?:[^\s/@'\"]*@)?\[?([^\s/:'\"?#\[\]]+)", re.I)
TOOL_USE_ID = re.compile(r"<tool-use-id>\s*([^<\s]+)\s*</tool-use-id>")
BARE_HOST = re.compile(r"(?<![\w-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![\w-])", re.I)
# shortcut: a word list, so a network tool missing from it makes a tainted
# command look local (flagged, not refused); turn it into an allow-list of local
# commands if the flagged journal shows misses.
NETWORK = re.compile(
    r"(?:^|[\s;&|(`'\"/=])(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|tftp|telnet|http|https|xh"
    r"|aria2c|lynx|w3m|links|elinks|dig|nslookup|host|ping|ping6|traceroute|whois|openssl|gh|mail|mailx"
    r"|sendmail|mutt|swaks|smbclient|ldapsearch|mosquitto_pub|redis-cli|psql|mysql|mongosh)(?=$|[\s;&|)`'\"])"
    r"|(?:^|[\s;&|(])git\s+(?:\S+\s+)*?(?:push|clone|fetch|pull|ls-remote|send-email)\b"
    r"|://|/dev/(?:tcp|udp)/"
    r"|urllib|requests\.|http\.client|httpx|aiohttp|socket|fetch\(|XMLHttpRequest|Net::HTTP|LWP|IO::Socket",
    re.I)


def fold(text: str) -> str:
    return re.sub(r"\s+", " ", text).casefold()


def hosts(text: str) -> set:
    found = {m.group(1) for m in URL_HOST.finditer(text)} | {m.group(1) for m in BARE_HOST.finditer(text)}
    return {h.casefold().strip(".") for h in found if "." in h}


def block_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and isinstance(b.get("text"), str))
    return ""


def split_transcript(events):
    """(untrusted text, human text) of the parent's transcript."""
    reader_ids, known_ids, results, notes, untrusted, human = set(), set(), {}, [], [], []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        msg = ev.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        blocks = content if isinstance(content, list) else []
        for b in blocks:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "tool_use":
                known_ids.add(b.get("id"))
            if b.get("type") == "tool_use" and b.get("name") in ("Agent", "Task"):
                kind = (b.get("input") or {}).get("subagent_type") if isinstance(b.get("input"), dict) else None
                if isinstance(kind, str) and kind.strip().casefold() == READER:
                    reader_ids.add(b.get("id"))
            elif b.get("type") == "tool_result":
                results[b.get("tool_use_id")] = block_text(b.get("content"))
        if ev.get("type") != "user":
            continue
        if ev.get("isCompactSummary"):
            untrusted.append(block_text(content))
        elif ev.get("isMeta"):
            continue
        elif ev.get("origin") is not None:
            text = block_text(content)
            m = TOOL_USE_ID.search(text.split("<result>", 1)[0])   # an id inside the report is the page's, not ours
            notes.append((m.group(1) if m else None, text))
        else:
            if isinstance(content, str):
                human.append(content)
            else:
                human.extend(b["text"] for b in blocks if isinstance(b, dict) and b.get("type") == "text"
                             and isinstance(b.get("text"), str))
    untrusted += [results.get(i, "") for i in reader_ids]
    unknown = any(i is not None and i not in known_ids for i, _ in notes)
    untrusted += [text for i, text in notes if i is None or i in reader_ids or i not in known_ids]
    return "\n".join(untrusted), "\n".join(human), unknown


def tainted_run(command: str, reader: str, human: str) -> bool:
    """A run of RUN characters of the command found in the reader's text and
    not in the human's. Windows of the (short) command in a set, one pass over
    each text: linear, not command x reader."""
    cmd, reader, human = fold(command), fold(reader), fold(human)
    wins = {cmd[i:i + RUN] for i in range(len(cmd) - RUN + 1)}
    if not wins:
        return False
    in_reader = {w for w in (reader[j:j + RUN] for j in range(len(reader) - RUN + 1)) if w in wins}
    if not in_reader:
        return False
    in_human = {w for w in (human[j:j + RUN] for j in range(len(human) - RUN + 1)) if w in in_reader}
    return bool(in_reader - in_human)


def tainted_host(command: str, reader: str, human: str) -> bool:
    reader_only = hosts(reader) - hosts(human)
    return any(h == r or h.endswith("." + r) for h in hosts(command) for r in reader_only)


WRITE_TARGET = re.compile(r"(?:\d?>>?|\btee(?:\s+-\w+)*)\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s;&|<>()]+))")


def taint_file(session: str) -> str:
    return os.path.join(STATE_DIR, "quarantine-flow-" + re.sub(r"[^\w.-]", "_", session) + ".txt")


def written_files(command: str) -> set:
    return {next(g for g in m.groups() if g) for m in WRITE_TARGET.finditer(command)
            if any(m.groups())} - {"/dev/null"}


def names_tainted_file(command: str, session: str) -> bool:
    try:
        with open(taint_file(session), encoding="utf-8") as f:
            names = {l.rstrip("\n") for l in f if l.strip()}
    except FileNotFoundError:
        return False
    except (OSError, ValueError):  # there but unreadable: what it holds is unknown, so fail closed
        block("file-memory", "this command is refused because the gate cannot read its file memory")
    return any(n in command or os.path.basename(n) in command for n in names)  # substring: names may hold spaces


def remember_files(command: str, session: str):
    names = written_files(command)
    if names:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(taint_file(session), "a", encoding="utf-8") as f:
                f.write("".join(n + "\n" for n in names))
        except OSError:
            pass  # shortcut: a state dir we cannot write loses the file memory, the flag line stays


def block(why: str, what: str):
    """Exit 2. `what` is our own text, never a piece of the payload."""
    gate_stat(HOOK, "block", why=why)
    try:
        sys.stderr.write(
            f"BLOCKED (quarantine-flow gate): {what}. Ask the human to type the "
            "host or text in the conversation if it must go out.\n")
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
        block("unreadable", "a tool call this gate cannot read is refused")
    if data.get("tool_name") != "Bash" or "agent_id" in data:
        gate_stat(HOOK, "skip")
        sys.exit(0)
    command = data.get("tool_input", {}).get("command") if isinstance(data.get("tool_input"), dict) else None
    if not isinstance(command, str):
        block("no-command", "a Bash call without a command string is refused")
    session = data.get("session_id")
    if not isinstance(session, str) or not session.strip():
        block("no-session", "a Bash call without a session id is refused")
    path = data.get("transcript_path")
    if not isinstance(path, str) or not os.path.isfile(path):
        block("no-transcript", "a Bash call is refused when the gate cannot read the transcript")
    reader, human, unknown = split_transcript(load_transcript(path, limit=0))
    # No early exit on an empty reader: a compaction can drop it, the file memory outlives it.
    host, run = tainted_host(command, reader, human), tainted_run(command, reader, human)
    net = NETWORK.search(command)
    named = not (host or run) and (net or written_files(command)) and names_tainted_file(command, session)
    if net and named:
        block("file", "this command can reach the network and names a file that earlier carried text "
                      "seen only in the reader's output")
    if (host or run) and net:
        block(("host" if host else "run") + ("+unknown-id" if unknown else ""),
              "this command can reach the network and carries "
              + ("a host" if host else f"a run of {RUN}+ characters")
              + " seen only in the reader's output, never typed by the human")
    if host or run or named:   # named: a copy by `>`/`tee` of a recorded file is recorded too
        remember_files(command, session)
        gate_stat(HOOK, "flag", why=("host" if host else "run" if run else "file") + ("+unknown-id" if unknown else ""))
        sys.stderr.write("NOTE (quarantine-flow gate): this local command carries text seen only in the "
                         "reader's output" + ("" if host or run else ", by a file that held it") + ".\n")
        sys.exit(0)
    gate_stat(HOOK, "pass")
    sys.exit(0)


if __name__ == "__main__":
    main()
