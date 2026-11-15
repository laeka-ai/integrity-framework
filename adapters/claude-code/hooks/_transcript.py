"""_transcript.py: read a Claude Code session transcript (JSONL events).

Host-specific on purpose: the event layout belongs to Claude Code, so it lives
in the adapter, not in core/common.
"""
import json
import os


def load_transcript(path, limit=400):
    """Returns the list of JSONL events (last `limit`). [] when unreadable."""
    if not path or not os.path.isfile(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out[-limit:] if limit else out


def assistant_text_blocks(ev):
    """Concatenate the text (type=text blocks) of one assistant event."""
    msg = ev.get("message", {})
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "")
            for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        )
    return ""


_KIND = {"Bash": "command", "Read": "read", "Grep": "read",
         "Write": "write", "Edit": "write", "MultiEdit": "write", "NotebookEdit": "write",
         "WebFetch": "fetch", "WebSearch": "search"}


def _result_text(block):
    content = block.get("content")
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict))
    return content if isinstance(content, str) else ""


def tool_events(events):
    """Map the tool_use / tool_result pairs of a transcript to the host-neutral
    shape core/canary reads: [{kind, target, output}], in call order."""
    calls, outputs = [], {}
    for ev in events:
        msg = ev.get("message") if isinstance(ev, dict) else None
        content = msg.get("content") if isinstance(msg, dict) else None
        for b in content if isinstance(content, list) else []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "tool_use":
                calls.append(b)
            elif b.get("type") == "tool_result":
                outputs[b.get("tool_use_id")] = _result_text(b)
    out = []
    for b in calls:
        name, inp = b.get("name", ""), b.get("input") or {}
        kind = _KIND.get(name, "other")
        if kind == "command":
            target = inp.get("command", "")
        elif kind in ("fetch", "search"):
            target = inp.get("url") or inp.get("query") or ""
        elif kind == "other":
            target = name + " " + json.dumps(inp, ensure_ascii=False)[:500]
        else:
            target = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""
        out.append({"kind": kind, "target": str(target), "output": outputs.get(b.get("id"), "")})
    return out
