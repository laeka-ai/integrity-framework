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
