"""adapters.py -- map other agent frameworks' recorded traces to the
host-neutral tool events core/canary reads: [{kind, target, output}].

No import of the frameworks: the input is the plain data their run already
returns, so the example needs no install and no paid call.

  from_langgraph(messages)  messages of a LangGraph run (dicts, or LangChain
                            message objects): AI messages carry `tool_calls`
                            [{id, name, args}], tool messages carry
                            `tool_call_id` and `content`.
  from_crewai(steps)        [{tool, tool_input, result}] (CrewAI step_callback
                            / task tool-usage log).

shortcut: tool names map by a fixed table (_KIND); an unknown tool is kind
"other", so doctrine rules see commands and file paths only for known tools.
Add the tool to _KIND when you wire a new one.
"""
import json

_KIND = {"bash": "command", "shell": "command", "terminal": "command", "run_command": "command",
         "read_file": "read", "file_read_tool": "read", "file_read": "read",
         "write_file": "write", "file_writer_tool": "write", "file_write": "write"}


def _get(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def _event(name, args, output):
    args = args if isinstance(args, dict) else {"input": args}
    kind = _KIND.get(str(name).lower(), "other")
    if kind == "other":
        target = "%s %s" % (name, json.dumps(args, ensure_ascii=False, default=str)[:500])
    else:
        target = next((str(args[k]) for k in ("command", "cmd", "file_path", "path", "filename", "input")
                       if args.get(k)), "")
    return {"kind": kind, "target": target, "output": str(output or "")}


def from_langgraph(messages):
    calls, outputs = [], {}
    for m in messages:
        for c in _get(m, "tool_calls") or []:
            calls.append((_get(c, "id"), _get(c, "name"), _get(c, "args")))
        if _get(m, "tool_call_id"):
            outputs[_get(m, "tool_call_id")] = _get(m, "content")
    return [_event(n, a, outputs.get(i)) for i, n, a in calls]


def from_crewai(steps):
    return [_event(_get(s, "tool"), _get(s, "tool_input"), _get(s, "result")) for s in steps]
