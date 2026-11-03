# pi-bash-boundary

`adapters/pi/hooks/bash-boundary.py`, hook on `tool.before.bash` of an unattended Pi
agent (pi-yaml-hooks). Exit 2 = block, and every failure of the script exits 2.

## What it does

It translates the pi-yaml-hooks payload (`tool_args.command`) into the Claude Code payload
and pipes it to the one shared gate, `adapters/claude-code/hooks/destructive-command-gate.py`,
unmodified. The gate's exit code and stderr come back as they are. There is no second copy
of the rules.

## Why a harder mode than Claude Code

With Claude Code the gate is a drift net: a classifier and a human stand behind it. An
unattended agent has neither, so three escape hatches built for a human are closed:

1. The authorization tag inside the command is stripped from every form sent to the gate,
   and the refusal never shows its syntax. The only authorization that counts is a
   host-side JSON-lines file mounted read-only (`PI_HOST_AUTHORIZATIONS`), each entry bound
   to the sha256 of the exact command and carrying an expiry.
2. The kill switch and tuning variables of the gate are unreachable: it runs under
   `python3 -I` with a closed environment (PATH, HOME, LANG, LC_ALL).
3. Prefixes (`FOO=1 rm`, `env rm`, `/bin/rm`, `"rm"`) are normalised before the gate sees
   the command. `bash -c "..."` and `eval "..."` contents (3 levels) are submitted too.

Also refused: a computed verb (`$(printf rm)`, backticks, `$X`), truncated or unreadable
context, and a gate file whose sha256 differs from the reference (`PI_GATE_SHA`), checked
on every call.

## Limit, kept on purpose

No shell parser unwraps heredocs or substitutions inside quotes. A gate that has one is
stronger; this one says it does not.

## Test

`tests/test_pi_bash_boundary.py` (stdlib only).
