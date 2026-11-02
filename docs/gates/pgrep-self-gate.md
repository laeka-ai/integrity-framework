# pgrep-self-gate

PreToolUse gate on `Bash`. Repairs or blocks `pgrep -f PATTERN` / `pkill -f PATTERN` when the pattern matches
the command line that carries it. Fail-open everywhere; journal results: `pass`, `repair`, `block`,
`unparsable`, `fail-open`, `skip-disabled`.

## Why

The Bash tool runs `bash -c '<the whole command>'`, so the `pgrep -f` pattern is written in that bash's own
command line and pgrep finds it every time. `while pgrep -f 'tools/bench'; do sleep 30; done` never ends;
`pkill -f` kills its own shell.

## What it does

- Rewrites the pattern with a character class (`'[t]ools/bench'`, which does not match itself) and returns it as
  `updatedInput`. The rewritten command is re-judged before it is returned.
- Blocks, with the alternative in the message, when no safe rewrite exists (`while kill -0 $PID; do sleep 30; done`).
- Lets through: a pattern that already has a class, `pgrep` without `-f`, and a bare listing
  (`pgrep -af X | head`). A listing whose output is discarded, or inside a loop or before `&&` / `||`, is a wait
  and is judged like the rest.

## Known limits

- `shortcut: Python regex, not ERE; on any doubt (unknown variable, POSIX class, invalid regex) the pattern is
  taken as self-matching, upgrade to a real ERE engine if that over-blocks`.
- The repair needs a host that honors PreToolUse `updatedInput` without a permission decision; otherwise only
  the block applies.
- It reuses the command parser of `set-e-inert-gate.py`, so the two files ship together.

## Disarm

One session: `HARNESS_PGREP_SELF_GATE_DISABLE=1`. Tests: `tests/test_pgrep_self_gate.py`.
