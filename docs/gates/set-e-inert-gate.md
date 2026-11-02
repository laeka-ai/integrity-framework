# set-e-inert-gate

PreToolUse gate on `Bash`. Exit 2 = block, fail-open everywhere, every execution logs one line to the
gate-stats journal (`pass`, `block`, `not-first`, `unparsable`, `fail-open`, `skip-disabled`).

## What it blocks

A command whose FIRST instruction arms errexit: `set -e`, `set -eu`, `set -euo pipefail`, `set -Ee`,
`set -o errexit`.

It does not block a `set -e` that is not first (`ls && set -e`; journaled as `not-first`), nor one inside a
heredoc body or a real script (`bash <<'EOF'`, `bash script.sh`): those run in their own process, where
`set -e` works.

## Why

Inside the agent's Bash tool, `set -e` stops nothing:

    set -e; false; echo AFTER        -> prints AFTER
    bash -ec 'false; echo AFTER'     -> stops, rc=1

A chain like `set -euo pipefail; git checkout -b x; generate; git commit` goes on after the failed checkout and
commits on the wrong branch. The command believes it is protected, which is what makes it dangerous.

The block message hands over the alternative: chain with `&&`, or wrap in `bash -euo pipefail -c '...'`.

## Re-check on every host update

Replay `set -e; false; echo AFTER` in the real Bash tool. If it stops, `set -e` works again and this gate must
be disarmed: it would block valid commands.

## Disarm

One session: `HARNESS_SET_E_INERT_GATE_DISABLE=1`. Tests: `tests/test_set_e_inert_gate.py`.
