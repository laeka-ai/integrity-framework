# pi-fail-closed

`adapters/pi/hooks/fail-closed.py`: a patch of pi-yaml-hooks 2026.8.11, kept as data.

## Why

pi-yaml-hooks blocks a tool call only when a `tool.before.*` hook exits 2. Every other end
lets the call through: a timeout, exit 1, a hook killed by a signal, an evaluation that
throws, a call without a session id. An agent that kills its own guard process (same uid)
sees its command pass.

## What it does

Four exact text replacements in the published dist so that, for `tool.before.*` only, any
end other than exit 0 blocks. Each original file must have its pinned sha256, each old text
must occur once, each patched file must come out at its pinned sha256: a different upstream
file is a refusal, never a guess.

```
fail-closed.py apply <pi-yaml-hooks dir> <out dir>   write the 4 patched files under <out dir>
fail-closed.py check <pi-yaml-hooks dir>             rc 0 patched, 1 originals, 2 otherwise
fail-closed.py list                                  relative paths and both pins
```

The source directory is never modified; you copy the patched files yourself after reading them.

## Test

`tests/test_pi_fail_closed.py` (stdlib only).
