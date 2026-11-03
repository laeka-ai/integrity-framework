# Install on Pi (manual, step by step)

There is no installer on purpose: you copy, read, then wire. Each step ends with a check.

Requirements: Python 3.10 or newer, a Pi agent with pi-yaml-hooks 2026.8.11
(the version the fail-closed patch pins), a shell. Node 20 only for the optional tool-call helper.

1. **Copy the repository** to a place the agent can read but NOT write, for example
   `/opt/pi-guard` (`git clone <repository-url> /opt/pi-guard`). A guard the agent can
   rewrite is not a guard.
2. **Read what you will run.** The guards are under `adapters/pi/hooks/`, one page each in
   `docs/gates/pi-*.md`. The bash boundary sends the command to the shared gate in
   `adapters/claude-code/hooks/destructive-command-gate.py`, which must therefore be copied too
   (copy the whole `adapters/` and `core/` trees).
3. **Run the tests** on your copy: `python3 -m pytest tests -q -k pi`. Expected: all green, no network.
4. **Set the environment** the guards read: `PI_WORKSHOP` (the only place the agent may write),
   `PI_JOURNAL`, `PI_HOST_AUTHORIZATIONS` (read-only JSON lines, empty at first),
   `PI_GATE_SHA` (a file holding the sha256 of the shared gate, optional but recommended),
   `INSTALL_GUARD_CONFIG` (copy `adapters/pi/hooks/install-guard.example.json`).
5. **Get the full malicious-package base**: `python3 adapters/pi/hooks/regenerate-malicious-packages.py`
   (see its header), and set `malicious_file` in your install-guard config. The 5-row sample
   is for tests only: with it, nothing real is refused.
6. **Wire the hooks.** Copy `adapters/pi/hooks.example.yaml` into your pi-yaml-hooks
   configuration, replace `/opt/pi-guard` by your path, keep the entries you chose in step 2.
   Hooks run under `python3 -I`; keep that.
7. **Apply the fail-closed patch** (without it a timeout or a killed guard lets the call through):
   `python3 adapters/pi/hooks/fail-closed.py apply <pi-yaml-hooks dir> /tmp/patched`, read the
   four files, copy them over the originals, then `... check <pi-yaml-hooks dir>` must exit 0.
8. **Check a forbidden gesture is refused**, without Pi:
   `echo '{"tool_args":{"command":"rm -rf /work/x/proj"}}' | python3 -I adapters/pi/hooks/bash-boundary.py; echo "exit=$?"`
   Expected: a refusal on stderr and `exit=2`. Then start Pi and ask the agent to run it: it must
   be refused. Same for a write outside `PI_WORKSHOP`.
9. **Optional**: `adapters/pi/extension/tool-call.mjs` calls one tool of a Pi extension the way Pi
   does, with no model turn (`node tool-call.mjs <pi-dir> <extension.ts> <tool> '<params JSON>'`),
   to test an extension's decisions. Tested by `node --test tests/pi-tool-call.test.mjs`.

To undo: remove the hook entries of step 6 and restore the original pi-yaml-hooks files.
