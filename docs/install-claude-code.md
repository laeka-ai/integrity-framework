# Install on Claude Code (manual, step by step)

There is no installer on purpose: you copy, read, then wire. A human or an agent
can follow every step; each one ends with a check.

Requirements: Python 3.10 or newer, Claude Code, a shell.

1. **Copy the repository** to a stable place, for example `~/integrity-framework`
   (`git clone <repository-url> ~/integrity-framework`). Export the location:
   `export HARNESS_HOME=~/integrity-framework`.
2. **Read what you are about to run.** Each gate is one file under `core/gates/`
   with its page under `docs/gates/`. Remove from step 4 the ones you do not want.
3. **Run the tests** to prove your copy is intact:
   `python3 -m pip install pytest && python3 -m pytest tests -q`.
   Expected: all green, no network.
4. **Copy the settings example** `adapters/claude-code/launchers/settings.example.json`
   to a scratch file and open it. It lists, per event, the commands to run, in the form
   `python3 $HARNESS_HOME/core/gates/<gate>.py`. Keep the entries you chose in step 2.
5. **Merge the `hooks` block** into your Claude Code `settings.json`
   (`~/.claude/settings.json` for all projects, or `.claude/settings.json` in one
   project). If you already have a `hooks` block, add the entries to the same event
   arrays; do not replace yours. Replace `$HARNESS_HOME` by the absolute path if your
   shell does not expand it inside Claude Code.
6. **Check one gate bites**, without Claude Code:
   `echo '{"tool_name":"Bash","tool_input":{"command":"sudo systemctl restart nginx"}}' | python3 $HARNESS_HOME/core/gates/destructive-command-gate.py; echo "exit=$?"`
   Expected: a refusal text on stderr and `exit=2`.
7. **Restart Claude Code** and ask it to run a command the gate refuses. It must be
   refused with the alternative named. The journal gets one line per execution
   under `$HARNESS_STATE_DIR` (default `~/.harness`).
8. **Optional**: the units in `adapters/claude-code/launchers/systemd/` (audit,
   recall refresh, sentinel) are examples with explicit paths. Edit, then enable them
   yourself. The panels are under `tools/` (`docs/mission-control.md`, `docs/watch.md`).

To undo: remove the entries you added in step 5. Nothing else was installed.
