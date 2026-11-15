# The Pi adapter

`adapters/pi/` wires the integrity layer into [Pi](install-pi.md) through pi-yaml-hooks.
Pi runs unattended, so the guard is the last wall: every guard refuses when it cannot
decide, and a patch makes the host itself refuse when a guard dies.

This page is the map. Each guard has its own page under `docs/gates/`; each claim below
names the test that proves it (the tests are in `tests/test_pi_*.py`).

## Install

Follow [install-pi.md](install-pi.md): copy the repository where the agent cannot write,
read the guards, run the tests, set the environment, wire
[`hooks.example.yaml`](../adapters/pi/hooks.example.yaml), apply the fail-closed patch, then
check that a forbidden gesture is refused. There is no installer, on purpose.

The example wires three guards on three events. pi-yaml-hooks has no wildcard, so the
write guard sits on both writing tools (`write` and `edit`), and every hook runs under
`python3 -I` so the agent cannot plant a module the guard would import
(`test_example_wires_guards_that_ship_under_isolated_python`).

## What each guard does under Pi

| Guard | Event | What it does | Proved by |
|:--|:--|:--|:--|
| [bash boundary](gates/pi-bash-boundary.md) | `tool.before.bash` | Translates the Pi payload and pipes it to the one shared destructive-command gate (`adapters/claude-code/hooks/destructive-command-gate.py`); the gate's exit code and message come back untouched. | `test_destructive_blocked`, `test_plain_command_allowed` |
| | | A prefix, an absolute path or a nested shell (`bash -c`, `eval`) does not hide the verb. | `test_prefix_and_absolute_path_do_not_hide_the_verb`, `test_nested_shell_is_judged` |
| | | A computed verb is refused; an expansion in an argument is not. | `test_computed_verb_blocked`, `test_argument_expansion_allowed` |
| | | The agent cannot authorize itself: the authorization tag is stripped and never shown, the gate's kill switch in the environment is ignored, and a host authorization holds for one exact command only. | `test_tag_is_stripped_and_never_taught`, `test_kill_switch_in_env_is_ignored`, `test_host_authorization_binds_to_exact_command` |
| | | A changed gate file blocks everything, when `PI_GATE_SHA` is set. | `test_changed_gate_blocks_everything` |
| | | Unreadable or truncated context is refused. | `test_unreadable_or_truncated_context_fails_closed` |
| [write guard](gates/pi-write-guard.md) | `tool.before.write`, `tool.before.edit` | Allows a write only inside `PI_WORKSHOP` (and `PI_JOURNAL`), decided on the resolved path, so a symlink does not lead out. | `test_inside_workshop_allowed`, `test_outside_blocked`, `test_symlink_into_gates_blocked` |
| | | Unreadable or truncated context is refused. | `test_unreadable_context_fails_closed`, `test_truncated_context_fails_closed` |
| [install guard](gates/pi-install-guard.md) | `tool.before.bash` | Finds a package install inside chains and nested shells; a line without an install costs no network call. | `test_hidden_in_nesting_and_chains_is_still_found`, `test_line_without_install_passes_with_no_network` |
| | | Refuses a package listed in the malicious-package base before any registry call. | `test_listed_malicious_package_is_refused_before_any_registry_call` |
| | | Holds what it cannot judge: a computed name, an unreadable base. | `test_computed_name_is_held`, `test_unreadable_base_holds_every_install` |
| [fail-closed patch](gates/pi-fail-closed.md) | (patches the host) | Makes pi-yaml-hooks block a `tool.before.*` call when its hook times out, is killed or fails. Four pinned replacements; a file that is not the pinned original is refused, never guessed. | `test_list_names_four_pinned_sites`, `test_apply_refuses_a_file_that_is_not_the_pinned_original`, `test_check_on_empty_dir_is_neither_patched_nor_original` |

The tool-call helper (`adapters/pi/extension/tool-call.mjs`) is not a guard: it calls one
tool of a Pi extension the way Pi does, with no model turn, to test an extension's
decisions. Its suite is `tests/pi-tool-call.test.mjs` (`test_tool_call_helper_suite` runs
it when Node is installed).

Why the destructive rules live in one place and the Pi guard only wraps them:
[ARCHITECTURE.md](../ARCHITECTURE.md), "Pi adapter".

## Known limits

- **No shell parser.** The bash boundary does not unwrap heredocs or substitutions inside
  quotes (stated in the header of `adapters/pi/hooks/bash-boundary.py` and in
  [its page](gates/pi-bash-boundary.md)).
- **The gate fingerprint is optional.** Without a `PI_GATE_SHA` file nothing is compared
  (`gate_fingerprint_ok` in `bash-boundary.py`).
- **Only these package managers are judged**: npm, pnpm, yarn, pip, uv, poetry, cargo, pipx,
  and their runners npx, pnpx, uvx (`adapters/pi/hooks/install-guard.py`). An install by
  another tool (`gem`, `apt-get`) passes the install guard unseen.
- **The shipped malicious-package base is a sample for tests.** With it nothing real is
  refused; generate the full base (step 5 of [install-pi.md](install-pi.md)).
- **Only `bash`, `write` and `edit` are wired.** A tool added by an extension is not
  guarded until you add its own `tool.before.<tool>` entry.
- **Without the fail-closed patch, a dead guard lets the call through.** The patch pins
  pi-yaml-hooks 2026.8.11 and refuses any other version (header of
  `adapters/pi/hooks/fail-closed.py`).

## Prove it on your copy

One offline command, standard library only, no network, no model:

```
python3 -m unittest discover -s tests -p 'test_pi_*.py'
```

It runs the four guard suites and `tests/test_pi_adapter.py`, which checks this page: the
example wires guards that ship, every guard keeps its page and its test, every test named
here exists, and no relative link of `README.md` or `docs/` is broken.
