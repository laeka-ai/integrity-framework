# pi-write-guard

`adapters/pi/hooks/write-guard.py`, hook on `tool.before.write` and `tool.before.edit`.
Exit 2 = block; unreadable input, a missing path or any failure also gives 2.

## What it blocks

Any write whose RESOLVED path is outside the workshop (`PI_WORKSHOP`) and the optional
journal directory (`PI_JOURNAL`). Writing is the agent's job; writing anywhere else is not.
Without it, a hook that covers only `tool.before.bash` leaves the agent free to rewrite its
own gate or launcher with the write tool.

## Why `realpath`, not a prefix check

```
ln -s /agent/gates/bash-boundary.py /agent/workshop/x.css
write /agent/workshop/x.css      <- the requested path is inside the workshop
```

`ln -s` is neither destructive nor privileged, so the bash gate lets it pass; the write
then follows the link onto the gate. The guard decides on `os.path.realpath` (links
followed at every component, also when the target does not exist yet), and the workshop is
resolved the same way.

## Test

`tests/test_pi_write_guard.py` (stdlib only), including the symlink case.
