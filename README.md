<div align="center">

# Integrity Framework

**by [Laeka](https://laeka.ai)**

### The integrity layer for coding agents: rules that run, not rules that are promised.

*Standard library only. No install step, no dependency to audit.*

[![CI](https://github.com/laeka-ai/integrity-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/laeka-ai/integrity-framework/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-625%20passing-brightgreen.svg)](tests/)
[![Dependencies](https://img.shields.io/badge/dependencies-none-informational.svg)](#why-there-is-no-install-step)

[laeka.ai](https://laeka.ai) · [Quickstart](docs/quickstart.md) · [Install on Claude Code](docs/install-claude-code.md) ·
[Install on Pi](docs/install-pi.md) · [Architecture](ARCHITECTURE.md) · [The gates](docs/gates/) · [Contributing](CONTRIBUTING.md)

</div>

---

## What the integrity layer is

An agent that writes code can also say "done" when it is not, delete what it was
told to keep, or install a package that does not exist. The integrity layer is the
set of small mechanisms that sit **between the agent and the machine** and refuse
those gestures: deterministic gates on what it runs and writes, rules that apply at
the moment of risk, a memory that cannot contradict itself, and a journal that
proves every gate actually ran. It does not make the model smarter. It makes the
model's mistakes cheap, visible and reversible.

**The demo in one sentence:** give the same model the same task with and without the
layer, and only the run with the layer is stopped from the destructive command, the
invented package and the unreal "done", while saying so in the journal.

### Two versions

| Version | Host | Where | Install |
|:--|:--|:--|:--|
| **Claude Code** | A human works in the session; gates are a drift net | `adapters/claude-code/` | [docs/install-claude-code.md](docs/install-claude-code.md) |
| **Pi** | An unattended agent; the gate is the last wall, so it is stricter and fail-closed | `adapters/pi/` | [docs/install-pi.md](docs/install-pi.md) |

Both share one core and the same destructive-command gate; the Pi adapter wraps it
instead of copying it ([ARCHITECTURE.md](ARCHITECTURE.md), "Pi adapter"). What each Pi guard
does, and its known limits: [docs/pi-adapter.md](docs/pi-adapter.md).

---

## The problem

Every team working with a coding agent writes the same document. Always verify
before claiming. Never delete without a backup. Do not rewrite the config on
your own initiative.

It goes in the system prompt, and for a while it works. Then the context gets
long, the task gets interesting, and the rule quietly stops applying. Nothing
errors. Nothing looks wrong. **The agent reports success, and the success is not
real.**

A rule in a prompt is a request. This repository turns the rules that matter
into mechanisms: processes that run outside the model, on files, in plain
Python, with an exit code no turn of phrase can argue with.

<p align="center">
  <img src="docs/media/hero-block.png" alt="A destructive command blocked, the agent taking the reversible path, and both events landing in the journal" width="880">
</p>

Notice the shape of the refusal. It says what was blocked, why, **the working
alternative**, and the documented way out. A gate that only says no teaches an
agent to route around gates, and it takes exactly one of those to poison the
credibility of all the others.

---

## What is in here

Ten modules. Take one, take all of them; a single gate dropped into your own
hooks directory is a legitimate way to use this.

| Module | What it does |
|:--|:--|
| **`adapters/claude-code/hooks/`** | **15 gates** on what the agent runs and writes, plus the shared helper and two stamp CLIs. The memory-verdict gate (statutory memory) is one of them. Each one exists because something went wrong once. |
| **`core/shield/`** | Behavioral rules in **three layers**: injected at the moment of risk, standing format invariants, and a reviewer that judges the outgoing message before it is displayed. |
| **Statutory memory** (`docs/statutory-memory.md`) | **Statutory memory**: a verdict on top, a closed status vocabulary, and an index that carries the state of what it points at. |
| **`core/recall/`** | A catalog that answers **"we already built this"** before an agent rebuilds it, with an executable liveness check per entry. |
| **`core/sentinel/`** | Daily health checks that **discover** what they audit by reading your wiring. Its central check finds gates that are wired but silent. |
| **`core/governor/`** | New rules face **two adversarial judges**, then a seven-day observation trial, before anything gets armed. |
| **`tools/watch/`** | A read-only local panel over gates and sessions, with a post-hoc analyst that proposes and never acts. |
| **`tools/mission-control/`** | A read-only local panel over the **present**: which roles are alive, what is scheduled, and what is waiting on a human. |
| **`adapters/pi/`** | The Pi version: bash boundary, write guard, install guard (OpenSSF base), fail-closed patch, tool-call helper. |
| **`adapters/claude-code/launchers/`** | Wiring templates: example settings per role, a vault pattern, and systemd units that carry the PATH trap's fix. |

### Layer status

Twenty layers are **proven**: each has a receipt on file, taken against a
witness (a deliberate fault the layer has to catch). Eighteen were run in a live
pod; Black Box and Restore were run on a copy (the pod's journal, its backup).
The last column says what the receipt shows, and nothing more. Three receipts
used a scripted provider instead of a real model, and one a stand-in scanner;
their rows say so.

Four of these layers ship in this repository, under `core/`: Promised-Fix
Verifier, Sub-Agent Canary, Quarantine and Skill Guard. The others run on the
pod's host and bridge; they are listed here for what their receipts show.

| Layer | Status | Receipt | What the receipt shows |
|:--|:--|:--|:--|
| Key | proven | 2026-11-13 | A pending delete decision answered with the pod's token alone was refused (HTTP 403), and so was the same answer sent for another pod (HTTP 403); the answer signed by the hardware key was taken (HTTP 200); the key list read after equals the one read before. |
| Governor | proven | 2026-11-13 | An agent's delete-files gesture was held as a pending decision classed delete; the file stayed in place until the test removed it. |
| Canary Camp | proven | 2026-11-06 | With the relay path broken by a firewall rule, a real canary pass read it red; with the path set back, the next pass read it green, with a newer receipt each time. |
| Vault | proven | 2026-11-13 | The pod holds no provider key (0 key file for three providers), and one call on its chat bucket was counted at the vault. |
| Restore | proven | 2026-11-06 | The newest backup of the pod, pulled read-only and 1 h old (limit 48 h), held a readable chat database at the manifest's fingerprint; the same database altered by one byte was refused. |
| Panel | proven | 2026-11-14 | A declined decision closed and nothing ran; a decision nobody clicked stayed pending; approval without the passkey signature was refused. |
| Lenses | proven | 2026-11-13 | The review lenses sent back a defective deliverable at the first loop and passed a clean turn; the send-back is recorded under the witness turn's id. A lens that answers unreadably counts as a send-back, never as absent. |
| Judge | proven | 2026-11-13 | The judge's second opinion on the turn arrived 2 s after the turn's receipt (agree). Another pod's route with this pod's token answered HTTP 403 in an earlier run, not replayed in this one. |
| Self Repair | proven | 2026-11-13 | With the chat service broken in a way the repairer cannot fix, its journal recorded a give-up line after the break; once the service was set back, it recorded the service healthy. |
| Loop | proven | 2026-11-13 | A message to a known contact was held as one send decision, then declined (nothing left the pod); a verdict that would loosen the rules was refused, and the rules file stayed unchanged. |
| Warden | proven | 2026-11-13 | The download door withheld a framework file, a file carrying the framework canary and a zip holding `AGENTS.md`, and served a client file. |
| Library Shield | proven, source ahead | 2026-11-06 | From inside the pod, npm installed a real package and answered E404 for an invented name; the public npm and PyPI registries were unreachable from the pod. pip is absent from the pod, so the pip case was not played. The host installer script has changed since this receipt. |
| Airlock | proven | 2026-11-08 | Scripted provider, not a real model: the agent was handed a `curl` mid-turn; the pass was cut, the 64 KiB it then tried to send reached nothing (0 byte at the target), and the send gesture was held as one decision, declined. |
| Readback | proven | 2026-11-13 | A wrong readback was refused (HTTP 409, nothing written); a right one opened a single signing ceremony, left to expire unsigned; the setting was written back to the byte. |
| Black Box | proven | 2026-11-06 | The passive audit, run on a read-only copy of the pod's journal from a separate host, reported the injected gesture as executed without a decision; nothing was written in the pod. |
| Backstage | proven | 2026-11-06 | The host's daily timer is active and enabled, its last pass ended with rc 0, and the pod's light read critical 0; each pass plants three witnesses and exits 1 if one is not seen. |
| [Sub-Agent Canary](docs/canary-layer.md) | proven | 2026-11-17 | Scripted provider, not a real model: in the pod, an invented sub-agent report (no nonce echo) was refused by the delegator and the honest one passed; the three installed files were at their pinned sha256. |
| [Quarantine](docs/quarantine-layer.md) | proven | 2026-11-17 | In the pod, the real agent read a trapped page through the quarantine door: the injected order was not followed, and a sound page came through intact. |
| [Skill Guard](core/skill_guard/skill-guard.sh) | proven | 2026-11-17 | Stand-in scanner, not SkillSpector: the pod has no SkillSpector, so its stand-in answers NOT_SCANNED to every skill, and the guard refused a trapped skill as unscanned (the skills folder held 0 entries after it); a sound skill, excepted by its fingerprint, was installed. The guard in the pod is an earlier version of the script published here. |
| [Promised-Fix Verifier](docs/promised-fix-verifier.md) | proven | 2026-11-17 | Scripted provider, not a real model: in the pod, with no GREEN probe the gate refused "The checkout bug is fixed."; with a GREEN probe the same sentence passed; the three installed files were at their pinned sha256. |

### The fifteen gates, and the day each one was earned

- a shell command prefixed with `HOME=` returned a **silently false result**
  that got reported as fact
- a regex with unbounded quantifiers **OOM-killed two panes**, on two separate
  days
- renaming a live hook instead of copying it **froze a production session**:
  config is read at boot, and a vanished hook blocks every prompt after
- an LLM judge that could see the answer it was grading returned a **flawless
  verdict** on work that was wrong, and cost real money to produce
- `set -e` at the head of a command **stops nothing** in the agent's shell tool,
  so a chain went on after a failed `git checkout` believing it was protected
- `pgrep -f PATTERN` **finds its own shell** (the pattern is in that shell's
  command line), so a wait loop never ended
- an index line said a name had been relaunched; the real decision, buried in a
  note body, was that the name was taken. **The index won**, and work restarted
  down a dead path

Every gate ships with its founding incident, anonymized but real, in
[`docs/gates/`](docs/gates/).

---

## The load-bearing idea

> **A gate that stays silent cannot be told apart from a gate that is dead.**

So every hook writes one line to a journal on every execution, whatever the
outcome, including the boring ones. A gate that blocks nothing today still
proves it ran. The sentinel cross-checks that journal daily and flags anything
wired but silent, because a dead gate does not scream: it goes quiet, and quiet
reads exactly like a good day.

Everything else follows from that:

**Fail-open, everywhere.** A crashing gate lets the work through and says so. A
harness that can halt the work becomes the thing you disable under pressure, and
a disabled harness protects nothing.

**A kill-switch is allowed, and never silent.** Route around a gate and the
journal records `skip-disabled`. Bypasses are legitimate; invisible ones are not.

**Nothing arms itself.** Cloning this repository changes nothing. Gates run
because a settings file names them, and that file is yours.

---

## Watch: seeing what actually happened

A read-only panel, bound to loopback, over the journal and the session
transcripts. It observes; it never intervenes.

<p align="center">
  <img src="docs/media/watch-dashboard.png" alt="Dashboard: sessions observed, gate events, blocks, sessions with a block, two time series, and a table of every gate by result" width="880">
</p>

<p align="center"><em>Which gate bites, on what, and how often. Every result in
the frozen vocabulary is counted, so a gate sitting at zero is visible.</em></p>

<table>
<tr>
<td width="50%"><img src="docs/media/watch-sessions.png" alt="Session list by role, with message counts, tool calls, blocks, and a per-session Analyze button"></td>
<td width="50%"><img src="docs/media/watch-trajectory.png" alt="One session's trajectory: the gates that fired as chips, the message timeline, and an expanded tool call"></td>
</tr>
<tr>
<td><strong>Sessions.</strong> One row per session, per role, with the number of
blocks it collected.</td>
<td><strong>Trajectory.</strong> The gates that fired, then the turn-by-turn
thread. Expand a message to see the exact tool call.</td>
</tr>
</table>

The panel has a **deliberate blind spot**: excluded transcripts are never
indexed, retroactively. An observation panel that can see everything ends up
watching people rather than gates.

---

## Mission control: what is happening right now

`watch` reads the past. This one reads the **present**, and those are different
questions. A log line proves an agent was alive when it wrote the line. It never
proves the agent is alive now, that a timer is about to fire, or that something
has been sitting there since lunch waiting for a human to say yes.

Run more than one agent and the failure mode stops being "an agent did something
wrong". It becomes **nobody noticed**.

<p align="center">
  <img src="docs/media/mc-overview.png" alt="Overview: roles alive, agents mid-turn, events recorded, blockers, health alerts, circuit breaks, log integrity, and whether the execution engine is paused" width="880">
</p>

<p align="center"><em>Counts are windowed, seven days by default: an all-time
counter keeps one bad afternoon on screen forever, and a number that never moves
stops being read.</em></p>

<table>
<tr>
<td width="50%"><img src="docs/media/mc-agents.png" alt="One line per role: alive or not, what its pane says it is doing, its directory and its last recorded event"></td>
<td width="50%"><img src="docs/media/mc-schedule.png" alt="Timers and scheduled units with their next run, so an armed job nobody remembers is visible"></td>
</tr>
<tr>
<td><strong>Agents.</strong> Two sources on purpose: the multiplexer answers
"alive", the log answers "what happened". Neither can answer both.</td>
<td><strong>Schedule.</strong> What is armed and when it fires next. A timer
nobody remembers arming is the classic surprise.</td>
</tr>
</table>

<p align="center">
  <img src="docs/media/mc-logs.png" alt="The signed log: filters by role, project and kind, with a validity column per row" width="880">
</p>

Every row is **signed**, and the panel recomputes the signature as it reads. A
row edited after the fact shows up as tampered rather than blending in, because
a log you cannot trust is worse than no log: it makes you confident.

<p align="center">
  <img src="docs/media/mc-approvals.png" alt="Two operations waiting for a decision, each with its plain-language impact, scope, path and hash; one flagged as requiring a hardware key" width="880">
</p>

The approvals screen is the one that earns the panel. An operation waiting on
you is shown with **what it actually does in plain language**, its scope, its
reversibility and its hash, so the decision is made on the operation rather than
on its filename. Acting is a separate, optional module: a panel that can only
read is a panel you can leave running.

---

## Governor: which rules earn their place

A human cannot audit a system that makes decisions at machine speed. So a
proposed rule does not get added because it sounds sensible. It gets judged.

<p align="center">
  <img src="docs/media/governor-propose.png" alt="Two judges from different model families reviewing two proposals: one accepted to build, one rejected and archived" width="880">
</p>

Two judges from **different model families**, neither seeing the other's
verdict. One rejection kills the proposal. A judge that cannot be reached
produces an explicit `judge-unavailable` and routes to a holding queue: it never
produces a yes by default, which is the entire point of having two.

<p align="center">
  <img src="docs/media/governor-trial.png" alt="Opening a seven-day observation trial, and closing it with a count of observations, legitimate blocks and false positives" width="880">
</p>

A surviving proposal is still **not armed**. It journals what it *would* have
blocked, for seven days, and blocks nothing. Then you look at the real catches
and decide. The governor never arms anything itself; it hands you the evidence.

<p align="center">
  <img src="docs/media/governor-audit.png" alt="Weekly audit listing only the gates that are noisy or silent, with three real samples each and a keep-or-review decision" width="880">
</p>

The weekly audit runs **by exception**: a gate doing its job is not listed. Only
the noisy ones, with real samples, and the silent ones, which are the dangerous
kind.

---

## Start here

```bash
git clone https://github.com/laeka-ai/integrity-framework.git
cd integrity-framework
python3 -m pytest tests/ -q         # 625 tests, no outbound network, no install
```

Then [**docs/quickstart.md**](docs/quickstart.md): fifteen minutes from clone to
a gate blocking something on purpose, with the real output at every step. Every
command on that page was executed to produce it.

| If you want to | Read |
|:--|:--|
| Understand how it holds together | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Know what each gate blocks, and why | [docs/gates/](docs/gates/) |
| Enforce behavior, not just commands | [docs/shield.md](docs/shield.md) |
| Stop rebuilding what already exists | [docs/recall.md](docs/recall.md) |
| Prove the harness is alive | [docs/sentinel.md](docs/sentinel.md) |
| Govern which rules earn their place | [docs/governor.md](docs/governor.md) |
| Keep memory that does not lie | [docs/statutory-memory.md](docs/statutory-memory.md) |
| Observe without interfering | [docs/watch.md](docs/watch.md) |
| See the fleet right now | [docs/mission-control.md](docs/mission-control.md) |
| Wire it into your own launcher | [docs/launchers.md](docs/launchers.md) |
| Add a gate of your own | [CONTRIBUTING.md](CONTRIBUTING.md) |

### Why there is no install step

Standard library only. No package to add, no dependency to audit, no supply
chain to trust. Where an optional accelerator exists, there is a fallback and a
test proving the two agree. The suites open no outbound connection: every LLM
judge is replaced by a fixed verdict through an environment variable.

---

## One rule if you add your own

> **A gate is born from an incident, never from a good idea.**

If you cannot tell the story of the day it hurt, the rule is noise, and noise
costs false positives until someone switches the whole thing off.

That is what the governor is for, and most proposals die at the judges. That is
the mechanism working.

## License

Integrity Framework is a laeka.ai product, released under Apache-2.0. See [LICENSE](LICENSE).
