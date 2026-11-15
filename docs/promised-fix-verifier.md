# Promised-Fix Verifier

An agent that answers "fixed" two minutes after a request has proven the local
symptom (a green bench, a commit), not the goal. Some goals only show over
hours: a spending rate, a queue that drains, an error that stops coming back.
When the operator asks for the same fix a second time, the Promised-Fix
Verifier arms a measured probe, runs it over time, and keeps the word "fixed"
off that problem until the probe says GREEN.

Core: `core/promised_fix/promised_fix.py`, stdlib only, host-neutral and pure
except for the journal. The adapter runs the probe, schedules the passes,
stores the records and speaks the verdicts.

## The cycle

| Step | Function | Rule |
|---|---|---|
| Detect | `detect(history, text, labels)` | `labels` maps a label to its words. A human message that names a label (whole words, case-insensitive) is a re-ask when at least one earlier message in `history` named it too. Returns `(label, count)`, `count` including the new message, or `None`. Count 2 or more: arm. The caller picks the window (the Pod uses 14 days). |
| Arm | `arm(label, probe, reply_to, now, words=...)` | A record: `id` = label + arming time (`spend-b-20261109145620`), `t0`, passes planned at +1 h and +2 h, `next` = the first one. `words` is required: the gate reads only records, and a record without words would leave it open. |
| Judge | `verdict(rc)` | The probe's exit code: `0` GREEN, `1` RED, anything else INCONCLUSIVE. Only an integer 0 is GREEN (`False`, `0.0`, `"0"` are INCONCLUSIVE). |
| Reschedule | `next_pass(record, verdict, now)` | Judges the latest pass whose time has come (overdue passes collapse into one; a timer up to 2 min early still judges its pass). Pass 1 never closes, pass 2 is already planned. From pass 2 on, GREEN or RED closes. INCONCLUSIVE plans the next pass at +4, +8, +24 h, then +72 h from `t0`, the ceiling, where it closes as **inconclusive final** (`final: true`). `next` is the time to schedule, or `None`. |
| Gate | `claim_blocked(text, records)` | A text saying `fixed`, `corrigé`, `réglé` or `résolu` that names a word of a label whose **latest** arming is neither GREEN nor disarmed is blocked: returns the reason, else `""`. |
| Record | `append_journal(path, entry)`, `stats(journal)` | One JSON line per arming (`"event": "arm"`, `id`, `t0`) and per pass (`id`, `verdict`, ...), strings scrubbed by `mask_secrets`. `stats` counts armings, GREEN, RED and INCONCLUSIVE pass lines, and the median hours from `t0` to an arming's first GREEN or RED pass. |

Record fields: `id`, `label`, `words`, `probe`, `reply_to` (the message the
verdicts answer), `t0`, `planned` (pass numbers), `state` (`armed`, `closed`;
the adapter writes `disarmed`), `last` (last verdict), `last_pass`, `final`,
`next`.

A probe is a command the adapter runs with `--t0 <record t0>`. It prints what it
measured and exits 0 (goal met), 1 (goal measurably missed) or 3 (not enough
time, data or trigger to say).

Default journal: `$PROMISED_FIX_DIR/journal.jsonl`, else
`$HARNESS_STATE_DIR/promised-fix/journal.jsonl`.

## What it proves

- A promised fix is measured over time by a probe against the goal, at +1 h
  and +2 h at least, not by the agent's word at the moment it answers.
- On an armed problem, the word "fixed" waits for GREEN: before the first
  verdict, after RED, after INCONCLUSIVE, the gate refuses it.
- A probe that crashes, times out or returns a code nobody planned is
  INCONCLUSIVE and goes on measuring; it is never GREEN by default.
- Nothing measures forever: at 72 h an undecided arming closes as
  inconclusive final, said as such.

## What it does NOT prove

- **The probe can lie.** The layer trusts its exit code. A probe that measures
  the wrong thing, or the right thing with the wrong threshold, turns GREEN on
  a problem that is not fixed. Bench the probe against a period known to be
  broken (it must say RED) before arming it.
- **A badly chosen label does not trigger the gate.** The gate matches words.
  "The B budget is fixed" passes when the label's words are "plan B" and
  "spend". Words too wide block unrelated claims; words too narrow let the
  claim through. The gate also stops nothing but the claim: the work goes on.
- **No detection without a second request.** The first request is never a
  re-ask, and a re-ask in words of no label is not detected. The operator, or
  the agent, can still arm by hand.
- That GREEN lasts: a closed arming is not watched any more. A third request
  arms it again, and the new arming is the one the gate reads.

## The real case

The Pod (the production team this framework comes from) asked eleven times
for a second subscription plan to be used at the rate its weekly allowance
permits. The agent answered "fixed" eight times, each time two to four
minutes after the request, each time backed by a green bench and a commit.
Measured one hour later, the rate was close to 0 %/h almost every time: every
claim had proven the local symptom, none the goal, and the only loop that
watched the goal was the operator.

The layer was armed for real on 2026-11-09 at 14:56 (`depense-b-20261109145620`,
answering request no. 2119): a probe reads the usage history since `t0` and
compares the measured rate with the rate the allowance permits (GREEN at 75 %
or more, RED under 50 % after at least an hour and two fresh readings, else
INCONCLUSIVE), and each pass writes its verdict to the operator's chat.
