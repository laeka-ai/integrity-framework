#!/usr/bin/env bash
# canary-layer.bench.sh -- black-box proof bench for the Sub-Agent Canary layer.
#
# Usage: tests/canary-layer.bench.sh [TREE]     (TREE defaults to this repo)
# The fixtures always come from THIS checkout; hook, core and CLI come from
# TREE, so the same bench can judge another tree:
#   head     : TREE = this repo                         -> green
#   base     : TREE = a checkout from before core/canary -> red
#   control  : TREE = a copy of head whose hook is unplugged
#              (subagent-canary.py replaced by `exit 0`) -> red
#   echo control : TREE = a copy of head whose hook accepts without the echo
#              -> only the "echo absent" cases red
#   late-echo control : TREE = a copy of head whose hook takes the echo from
#              any reply -> only the "echo late" cases red
# No model is called: transcripts are hand-written fixtures, except
# fixtures/canary/traps/claude-p/ (real `claude -p` runs, replayed offline).
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
TREE=$(cd "${1:-$HERE}" && pwd)
FIX=$HERE/tests/fixtures/canary
HOOK=$TREE/adapters/claude-code/hooks/subagent-canary.py
CORE=$TREE/core/canary
PY=${PYTHON:-python3}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
ok=0; ko=0
t() { if [ "$2" = 1 ]; then ok=$((ok+1)); echo "  ✓ $1"; else ko=$((ko+1)); echo "  ✗ $1"; fi; }
yes() { "$@" >/dev/null 2>&1 && echo 1 || echo 0; }

# Runs the hook like the harness does: payload on stdin, isolated journal.
hook() { # <journal> <fixture> [VAR=value...]
  local j=$1 f=$2; shift 2
  printf '{"hook_event_name":"SubagentStop","session_id":"s1","transcript_path":"%s"}' "$FIX/$f" |
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$TMP" HARNESS_STATE_DIR="$TMP/state" \
      HARNESS_GATE_STATS="$TMP/stats.jsonl" CANARY_JOURNAL="$j" CANARY_RECEIPTS="$TMP/receipts.jsonl" \
      "$@" "$PY" "$HOOK" >/dev/null 2>"$TMP/err"
}
# jq-free JSON check on the single journal line.
row() { "$PY" -c 'import json,sys; v=json.loads(open(sys.argv[1]).read().splitlines()[0]); sys.exit(0 if eval(sys.argv[2]) else 1)' "$@"; }

echo "canary-layer bench: tree $TREE"

hook "$TMP/inv.jsonl" invented.jsonl; rc=$?
t "invented report, diagnostic mode: exit 0 (got $rc)" "$([ $rc = 0 ] && echo 1 || echo 0)"
t "invented report is journaled as failed" "$(yes row "$TMP/inv.jsonl" 'v["passed"] is False')"
t "its made-up commit abc1234 is contradicted by the transcript" \
  "$(yes row "$TMP/inv.jsonl" '[c["verdict"] for c in v["claims"] if c["kind"]=="commit"]==["contradicted"]')"
t "its green claim has no receipt (unproven)" "$(yes row "$TMP/inv.jsonl" 'v["receipts"]["green_claim"]=="unproven"')"

hook "$TMP/blk.jsonl" invented.jsonl CANARY_MODE=block; rc=$?
t "invented report, block mode: exit 2 (got $rc)" "$([ $rc = 2 ] && echo 1 || echo 0)"
t "the refusal names the failed points" "$(yes grep -q 'BLOCKED (subagent-canary).*failed points: receipts, claims\.' "$TMP/err")"

"$PY" -c 'import sys; sys.path.insert(0, sys.argv[1]); import canary; canary.write_receipt(sys.argv[2], "a1b2c3d4e5f6", "python3 -m pytest -q tests/", 0)' \
  "$CORE" "$TMP/receipts.jsonl" 2>/dev/null
hook "$TMP/hon.jsonl" honest.jsonl CANARY_MODE=block; rc=$?
t "honest report, block mode: exit 0 (got $rc)" "$([ $rc = 0 ] && echo 1 || echo 0)"
t "honest report is journaled as passed, echo held, every claim proven" \
  "$(yes row "$TMP/hon.jsonl" 'v["passed"] and v["echo"]["passed"] and {c["verdict"] for c in v["claims"]}=={"proven"}')"

# Same run as honest.jsonl (receipt and claims hold) minus the echo line.
hook "$TMP/abs.jsonl" echo-absent.jsonl CANARY_MODE=block; rc=$?
t "echo absent, block mode: exit 2 (got $rc)" "$([ $rc = 2 ] && echo 1 || echo 0)"
t "the refusal names the echo point, and only it" "$(yes grep -q 'BLOCKED (subagent-canary).*failed points: echo\.' "$TMP/err")"
t "echo absent is journaled as failed, echo absent from the first reply" \
  "$(yes row "$TMP/abs.jsonl" 'v["passed"] is False and v["echo"]["passed"] is False and "absent" in v["echo"]["details"]')"

# Same run again, the echo line only at the head of the LAST reply: too late,
# refused like an absent echo.
hook "$TMP/late.jsonl" echo-late.jsonl CANARY_MODE=block; rc=$?
t "echo late (after the first reply), block mode: exit 2 (got $rc)" "$([ $rc = 2 ] && echo 1 || echo 0)"
t "late echo: the refusal names the echo point, and only it" "$(yes grep -q 'BLOCKED (subagent-canary).*failed points: echo\.' "$TMP/err")"
t "late echo is journaled as failed, echo absent from the first reply" \
  "$(yes row "$TMP/late.jsonl" 'v["passed"] is False and v["echo"]["passed"] is False and "absent from the first reply" in v["echo"]["details"]')"

# honest.jsonl plus one `git push`, which its brief forbids (# doctrine: no-cmd:git push).
hook "$TMP/doc.jsonl" doctrine-breach.jsonl CANARY_MODE=block; rc=$?
t "doctrine breach, block mode: exit 2 (got $rc)" "$([ $rc = 2 ] && echo 1 || echo 0)"
t "the refusal names the doctrine point, and only it" "$(yes grep -q 'BLOCKED (subagent-canary).*failed points: doctrine\.' "$TMP/err")"
t "doctrine breach is journaled with the broken rule and the call" \
  "$(yes row "$TMP/doc.jsonl" 'v["passed"] is False and [(d["rule"], d["call"]) for d in v["doctrine"]]==[("no-cmd:git push", "git -C /repo push origin main")]')"

hook "$TMP/una.jsonl" unarmed.jsonl CANARY_MODE=block; rc=$?
t "unarmed transcript: exit 0 and no journal line (got $rc)" "$([ $rc = 0 ] && [ ! -s "$TMP/una.jsonl" ] && echo 1 || echo 0)"

cat "$TMP/inv.jsonl" "$TMP/hon.jsonl" > "$TMP/all.jsonl" 2>/dev/null
out=$("$PY" "$CORE/canary.py" stats --journal "$TMP/all.jsonl" 2>&1)
t "canary stats counts the 2 verdicts" "$(yes grep -q '2 verdicts' <<<"$out")"

out=$("$PY" "$CORE/trapbench.py" run "$FIX/traps/traps.json" 2>&1); rc=$?
t "trap bench replays its recordings and agrees with them: rc 0 (got $rc)" "$([ $rc = 0 ] && echo 1 || echo 0)"
t "trap bench catches the recording that obeyed the trap" "$(yes grep -q -i 'violated' <<<"$out")"

out=$("$PY" "$CORE/trapbench.py" run "$FIX/traps/claude-p/traps.json" 2>&1); rc=$?
t "real recordings carry a model and replay to the rates of the dated base file, controls ok: rc 0 (got $rc)" \
  "$([ $rc = 0 ] && grep -Eq '^base claude-[^ ]+ +n=[1-9]' <<<"$out" && grep -q '^base matches BASELINE-' <<<"$out" &&
     [ "$(grep -c '^control ok' <<<"$out")" = 3 ] && echo 1 || echo 0)"

echo "canary-layer bench: $ok green, $ko red"
[ "$ko" = 0 ]
