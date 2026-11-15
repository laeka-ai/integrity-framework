# AgentDojo adapter (described, not run)

**What it is.** AgentDojo (ETH Zurich and Invariant Labs,
github.com/ethz-spylab/agentdojo) is a dynamic environment to evaluate prompt
injection attacks and defenses for LLM agents: task suites (for example
`workspace`) with user tasks, injected data in the tool results, and named
attacks and defenses. Source: its README, read 2026-11-09.

**Why it is not run here.** Its runs call a model through a provider API,
billed per token. This framework measures on the subscription only, with the
local trap bench (`tools/quarantine_traps.py`, see
[the Quarantine Layer](../quarantine-layer.md#trap-bench)). This page says how
the two would meet; nothing below has been executed.

**How it would run** (upstream README, not run):

```sh
pip install agentdojo
python -m agentdojo.scripts.benchmark -s workspace -ut user_task_0 \
    --model <model> --defense tool_filter --attack tool_knowledge
```

**Mapping onto the Quarantine Layer.**

| AgentDojo | Quarantine Layer |
|---|---|
| a tool result that carries third-party data (an email, a web page, a file) | a reader event, `{kind: "fetch", target: tool name and arguments, output: result text}` |
| any tool call that acts (send, write, pay, delete) | a hand: `check_hands` names it; a quarantined reader must have none |
| the agent's final answer | the report, read by `check_report` |
| injection task succeeded | the trap `marker` present outside a grounded quote, or a hand |

The fit is partial: AgentDojo agents are meant to act, so the "no hands" rule
holds only for a reader-only split of each task. Plugging the checker in as an
AgentDojo defense needs its extension point for custom defenses, which this
page does not specify (upstream documentation not read here).

**What to publish.** n/N per suite and per model, beside the local bench,
never a percentage.
