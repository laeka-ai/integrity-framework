# PyRIT adapter (described, not run)

**What it is.** PyRIT, the Python Risk Identification Tool for generative AI
(Microsoft, github.com/microsoft/PyRIT, moved from github.com/Azure/PyRIT), is
an open framework for red teaming generative AI systems: a command-line
Scanner for repeatable assessments, a GUI, and a Python framework of
composable parts. It connects to hosted models (OpenAI, Anthropic, Azure,
Bedrock, Gemini and others) and to whole applications through HTTP,
WebSocket, Playwright or custom targets. Source: its README, read 2026-11-09.

**Why it is not run here.** Its attacks drive a target model and usually an
attacker or scorer model too, through provider APIs billed per token. This
framework measures on the subscription only, with the local trap bench
(`tools/quarantine_traps.py`). Nothing below has been executed, and no
install or run command is given: the README points to its website for both.

**Mapping onto the Quarantine Layer.**

| PyRIT | Quarantine Layer |
|---|---|
| a custom or HTTP target wrapping the reader (prompt in, report out) | the reader under test, in one of the three bench conditions |
| the content an attack plants where the reader will read it | a page in the `bench/traps` format, served by `quarantine_traps.py serve` |
| a scorer | `check_report` on the report and the run's events: deterministic, zero tokens, never a model |

The useful part for this framework is the attack generation, not the scoring:
a model-based scorer reads the injected text and can be injected too (see
[the Quarantine Layer](../quarantine-layer.md)).

**What to publish.** n/N per attack family and per model, never a percentage.
