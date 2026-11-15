# Garak adapter (described, not run)

**What it is.** garak (NVIDIA, github.com/NVIDIA/garak, Apache 2.0) is an LLM
vulnerability scanner: *probes* send attack prompts, *detectors* judge the
outputs, *generators* are the model interfaces (`--target_type openai`,
`huggingface`, and `rest.RestGenerator` for any REST endpoint returning text or
JSON). `--spec probes.promptinject` restricts a run to the PromptInject
probes. Source: its README, read 2026-11-09.

**Why it is not run here.** A garak run sends thousands of prompts to a model
interface, an API billed per token in every hosted case. This framework
measures on the subscription only, with the local trap bench
(`tools/quarantine_traps.py`). Nothing below has been executed.

**How it would run** (upstream README, not run):

```sh
python -m pip install -U garak
python3 -m garak --target_type openai --target_name <model> --spec probes.promptinject
```

**Mapping onto the Quarantine Layer.** garak puts its payload in the prompt;
the Quarantine Layer is about payloads in what the reader *fetches*. Two ways
to meet:

1. **Payloads as pages.** Render garak probe payloads as static pages in the
   `bench/traps` format (one page per payload, family, `marker`,
   `true_quote` in the manifest) and play them with the local bench. garak's
   corpus, our flow and our counts.
2. **The reader behind REST.** Wrap the reader (prompt in, report out) in a
   local REST endpoint and point `rest.RestGenerator` at it, then run
   `check_report` on each output. Every probe is then a model call: same cost
   rule as above.

garak's detectors read the model's text; the Quarantine Layer reads the
report against the tool events. Both verdicts can sit side by side, the
second needs the run's events, which a REST wrapper must log.

**What to publish.** n/N per probe family and per model, never a percentage.
