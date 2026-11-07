---
title: "AI mode: --ai"
sidebarTitle: "AI mode"
description: "AI mode is opt-in and experimental."
---

> **Starter and pro.** For "can a model look for what Penthera's rules miss,
> without my code leaving my computer and without trusting the model?"

AI mode is opt-in and experimental. A model on your computer reads your code,
part by part, and proposes problems that no rule describes. Penthera then
checks every proposal with its own rules. A model never decides a finding:
what a rule confirms becomes a finding, and the rest is shown as
"model-proposed, unverified", apart from rule findings, and never fails CI.

```bash
penthera --repo . --ai
```

AI mode **finds; it doesn't fix.** To have a coding agent fix what Penthera
found, give it the findings through the [MCP server](commands/mcp.md), the
[Agent Skill](commands/skill.md) or `penthera fix --plan`. The rules decide in
every case.

Whether AI mode finds more than the rules alone is not measured yet. A planned
experiment (E9) will measure it, and AI mode stays opt-in until it does.

## What you need

[Ollama](https://ollama.com) running on this computer, with a code model
pulled, for example:

```bash
ollama pull qwen2.5-coder:7b
penthera ai models
```

`penthera ai models` lists your models and says which run on this computer and
which run on ollama.com.

## What happens, step by step

1. **Consent.** Penthera asks before anything is scanned, every run.
2. **Rules.** The normal repo scan runs, and records what it read (the
   coverage ledger in the report).
3. **The model reads.** Your code is split into parts of up to 200 lines. Files
   the rules could not analyse come first, then files that handle outside
   input. Tests and minified files are left out. Anything the secret scan
   recognises is masked before a part is sent. A key written with `\u`
   escapes masks its whole line. The model gets text only: no
   tools, files, network or shell.
4. **Penthera checks.** Each proposal must point at a line of the part the
   model was shown, or it is dropped. A proposal that a Penthera rule confirms
   (same kind of issue, same file) marks that rule's finding "also proposed by
   AI". The rest are model-proposed, unverified.
5. **The report** has an AI mode section: the model, where it ran, how much it
   read, and the unverified proposals. They are not counted in the summary and
   never change the exit code.

## Consent

Every `--ai` run shows this, and the default answer is no:

```
  AI mode: a model reads your code to look for problems the rules can't see.

  Model     qwen2.5-coder:7b, through Ollama on this computer (127.0.0.1)
  Reads     up to 200 parts of ./my-app, with secrets masked
  Sends     nothing off this computer
  Decides   nothing. Penthera checks every model finding with its own rules.
            Unchecked ones are labelled and never fail CI.

  Use this model for ./my-app? [y/N/details]
```

- Enter, Ctrl-C or anything but `y` runs the scan with rules only. Saying no is
  never an error.
- `details` explains the route in full, the model's size and digest, and where
  consent is logged, then asks again.
- Nothing is remembered as permission. Each answer is added to a log on this
  computer only (`~/.penthera/consent.jsonl`); `penthera ai consent` shows it.

### Cloud models

Ollama can serve models that run on ollama.com through the same local address;
their names end in `-cloud`. Penthera recognises them and never treats one as
local. Choosing one shows a second screen, and you type the host to agree:

```
  This model runs on ollama.com, not on this computer.

  Sends     up to 200 parts of ./my-app, secrets masked, to ollama.com
            through your local Ollama, under Ollama's terms

  Type ollama.com to send your code there, or press Enter to stop:
```

If Penthera cannot tell whether a model runs locally, it treats it as a cloud
model.

### CI and other runs that cannot ask

A run without a terminal (CI, piped input, `--json`) needs consent given in
advance, or it stops before scanning with exit code 2:

```bash
penthera --repo . --ai --ai-model qwen2.5-coder:7b --ai-consent local
```

or, reviewed with the rest of your config, in `penthera.policy.json`:

```json
{ "ai": { "allow": ["local"] } }
```

The value is a route, not a yes: `local` never covers a cloud model, which
needs `ollama-cloud`. `"allow": []` turns AI mode off for the repository.

## In the dashboard

`penthera ui`: in **New scan…**, turn on **AI mode** for a scan of a project
folder. The same consent appears as a sheet, with a picture of where your code
goes and two equal buttons, "Use `<model>` on this computer" and "Not now". See
[dashboard.md](dashboard.md#ai-mode).

## Options

| Flag | Default | Use |
|---|---|---|
| `--ai` | off | Turn AI mode on for this run (needs `--repo`) |
| `--ai-model <name>` | asks | An Ollama model; required when the run cannot ask |
| `--ai-budget <spec>` | `units=200,tokens=2M,time=20m` | Hard caps; the first one hit ends the model's reading, and the report says the run was partial and what it did not read |
| `--ai-consent <route>` | none | `local` or `ollama-cloud`, for runs that cannot ask |
| `--ai-scope <folder>` | the whole repo | Only read files under this folder |

When Ollama is not running, has no models, or the model you named is not
installed, the rules-only scan runs and the report says why AI mode did not.
Ctrl-C during the model's reading stops it; what it read so far is checked and
reported as partial.

## Using your own agent instead

You can also run an AI audit in your own coding agent, for example
Cloudflare's security-audit skill, with any model it supports, and give the
result to Penthera to check: see [penthera verify](commands/verify.md). Then
Penthera runs no model at all; your agent and its provider handled your code,
under their terms.

## What this does not do

- It does not make the model a judge. A model's "critical" stays a claim until
  a rule confirms it.
- It does not run your code. (Checking proposals by running the code in a
  sandbox is planned and will ask separately.)
- It is not robust against code written to mislead a model. Such code can make
  the model miss things or invent things; it cannot turn a proposal into a
  finding, because only rules confirm.
- It does not call any hosted AI service itself. The only way code leaves your
  computer in AI mode is a cloud model in your own Ollama, after the second
  screen.
