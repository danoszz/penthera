---
title: "Penthera and Cloudflare's security-audit skill"
sidebarTitle: "vs Cloudflare audit"
description: "How Penthera's rules and Cloudflare's AI security-audit skill fit together."
---

> **Pro.** For "how does Penthera compare to Cloudflare's security-audit skill, and how do I run both?"

*Last checked: 2026-10-22 against the repository at commit
[`c1c8a8c`](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c)
(2026-09-14).*

## Use them together

[security-audit-skill](https://github.com/cloudflare/security-audit-skill) is
an MIT-licensed skill that turns a coding agent into a security auditor. It
comes from Cloudflare's internal vulnerability-discovery harness. The agent
maps the architecture, sends isolated sub-agents to hunt across attack classes,
has fresh agents try to disprove each candidate, and writes a schema-checked
`findings.json` and reports. The reasoning is done by the language model; two
small Node.js validators check the output files.

The two answer different questions:

- **The skill asks a model to read your code like a security researcher.** It
  can find business-logic flaws, authorization mistakes and bugs no rule
  describes, in any language, at the cost of model time and with results that
  vary between runs.
- **Penthera runs fixed, readable checks** in seconds, offline, with the same
  answer every time. It finds known classes of problems, checks what your
  running app and your dependencies actually do, and verifies its own fixes.

A reasonable setup: Penthera on every commit and pull request, because it is
fast, free and repeatable. The skill for a deep review before a release, or
when Penthera reports nothing and you still want a second opinion.

## Side by side

| | Penthera | security-audit skill |
|---|---|---|
| How it decides | Deterministic, readable rules; models may only propose | A language model hunts and validates; fresh agents try to disprove each finding |
| Same answer every run | Yes | No. The authors say one run found "roughly half" of what repeated runs found ([README](https://github.com/cloudflare/security-audit-skill#readme)) |
| What it reads | Source (Next.js, Express, Hono, Fastify), dependencies (npm, Python), AI tooling config | Any source, including native code, protocols, cloud config, mobile and desktop ([attack classes](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c/skills/security-audit)) |
| Running app | URL scan of a target you own | No: it forbids probing deployed endpoints and works from source |
| Dependencies | What each package can do, install firewall, typosquats, known malicious versions, runtime advisories | Supply-chain review of your repo's build and release setup |
| AI tooling | `penthera agents`: skills, MCP servers, hooks, permissions | AI and LLM attack classes in your application code |
| Fixes | Applied on a local branch, re-scanned and kept only if verified | Recommends the smallest fix; does not apply it |
| Accuracy published | Precision and recall with 95% intervals on our own labs and on four public datasets; real-world study pre-registered | No figures beyond the run-to-run note |
| Needs | Node.js 22; no model, no account | A coding agent with tool use and parallel sub-agents, and model usage for every run |
| Network | Only the target you name; `--offline` enforces it | Not stated in the README; depends on your agent and model provider |
| License | MIT | MIT |

## Where the skill goes further

- **Depth on your own code.** A model reading code can find flaws that no rule
  describes: broken authorization, unsafe state machines, logic errors.
- **Breadth of languages and targets**, from memory safety in native code to
  RPC and mobile.
- **A disciplined method:** an explicit coverage ledger, independent
  disproof of each candidate, and strict sandbox rules before running any
  target code. Those ideas are worth copying.

## Where Penthera adds something

- **Speed, repeatability and cost:** seconds, the same result every time, no
  model bill. That is what a CI gate needs.
- **Outside the source:** the running app, what packages do when installed, and
  the agent config on your machine.
- **Fixes that are verified** by a re-scan on a local branch, and an
  evidence bundle for auditors.
- **Measured accuracy**, with intervals and limits stated.

## Run both

```bash
npx penthera http://localhost:3000 --repo . --sarif penthera.sarif
npx penthera agents
npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
```

Then ask your agent for a full security audit. Treat findings that both tools
report as the highest priority, and use Penthera to re-check fixes for anything
the skill found that Penthera has a rule for.

[All comparisons](https://github.com/danoszz/penthera/blob/main/docs/compare/README.md) · [Back to the README](https://github.com/danoszz/penthera/blob/main/README.md)
