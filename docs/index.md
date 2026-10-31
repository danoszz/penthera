---
title: "Penthera documentation"
sidebarTitle: "Overview"
description: "Penthera is an open-source cyber security agent."
---

> **Starter and pro.** For "where do I start, and where do I go next?"

Penthera is an open-source cyber security agent. It checks your app, its
dependencies and your AI coding tools on your own machine, offline, with rules
you can read. A model may propose; a rule decides.

Pick the journey that fits you. Each page answers one question, and each
journey runs from the first command to the details.

[![Walkthrough video: setup, a scan, the dashboard in Simple and Advanced mode, one fix approved, the report](https://github.com/danoszz/penthera/raw/main/assets/walkthrough-poster.jpg)](https://github.com/danoszz/penthera/raw/main/assets/walkthrough.mp4)

[Watch the 80-second walkthrough](https://github.com/danoszz/penthera/raw/main/assets/walkthrough.mp4). Demo data, no
sound, captions in the video ([as text](https://github.com/danoszz/penthera/raw/main/assets/walkthrough.vtt)).

## 1. I'm new

For "is my app secure?" Start with one command in your project folder:

```bash
npx penthera
```

| Your question | Read |
|---|---|
| "What does `npx penthera` do, and what does it not do?" | [Set up in one command](commands/init.md) |
| "I build with Cursor, Claude Code, Lovable or another AI tool: how do I add it?" | [Penthera in your coding tool](integrations.md) |
| "An AI tool built my app. What should I check before I publish it?" | [Before you publish](before-you-publish.md) |
| "How do I scan my running app and its source?" | [Scanning your app](commands/scan.md) |
| "Can it run gitleaks, Trivy and Semgrep for me, in one report?" | [Other tools in one run: `--giants`](commands/giants.md) |
| "Is this package safe to add?" | [Dependency risk](commands/deps.md), [the install firewall](commands/install.md) |
| "Can I see it all in one place?" | [The local dashboard](dashboard.md) |
| "What does it send over the network?" | [Privacy and network use](privacy.md) |

## 2. I use AI coding tools

For "is my AI setup safe, and can my agent run Penthera?"

| Your question | Read |
|---|---|
| "Is this MCP server or skill safe?" | [Auditing your AI tooling](commands/agents.md) |
| "Can my coding agent run it for me?" | [Penthera as an Agent Skill](commands/skill.md) |
| "Can my agent call it as a tool?" | [Penthera as an MCP server](commands/mcp.md) |
| "I let an agent work on my code. What should I check?" | [Running AI agents safely](agents-safely.md) |
| "Can a model look for what the rules miss?" | [AI mode](ai-mode.md) (opt-in, experimental) |
| "An AI audit gave me a list of findings. Which are real?" | [`penthera verify`](commands/verify.md) |

## 3. I run it in CI

For "how do I make it part of every change?"

| Your question | Read |
|---|---|
| "How do I put it in CI?" | [Penthera in CI](commands/action.md), [scan in CI](commands/scan.md#ci-integration), [example workflows](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-scan.yml) |
| "How do I stop problems before they are committed?" | [The pre-commit hook](commands/hook.md) |
| "How do I run the fix loop?" | [Fixing what it finds](commands/fix.md), [the local loop and its memory](local-loop.md) |
| "How do I tune the rules?" | [Scan configuration](commands/scan.md#configuration), [rule packs](rule-packs.md) |
| "Is the runtime I deploy affected by an advisory?" | [Runtime advisories](runtime-advisories.md) |
| "Which OWASP tests does it cover?" | [OWASP WSTG coverage](owasp-wstg-coverage.md) |
| "Which command and flag do I need?" | [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md) |

## 4. I need evidence for an auditor

For "what do I give my auditor?" Compliance output is readiness tooling. It is
not a certification and not legal advice.

| Your question | Read |
|---|---|
| "What do I hand over, and how does the auditor check it?" | [Evidence bundles and audience reports](evidence.md) |
| "What does NIS2 ask, and what can Penthera show?" | [NIS2](compliance-nis2.md) |
| "What must I report under the CRA, and what is in my AI-BOM?" | [The CRA and AI-BOM](compliance-cra.md) |

## 5. I'm a researcher

For "how do you know it works?"

| Your question | Read |
|---|---|
| "How does it decide, and what can't it see?" | [Methodology](METHODOLOGY.md), [known limitations](METHODOLOGY.md#known-limitations) |
| "How accurate is it?" | [Public benchmarks](https://github.com/danoszz/penthera/blob/main/bench/public/RESULTS.md) against the free tools (E11b), our own [benchmark](https://github.com/danoszz/penthera/blob/main/bench/README.md) and [latest results](https://github.com/danoszz/penthera/blob/main/bench/RESULTS.md), the [E10 pilot](https://github.com/danoszz/penthera/blob/main/bench/known-vuln/RESULTS.md) on known-vulnerable apps |
| "What will you measure next?" | [Research plan](vision-2.0.md), [pre-registrations](https://github.com/danoszz/penthera/blob/main/docs/research/prereg/E1-real-world-accuracy.md), [research notes](https://github.com/danoszz/penthera/tree/main/docs/research) |
| "How do I know a release is sound?" | [Internal audit](internal-audit.md) |
| "What research is it based on?" | [References](references.md) ([BibTeX](https://github.com/danoszz/penthera/blob/main/docs/references.bib)), [how to cite](METHODOLOGY.md#how-to-cite) |
| "How does it compare to the tool I use?" | [Comparisons](https://github.com/danoszz/penthera/blob/main/docs/compare/README.md) |
| "Why was it built this way?" | [Manifesto and FAQ](MANIFESTO.md) |
| "How much of it did AI write?" | [Use of generative AI](genai.md) |

The accuracy numbers come with their sample and caveats on the same page. In
short: the bundled benchmark is 24 findings in labs we wrote ourselves, the E10
pilot used one labeller, and accuracy on real projects (E1) is not measured
yet.

## The project

| Page | For |
|---|---|
| [Roadmap](https://github.com/danoszz/penthera/blob/main/ROADMAP.md) | Where it stands, what ships next, and what is not planned |
| [CONTRIBUTING](https://github.com/danoszz/penthera/blob/main/CONTRIBUTING.md) | Setup, tests, the merge flow and the release steps |
| [AGENTS.md](https://github.com/danoszz/penthera/blob/main/AGENTS.md) | Coding agents working on or with Penthera |
| [Voice guide](voice.md) | How Penthera's docs and messages are written |
| [CHANGELOG](https://github.com/danoszz/penthera/blob/main/CHANGELOG.md) | Every release |
| [SECURITY](https://github.com/danoszz/penthera/blob/main/SECURITY.md) | Reporting a vulnerability in Penthera itself |
| [Funding](funding/sponsor-tiers.md) | How to sponsor Penthera, and what each tier includes |
| [Marketing automation](https://github.com/danoszz/penthera/blob/main/docs/marketing.md) | What runs on a schedule, and what a person still posts |
| [MCP directory listings](https://github.com/danoszz/penthera/blob/main/docs/mcp-listing.md) | What the maintainer pastes into MCP directories |

## Programmatic API

```javascript
import { loadTemplatesFromPaths, runTemplateScan } from "penthera/plugins";
import { runAdaptiveProbes } from "penthera/adaptive";
```

The exports are in `lib/plugins.js` and `lib/blackbox/adaptive-scan.js`, both
shipped in the npm package. The npm package ships only `docs/examples/` from
this folder; the rest of the docs live on GitHub.

Only scan systems you own or are authorized to test.
