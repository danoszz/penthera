---
title: "The agent brief"
sidebarTitle: "The agent brief"
description: "The brief is a short summary of a scan, the same shape every time, for an AI assistant to pass on as it is."
---

> **Pro.** For "what should my AI assistant tell me after a scan?"

The brief is a short summary of a scan, the same shape every time, for an AI
assistant to pass on as it is. Penthera's rules fill it; no model is involved.

| Section | What is in it |
|---|---|
| Verdict | `Fix now`, `Review` or `Nothing to fix`, with the counts. `Nothing to assess` when `penthera agents` found no agent config. Never `Nothing to fix` when a finding or a required tool makes the scan exit 1 or 2: it says `Review` and gives the reason on the next line. A failure after the brief prints, such as an output file it can't write, exits 2 with an error of its own |
| Act on | Findings that need a change: where, why, the fix, the rule id |
| Check first | Heuristic and low findings, and what a dependency *can* do |
| Likely noise | Hits in files git ignores, generated build output or test fixtures, one line per group |
| Not checked | What the scan did not read. Always shown, so a short brief is not read as "safe" |
| Next | Up to three commands, and the path of the full report |

Findings that repeat collapse into one line: two advisories for one Node.js
pin, or the same rule in 16 build files. Every finding is counted once. The
full list stays in the JSON and Markdown reports.

## Get it

| Where | How |
|---|---|
| A scan, in a terminal | `penthera --repo . --brief` |
| A scan, from an agent | Nothing to add: with no terminal on stdout, a scan prints the brief instead of the terminal report. `PENTHERA_BRIEF=0` turns that off; CI keeps the terminal report |
| A report file | `penthera --repo . --audience agent --markdown reports/brief.md` |
| JSON | The `brief` field of `-o report.json` (schema `penthera.brief/1`). `exit_code` is the code the findings give, `exit_reason` the line under the verdict or null, and `likely_noise[].severe` the critical or high findings in that group |
| Several scans in one | `penthera brief reports/repo.json reports/deps.json reports/agents.json` |
| MCP | The text of every tool result is the brief; `structuredContent.brief` holds the object |

```bash
penthera --repo . -o reports/repo.json
penthera deps . -o reports/deps.json
penthera agents . -o reports/agents.json
penthera brief reports/repo.json reports/deps.json reports/agents.json
```

`penthera brief --json` prints the merged brief as JSON. `penthera brief`
reads only the files you name and runs no scan.

## How an assistant should reply

The MCP server and the Agent Skill ask the assistant to:

1. Pass the brief on in its order, with the verdict line and section names.
2. Not move a finding between sections, change a severity or drop a group.
3. Put anything it checked itself under a last section, **My read**, and say
   what it looked at. That section is the assistant's view, not Penthera's.
4. Ask before changing files.

## Which section a finding goes in

The first matching rule wins:

1. **Likely noise:** the file is local only (git ignores it), in generated
   output (`.next*`, `dist`, `build`, `out`, `__pycache__`, `coverage`), or a
   test fixture. In a skill folder you name, `dist` and `build` are the skill's
   own code, so they are not noise there.
2. An **info** finding goes to **Next** if it names a command, or to **Not
   checked** if it says something was not found or not run.
3. **Check first:** confidence `potential` or `needs-human-review`, severity
   low, or a dependency capability.
4. **Act on:** everything else.

The design is in [docs/research/spec-agent-brief.md](https://github.com/danoszz/penthera/blob/main/docs/research/spec-agent-brief.md).
