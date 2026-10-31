---
title: "Penthera as an Agent Skill"
sidebarTitle: "Agent Skill"
description: "Penthera ships as an Agent Skill, the open format used by Cursor, Claude Code, Claude.ai, and 40+ agent tools."
---

> **Starter.** For "can my coding agent run it for me?"

## For your AI coding agent

Penthera ships as an [Agent Skill](https://agentskills.io), the open format used
by Cursor, Claude Code, Claude.ai, and [40+ agent tools](https://agentskills.io/clients).
The skill teaches an agent to run authorized scans, pick the right profile, and
summarize findings, so you can describe what you want in plain words.

**Install** (any of these):

```bash
# Cross-agent, frictionless
npx skills add danoszz/penthera

# Or the one-line installer (also links the CLI)
curl -fsSL https://raw.githubusercontent.com/danoszz/penthera/main/install.sh | bash

# Or copy into a single project for team sharing
cp -r skills/penthera .cursor/skills/penthera     # Cursor
cp -r skills/penthera .claude/skills/penthera     # Claude Code
```

Or as a Claude Code plugin (installs the skill):

```bash
/plugin marketplace add danoszz/penthera
/plugin install penthera@penthera
```

For Claude.ai (web), zip and upload the skill:

```bash
npm run package:skill   # produces penthera-skill.zip; upload in Settings > Capabilities > Skills
```

The skill runs the CLI in your agent's terminal. To give your agent typed,
read-only tools instead, add the MCP server: see [mcp.md](mcp.md).

**Prompts that trigger it:**

- "Scan my localhost app on port 3000 for security issues"
- "Run a pre-deploy audit on staging.myapp.com and summarize critical findings"
- "Scan this repo for hardcoded secrets and exposed API routes"
- "Compare today's scan to last week's baseline and show only new findings"
- "Generate a SARIF report for GitHub code scanning"
- "Audit my MCP servers, skills and Claude Code hooks"

The skill adds an authorization gate: it instructs the agent to refuse targets you
do not own or are not authorized to test, and the wizard asks you to confirm before
scanning a remote host. The raw CLI does not check who owns a target. It asks for
confirmation only before active modes (`--deep`, `--fuzz`, `--adaptive`, `--all`,
`--profile deep`). You are responsible for every target you pass it. Run preflight
from your project folder before the first scan. The script is in the skill's own folder:
`~/.claude/skills/penthera` after `npx skills add -g`, or `skills/penthera` in a checkout.

```bash
bash ~/.claude/skills/penthera/scripts/preflight.sh http://localhost:3000
```

Skill source and workflows live in [`skills/penthera/SKILL.md`](https://github.com/danoszz/penthera/blob/main/skills/penthera/SKILL.md).

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
