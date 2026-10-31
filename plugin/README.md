# Penthera plugin

Penthera is an offline, rule-based cyber security agent for your own apps and AI
coding tools. Every finding comes from a rule you can read, and you can check
each one yourself. MIT licensed.

This folder is the plugin for Claude Code and Cowork. It holds two things:

- **The Penthera skill** (`skills/penthera`): tells Claude how to scan your own
  app, live URL, dependencies and agent setup, explain the findings and fix them
  with your approval.
- **The Penthera MCP server** (`.mcp.json`): read-only tools that scan inside your
  project. They never apply fixes and run no shell. It starts locally with
  `npx -y penthera@2.1.2 mcp`, so it works in Claude Code and Cowork, not in chat
  on claude.ai.

## Install

In Claude Code:

```bash
/plugin marketplace add danoszz/penthera
/plugin install penthera@penthera
```

Penthera needs Node.js 22 or later. The first run downloads the `penthera` package
from npm; after that it runs offline.

## What it may do without asking

The skill pre-approves only Penthera's own commands (`penthera`, `npx -y penthera`,
`npx --no-install penthera`) and reading files. Claude asks you before it edits a
file or runs any other command.

## Data

Penthera reads your project on your machine and uploads nothing. A scan of a live
URL contacts only that URL, and only one you are allowed to test.

## More

- Website and public benchmark results: https://penthera.org
- Source and docs: https://github.com/danoszz/penthera
- Security policy: https://github.com/danoszz/penthera/blob/main/SECURITY.md
