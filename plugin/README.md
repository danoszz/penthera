# Penthera plugin

Penthera is an offline, rule-based cyber security agent for your own apps and AI
coding tools. Every finding comes from a rule you can read, and you can check
each one yourself. MIT licensed.

This folder is the plugin for Claude Code and Cowork. It holds the
Penthera skill (`skills/penthera`), which tells Claude how to scan your own
app, live URL, dependencies and agent setup with the Penthera CLI
(`npx -y penthera@2.4.0`), explain the findings and fix them with your approval.

The plugin starts no MCP server. To use Penthera's read-only MCP tools as well,
add the server yourself:

```bash
claude mcp add penthera -- npx -y penthera@2.4.0 mcp
```

The tools scan inside your project, never apply fixes and run no shell. Other
agents: see [the MCP docs](https://github.com/danoszz/penthera/blob/main/docs/commands/mcp.md).

## Install

In Claude Code:

```bash
/plugin marketplace add danoszz/penthera
/plugin install penthera@penthera
```

Penthera needs Node.js 22 or later. The first run downloads the `penthera` package
from npm; after that it runs offline.

## What it may do without asking

The skill pre-approves only reading files. Claude asks you before it runs any
command, Penthera's own included, and before it edits a file.

## Data

Penthera reads your project on your machine and uploads nothing. A scan of a live
URL contacts only that URL, and only one you are allowed to test.

## More

- Website and public benchmark results: https://penthera.org
- Source and docs: https://github.com/danoszz/penthera
- Security policy: https://github.com/danoszz/penthera/blob/main/SECURITY.md
