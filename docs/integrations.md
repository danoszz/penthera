---
title: "Penthera in your coding tool"
sidebarTitle: "Your coding tool"
description: "Penthera runs on your machine."
---

> **Starter.** For "I build with Cursor, Claude Code, Lovable or another AI tool: how do I add Penthera?"

Penthera runs on your machine. Pick your tool below. There are three ways in:

- **Your coding agent calls it** through the MCP server (`npx -y penthera@2.1.2 mcp`). This works in tools that run on your computer.
- **You run it** in a terminal, or in CI with the [GitHub Action](commands/action.md).
- **You check the live app** on [penthera.org](https://penthera.org). It's passive, nothing is stored, and it only needs a URL. This is the route for browser-only app builders.

The MCP tools only read your project, never apply fixes, run no shell and send no attack payloads. `scan_url` reaches loopback only, unless you add `"--allow-host", "app.example.com"` to `args`, and only for a host you're allowed to test. A redirect may also move within the target's registrable domain. Details: [the MCP server](commands/mcp.md).

The commands below pin a version on purpose: an update never reaches you unless you change the pin.

## Coding agents and editors

| Tool | Where the config goes | Docs |
|---|---|---|
| Claude Code | `claude mcp add` (project scope writes `.mcp.json`), or the plugin | [MCP](https://code.claude.com/docs/en/mcp) |
| Cursor | `.cursor/mcp.json` | [MCP](https://cursor.com/docs/context/mcp) |
| VS Code (Copilot agent mode) | `.mcp.json` at the workspace root, or `.vscode/mcp.json` | [MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| OpenAI Codex | `codex mcp add`, or `.codex/config.toml` | [MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) |
| Gemini CLI | the extension, or `.gemini/settings.json` | [MCP servers](https://geminicli.com/docs/tools/mcp-server/) |
| Google Antigravity | `.agents/mcp_config.json` | [MCP](https://antigravity.google/docs/mcp) |
| Windsurf (Devin Desktop) | `mcp_config.json` | [MCP](https://docs.devin.ai/desktop/cascade/mcp) |
| Cline | `cline_mcp_settings.json` | [Configuring MCP servers](https://docs.cline.bot/mcp/configuring-mcp-servers) |
| Zed | `context_servers` in `settings.json` | [MCP](https://zed.dev/docs/ai/mcp) |
| JetBrains AI Assistant | Settings, Tools, AI Assistant, Model Context Protocol | [MCP](https://www.jetbrains.com/help/ai-assistant/mcp.html) |
| JetBrains Junie | `.junie/mcp/mcp.json` | [MCP](https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html) |
| Kiro | `.kiro/settings/mcp.json` | [MCP configuration](https://kiro.dev/docs/mcp/configuration/) |
| Continue | `.continue/mcpServers/penthera.yaml` (agent mode) | [MCP](https://docs.continue.dev/customize/deep-dives/mcp) |

### Claude Code

```bash
claude mcp add --scope project penthera -- npx -y penthera@2.1.2 mcp
```

Or install the plugin (the skill plus the pinned server) from Claude Code's prompt: `/plugin marketplace add danoszz/penthera`, then `/plugin install penthera@penthera`.

### Cursor, Windsurf, Cline, Antigravity, Kiro, Junie, JetBrains, VS Code (`.mcp.json`)

All of these read the same shape:

```json
{
  "mcpServers": {
    "penthera": {
      "command": "npx",
      "args": ["-y", "penthera@2.1.2", "mcp"]
    }
  }
}
```

One `.mcp.json` at the root of your repo serves Claude Code and VS Code together. Windsurf's file path changed when it became Devin Desktop: check your build's MCP settings for where it reads `mcp_config.json`.

### VS Code, older format (`.vscode/mcp.json`)

```json
{
  "servers": {
    "penthera": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "penthera@2.1.2", "mcp"]
    }
  }
}
```

### OpenAI Codex

```bash
codex mcp add penthera -- npx -y penthera@2.1.2 mcp
```

### Gemini CLI

```bash
gemini extensions install https://github.com/danoszz/penthera
```

Gemini CLI now needs a paid API key or an Enterprise licence. Google moved free use to Antigravity, which uses the JSON above.

### Zed (`settings.json`)

```json
{
  "context_servers": {
    "penthera": {
      "command": "npx",
      "args": ["-y", "penthera@2.1.2", "mcp"],
      "env": {}
    }
  }
}
```

### Continue (`.continue/mcpServers/penthera.yaml`)

```yaml
name: Penthera
version: 0.0.1
schema: v1
mcpServers:
  - name: penthera
    command: npx
    args: ["-y", "penthera@2.1.2", "mcp"]
```

## App builders (Lovable, Bolt, Base44, Replit, v0)

These run in the browser and only accept MCP servers by URL. Penthera's server runs on your machine, so it can't be added there. That's deliberate: your code stays local. Two routes work instead:

| Builder | 1. Check the live app | 2. Scan the code |
|---|---|---|
| **Lovable** | paste your `*.lovable.app` URL into [penthera.org](https://penthera.org) | connect GitHub (two-way sync), clone, `npx penthera@2.1.2 --repo .` |
| **Bolt.new** | the published URL into penthera.org | GitHub sync, then the CLI or the Action |
| **Base44** | the published URL into penthera.org | GitHub sync (Builder plan and up), clone, the CLI |
| **Replit** | the deployed URL into penthera.org | in the Shell: `npx penthera@2.1.2 --repo .` (needs Node.js 22 or later) |
| **v0** | the **production** URL into penthera.org (preview links can sit behind a Vercel login) | connect GitHub and add the [Action](commands/action.md) to the pull requests v0 opens |

Once the code is on GitHub, the Action checks every pull request: dependencies, AI-tool config and the code. See [the Action](commands/action.md) and [a ready workflow](https://github.com/danoszz/penthera/blob/main/docs/examples/pr-dependency-review.yml).

After the GitHub sync, one file checks the agent config (skills, MCP servers, hooks) on every pull request and reports to Code scanning: copy [`github-actions-agents.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-agents.yml) into `.github/workflows/`, or let `penthera init` write it.

Most of these builders also scan before publish. [Before you publish](before-you-publish.md) lists what each one checks and where Penthera adds a second check.

Mobile builders (Rork and similar) usually have no web URL. Sync to GitHub and scan the repository.

## Limits

- **Browser-only builders:** they can't run Penthera's MCP server, because it needs a local process.
- **Live check:** penthera.org checks one public page and up to 8 of its scripts. It's passive and doesn't log in.
- **Configs in these tools change often.** Each link above goes to the tool's own docs. If a path moved, the tool's docs win.
