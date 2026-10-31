# MCP client configs for `penthera mcp`

> **Starter.** For "what do I paste into my agent's MCP config?"

Ready-to-copy configs, each pinned to an exact version: 2.1.2. The test suite checks
every one with Penthera's own MCP rules (`mcp-unpinned`, `mcp-exec`,
`mcp-inline-secret`, `mcp-plain-http`).

| File | Client | Where it goes |
|---|---|---|
| `claude-code.mcp.json` | Claude Code | `.mcp.json` in the project (or `claude mcp add`) |
| `cursor.mcp.json` | Cursor | `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` |
| `vscode.mcp.json` | VS Code | `.vscode/mcp.json` in the project |
| `codex.config.toml` | Codex | `~/.codex/config.toml` |
| `windsurf.mcp_config.json` | Windsurf | `~/.codeium/windsurf/mcp_config.json` |

See [docs/commands/mcp.md](../commands/mcp.md) for what the server does and
does not do.
