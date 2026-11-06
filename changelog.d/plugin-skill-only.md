section: Changed

- **The Claude Code plugin is skill-only.** It no longer starts Penthera's MCP
  server: Anthropic's plugin directory accepts an MCP server that runs on your
  computer only from verified publishers, and refused the plugin for it. The
  skill runs the pinned CLI (`npx -y penthera@2.3.2`), and you approve each run.
  To keep the MCP tools, add the server yourself:
  `claude mcp add penthera -- npx -y penthera@2.3.2 mcp`. The same goes for the
  Agent Plugins copy that GitHub Copilot and Codex read. The repo's own
  `.mcp.json` stays: it is this repo's project config, not part of the plugin.
