section: Changed
docs: none, the tool descriptions live in the server itself; docs/commands/mcp.md lists the tools and stays correct

- **The MCP tools say when to use each one and what comes back.** Each tool's
  description now names the sibling to use instead (packages, agent config, a
  running app) and the result's shape (the brief first, then findings with rule,
  severity, confidence and file:line). Agents pick the right tool more often.
