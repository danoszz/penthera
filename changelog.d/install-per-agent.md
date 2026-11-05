section: Docs

- **One install line per agent.** The README, `docs/commands/mcp.md` and `docs/commands/skill.md` give a pinned, copyable line for Claude Code, Codex, GitHub Copilot (CLI and VS Code), Gemini CLI, Cursor and Windsurf, and `npx skills add`, each checked against the agent's own docs.
- **The plugin works in GitHub Copilot CLI and Codex too.** `plugin/` now also carries Agent Plugins 1.0.0 manifests, `plugin.json` and `mcp.json`, beside the Claude Code ones. A test keeps the two sets equal, and the internal audit checks their versions.
