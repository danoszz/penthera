section: Changed
docs: none, this repository only; CONTRIBUTING.md describes it

- **This repository pins its own skill and MCP server in `penthera.lock`.** `penthera agents .` on the repo no longer reports a missing lock, and a later change to `skills/penthera/` or the root `.mcp.json` shows up until it is re-pinned. CONTRIBUTING says when to re-pin, including in the release steps.
