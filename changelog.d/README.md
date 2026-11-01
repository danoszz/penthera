# Changelog fragments

Each pull request adds **one file here** instead of editing `CHANGELOG.md`, so
parallel pull requests never conflict on the changelog.

Name it after the change, for example `changelog.d/mcp-server.md`:

```markdown
section: Added

- **`penthera mcp`: an MCP server for coding agents.** What changed for users,
  in the voice of [docs/voice.md](../docs/voice.md).
```

Sections, in release order: Security, Added, Detection, Changed, Fixed,
Removed, Site, Docs.

## When a change needs no doc

A pull request that touches the public surface (CLI flags and output, MCP
tools, rules, the GitHub Action) must change a doc that owns it. If nothing
changes for users, say why in one line under `section:`, instead:

```markdown
section: Fixed
docs: none, the flag parser moved and nothing changes for users

- **What changed.** The notes, as usual.
```

The reason needs at least 8 characters, and the line never reaches
`CHANGELOG.md`. `scripts/ci/docs-gate.mjs` checks this on every pull request;
try it before you push with `npm run docs:gate`.

## Checks and release

`npm run changelog` checks every fragment (it also runs in `npm test`). At
release time, `npm run changelog -- --release <version> <YYYY-MM-DD>` moves
them into `CHANGELOG.md` and deletes the files.
