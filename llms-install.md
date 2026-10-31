# Installing Penthera's MCP server

> **Project page.** For an agent asking "how do I add Penthera to Cline?"

Penthera runs as an MCP server over stdio. It needs Node.js 22 or later.
Check with `node --version` before you add it.

Add this to `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "penthera": {
      "command": "npx",
      "args": ["-y", "penthera@2.1.2", "mcp"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Keep the version pinned. An unpinned `npx penthera` runs whatever is newest on
npm each time the server starts.

No API key and no account. The server takes three optional flags, added after
`mcp` in `args`:

| Flag | Meaning |
|---|---|
| `--root <dir>` | A folder the tools may read (repeatable). Default: the folder Cline starts the server in. Roots Cline sends take precedence. |
| `--allow-host <host>` | A host `scan_url` may contact besides loopback. Add one only if the user is authorized to test it. |
| `--offline` | `scan_url` contacts only the target |

## What the tools may do

All six tools are read-only:

- They read only inside the workspace roots. Symlinks that lead outside are
  refused.
- They never write a file, apply a fix or run a shell.
- `scan_url` is passive (no injection probes, no fuzzing) and reaches only
  `localhost`, `127.0.0.1`, or a host listed with `--allow-host`. A redirect may
  also move within the target's registrable domain.
- Text from scanned files reaches you as finding text, marked as data.

## Check that it works

Ask Cline to run `explain_finding` with id `secrets`. Then run `scan_repo` on
the open project. Each result lists its findings with a severity, a confidence
label and the `file:line`, and says what it did not check.

The full reference is [docs/commands/mcp.md](docs/commands/mcp.md).
