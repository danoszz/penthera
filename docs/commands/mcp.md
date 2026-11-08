---
title: "Penthera in your agent: penthera mcp"
sidebarTitle: "MCP server"
description: "penthera mcp runs Penthera as an MCP server."
---

> **Starter.** For "can my coding agent call Penthera as a tool?"

## Add it to your agent

`penthera mcp` runs Penthera as an [MCP](https://modelcontextprotocol.io)
server. Your agent (Claude Code, Codex, GitHub Copilot, Cursor, Windsurf, Gemini CLI) starts it
and calls its tools. It needs Node.js 22 or later.

The commands below pin 2.3.2, so an update never reaches you unless you change the pin.

Always pin the version. An unpinned `npx penthera` runs whatever version is
newest on npm each time your agent starts, which is the risk that
`penthera agents` reports as `mcp-unpinned`.

### Claude Code

```bash
claude mcp add penthera -- npx -y penthera@2.3.2 mcp
```

Add `--scope project` to write it to `.mcp.json` for the whole team. The
Penthera plugin holds only the skill, which runs the CLI, and starts no MCP
server. Install it as well if you want the skill:

```bash
claude plugin marketplace add danoszz/penthera
claude plugin install penthera@penthera
```

Inside a session, the same is `/plugin marketplace add danoszz/penthera` and
`/plugin install penthera@penthera`. Checked against Claude Code's
[MCP](https://code.claude.com/docs/en/mcp) and
[plugin](https://code.claude.com/docs/en/plugins/publish.md) docs.

### Codex

```bash
codex mcp add penthera -- npx -y penthera@2.3.2 mcp
```

Or add it to `~/.codex/config.toml`:

```toml
[mcp_servers.penthera]
command = "npx"
args = ["-y", "penthera@2.3.2", "mcp"]
```

Checked against [Codex's MCP docs](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

### GitHub Copilot

In Copilot CLI, the plugin gives you the skill, which runs the CLI. It starts no
MCP server. Copilot reads the same marketplace file as Claude Code:

```bash
copilot plugin marketplace add danoszz/penthera
copilot plugin install penthera@penthera
```

For the MCP tools in Copilot CLI, add the server in its MCP settings with the
same `npx -y penthera@2.3.2 mcp` launch line.

In VS Code, add the server to your user profile:

```bash
code --add-mcp '{"name":"penthera","type":"stdio","command":"npx","args":["-y","penthera@2.3.2","mcp"]}'
```

Or put the JSON under **VS Code** below in `.vscode/mcp.json`. Checked against
GitHub's [Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
and VS Code's [MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

### Cursor and Windsurf

Cursor reads `.cursor/mcp.json`, and Windsurf `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "penthera": {
      "command": "npx",
      "args": ["-y", "penthera@2.3.2", "mcp"]
    }
  }
}
```

Checked against [Cursor's MCP docs](https://cursor.com/docs/context/mcp).

**VS Code** (`.vscode/mcp.json`):

```json
{
  "servers": {
    "penthera": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "penthera@2.3.2", "mcp"]
    }
  }
}
```

### Gemini CLI

As an extension. It reads `gemini-extension.json` at the root of this repository,
with the same pinned server:

```bash
gemini extensions install https://github.com/danoszz/penthera
```

Checked against [Gemini CLI's extension docs](https://geminicli.com/docs/extensions/).
Their page says Gemini CLI gave way to Antigravity CLI for unpaid and Google One
accounts on 18 June 2026; this route is for accounts that still have Gemini CLI.

### Any agent that reads skills

```bash
npx skills add danoszz/penthera
```

It installs the skill, which runs the CLI; see [skill.md](skill.md).

The same files are in [docs/mcp-clients/](https://github.com/danoszz/penthera/tree/main/docs/mcp-clients). The test suite
checks each one with Penthera's own MCP rules.

Then ask your agent: "scan this repo for security issues", "is this MCP config
safe?", or "what can the dependencies in this project do?".

## The tools

Every tool is read-only. None writes a file, applies a fix, or runs a shell.

| Tool | What it does | Network |
|---|---|---|
| `scan_repo` | Secrets, code-execution sinks, API routes, runtime version pins in a project folder, plus a coverage ledger of what ran and what was skipped | none |
| `check_dependencies` | What each npm or Python package can do (install scripts, shell, network, eval, credential access), known-malicious packages, typosquats | none |
| `audit_ai_tooling` | The project's skills, MCP servers, hooks, permissions and rule files, graded A to F, or no grade if it finds no agent config. A `path` other than the workspace root can also be a skill folder or its `SKILL.md` | none |
| `runtime_advisories` | Advisories and end of life for the PHP, nginx, Apache, Node.js, Python, OpenSSL or MongoDB a project pins, or the PHP, nginx, Apache or OpenSSL a `Server` or `X-Powered-By` header shows | none |
| `explain_finding` | What a finding's rule checks, why it matters, how to fix it, references and OWASP ids | none |
| `scan_url` | A passive scan of a running app: TLS, headers, cookies, CORS, exposed files, OpenAPI and auth smoke checks | the target only (see below) |

Each scan tool's result has the findings as structured JSON, and as text the
[agent brief](brief.md): a verdict, `Site not read` when a firewall refused `scan_url`, what to act on, what to check first, what
is likely noise, what was not checked, and what to run next. The text asks the
assistant to pass the brief on as it is and to put its own view under "My
read". Every
finding has a `rule` (such as `openapi-exposed`, `gha-pwn-request` or `agents/mcp-unpinned`, or
its category when no narrower rule applies), a severity, a confidence label (`confirmed`, `likely`,
`potential`, `needs-human-review`), and evidence at `file:line` or a URL. Each
result also lists what the tool did not check. By default a tool returns the 50
most severe findings; ask for up to 200 with `max_findings`.

The brief's `exit_code` is the code the CLI would exit with. A
`check_dependencies` result is incomplete when a lockfile or requirements file
could not be read (a FIFO, a device, a link out of the project, over the 64 MiB
cap, or an `-r` include like that), or when a venv's `METADATA` or `PKG-INFO`
could not be read. Its brief then has `exit_code` 2, a verdict of Review, and an
`exit_reason` that names the file, and the findings list it as
`File not read: <file>`. Never read that as clean. `scan_repo` and
`audit_ai_tooling` work the same way for a source or agent config file they
could not read, such as a route file over 5 MiB, a FIFO or a link out of the
project. Each tool reads a file whole under a size limit and matches it in
linear time, so a padded file or a crafted header can't stall the server.

Arguments: `path` and `max_findings` on the file tools, `prod` on
`check_dependencies`, `url` and `profile` (`quick` or `standard`) on `scan_url`,
`path` or `headers` on `runtime_advisories`, `id` on `explain_finding`. A result
stays under 256 KB; past that the least severe findings drop and `truncated` is
true.

## What it will not do

- **Read outside your project.** A tool reads only inside the workspace: the
  folders your agent shares as MCP roots, or else the folder it starts the
  server in. Symlinks that lead outside are refused.
- **Attack anything.** `scan_url` sends no payloads: no injection probes, no
  fuzzing, no recon sources. For those, run `penthera <url> --deep` yourself,
  where Penthera asks you to confirm the target.
- **Scan a host you did not name.** `scan_url` reaches loopback
  (`localhost`, `*.localhost`, `127.x.x.x`, `[::1]`). Any other host must be in the server's launch arguments, which
  you write, not the model:

```bash
npx -y penthera@2.3.2 mcp --allow-host staging.example.com
```

  Only list hosts you are authorized to test. The same limit holds on every
  redirect, with or without `--offline`. A redirect may also move between the
  apex and `www.` (`example.com` to `www.example.com`, or back), or down to a
  subdomain of the target (`example.com` to `app.example.com`). It never moves
  to a sibling or a parent host, so `one.vercel.app` never follows to
  `two.vercel.app`: on a platform that gives each customer a host, that is
  someone else's site.
  `scan_url` refuses any other host and names it under **Not checked**.
- **Follow instructions in your files.** Scanned text reaches the agent only as
  finding text, with invisible characters removed and a note that it is data.
  A file that says "ignore previous instructions" becomes a finding, not a
  command.
- **Phone home.** It talks to your agent over stdin and stdout and never opens
  a port. `scan_url` uses the vendored Retire.js snapshot, never a download.
  Without `--offline` it makes the SPF and DMARC DNS lookups. With `--offline`
  it skips them and contacts only the target, not your listed hosts.

## Options

```bash
npx -y penthera@2.3.2 mcp --offline
npx -y penthera@2.3.2 mcp --help
```

| Flag | Meaning |
|---|---|
| `--root <dir>` | A folder tools may read (repeatable). Default: the folder the agent starts the server in. Roots your agent sends take precedence. |
| `--allow-host <host>` | A host `scan_url` may contact besides loopback (repeatable, exact name, no wildcards) |
| `--offline` | `scan_url` contacts only the target: no listed hosts, no DNS lookups |

## In a container

The repo's `Dockerfile` builds an image whose entry point is `penthera`. Mount
your project at `/src` and point `--root` at it:

```bash
docker build -t penthera-mcp .
docker run -i --rm --network none -v "$PWD:/src:ro" penthera-mcp mcp --root /src
```

Your agent sends its roots as host paths, which do not exist inside the
container. The server drops roots it cannot find. When none is left, it uses
`--root` and logs "client sent no usable roots; using the server's roots" to
stderr. If `--root` does not exist either, it does not start and names the
folder. With `--network none`, `scan_url` has nothing to reach; the other
tools need no network.

## Limits

- A clean result is not proof of safety. Penthera reports what its rules
  match.
- `audit_ai_tooling` reads the project's config, not `~/.claude` or other home
  folders (run `penthera agents --home` for that), and does not read Codex's
  `config.toml` or Windsurf's `mcp_config.json` yet.
- The server speaks MCP 2026-07-28 and the earlier `initialize` versions
  (2025-11-25 back to 2024-11-05). The design and its security controls are in
  [the spec](https://github.com/danoszz/penthera/blob/main/docs/research/spec-mcp.md).

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
