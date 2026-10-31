# MCP directory listing text

> **Project page.** For "what do we paste into mcp.so, Smithery and Glama?"

Ready-to-paste text for MCP directories. **Not submitted.** Submitting is the
maintainer's step, after `penthera@2.1.2` is on npm and the server is in the
official MCP Registry. Keep the version pinned everywhere it appears.

## Fields

| Field | Text |
|---|---|
| Name | Penthera |
| Registry name | `io.github.danoszz/penthera` |
| One line (under 100 characters) | Offline, rule-based security checks for your repo, dependencies, AI agent config and local app. |
| Category | Security |
| Tags | security, sast, secrets, dependencies, supply-chain, mcp-security, agent-security, offline |
| Transport | stdio |
| License | MIT |
| Repository | https://github.com/danoszz/penthera |
| Website | https://penthera.org |
| Docs | https://github.com/danoszz/penthera/blob/main/docs/commands/mcp.md |

## Description

Penthera is an open-source security agent that runs on your own machine. As an
MCP server it gives your coding agent six read-only tools:

- `scan_repo`: hardcoded secrets, code-execution sinks, API routes and runtime
  version pins, with evidence at file:line;
- `check_dependencies`: what each npm or Python package can do (install
  scripts, shell, network, eval, credential access), known-malicious packages
  and typosquats, read offline from the lockfile;
- `audit_ai_tooling`: the project's skills, MCP servers, hooks and
  permissions, checked for hidden instructions, curl-pipe-shell, unpinned
  packages and inline secrets, graded A to F when it finds agent config;
- `runtime_advisories`: published advisories and end of life for the PHP,
  nginx, Apache, Node.js, Python or OpenSSL an app runs;
- `explain_finding`: why a rule matters and how to fix it;
- `scan_url`: a passive scan of a running app (headers, TLS, cookies, CORS,
  exposed files), loopback or hosts you list.

Every finding comes from a deterministic rule, not a model, with a confidence
label and the limits of the check. Tools read only inside your workspace, never
apply fixes, never run a shell, and send no attack payloads. There is no
telemetry and no port: the client starts the server over stdio. One runtime
dependency.

## Install

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

Claude Code: `claude mcp add penthera -- npx -y penthera@2.1.2 mcp`

## Per directory

- **mcp.so**: submit through the site's "Submit" form with the GitHub URL, the
  one line and the description above.
- **Smithery**: list it as a local (stdio) server. Smithery's hosted remote
  option does not apply: Penthera reads the user's own files and opens no
  listener. Use the install JSON above.
- **Glama**: Glama indexes GitHub repositories. Claim the server with the
  GitHub account that owns the repository, then check that the listing uses
  the pinned install command, not an unpinned `npx penthera`.

Directories change their forms often; check each one's current submission page
before pasting.
