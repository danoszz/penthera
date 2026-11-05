/**
 * `penthera mcp`: run Penthera as an MCP server on stdio. The MCP client
 * (Claude Code, Cursor, Codex, VS Code, Windsurf) starts this process; it
 * never listens on a port. See docs/commands/mcp.md.
 */
import { parseArgs } from "node:util";
import { normalizeRoots, parseAllowHosts } from "../mcp/workspace.js";

export const MCP_HELP = `
  penthera mcp: Penthera as an MCP server, for Claude Code, Cursor, Codex, VS Code and other agents

  Usage
    $ penthera mcp [--root <dir>] [--allow-host <host>] [--offline]

  Started by your MCP client over stdio; it does not listen on a port. Add it with a pinned version:
    claude mcp add penthera -- npx -y penthera@<version> mcp

  Tools (all read-only; nothing is ever fixed or written)
    scan_repo            Secrets, code sinks, routes, runtime pins in a project folder
    scan_url             Passive scan of a running app (no attack payloads)
    check_dependencies   What npm and Python dependencies can do, offline
    audit_ai_tooling     Skills, MCP servers, hooks and permissions of the project
    explain_finding      Why a rule matters and how to fix it
    runtime_advisories   Advisories for the PHP, nginx, Node.js... a project or header shows

  Options
        --root <dir>        Workspace folder tools may read (repeatable). Default: the folder the
                           client starts the server in. Clients that send MCP roots override it.
        --allow-host <host> A host scan_url may contact besides loopback (repeatable, exact name).
                           Only list targets you are authorized to test. A redirect may also move
                           between the apex and www., or to a subdomain of the target; never to a
                           sibling or a parent host. Any other host is refused.
        --offline           scan_url contacts only the target: no listed hosts, no DNS lookups
    -h, --help              Show this help
`;

/** Parse `penthera mcp` arguments. Throws on anything unknown. */
export function parseMcpArgs(argv, cwd = process.cwd()) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      root: { type: "string", multiple: true },
      "allow-host": { type: "string", multiple: true },
      offline: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (positionals.length) throw new Error(`penthera mcp takes no positional arguments, got: ${positionals.join(" ")}`);
  const asked = values.root?.length ? values.root : [cwd];
  const roots = normalizeRoots(asked);
  if (!roots.length) throw new Error(`No usable --root: ${asked.join(", ")} (each must be an existing folder)`);
  return { help: values.help, roots, allowHosts: parseAllowHosts(values["allow-host"]), offline: values.offline };
}

export async function runMcp(argv, { version }) {
  let opts;
  try {
    opts = parseMcpArgs(argv);
  } catch (e) {
    process.stderr.write(`penthera mcp: ${e.message}\n`);
    return 2;
  }
  if (opts.help) {
    process.stdout.write(MCP_HELP.replace("<version>", version) + "\n");
    return 0;
  }

  // stdout carries protocol messages only. Anything a scanner prints goes to stderr.
  const out = process.stdout.write.bind(process.stdout);
  const toStderr = (...a) => process.stderr.write(a.map(String).join(" ") + "\n");
  for (const k of ["log", "info", "warn", "debug", "trace", "dir", "table"]) console[k] = toStderr;
  process.stdout.write = (chunk, ...rest) => process.stderr.write(chunk, ...rest);

  const { serve } = await import("../mcp/server.js");
  process.stderr.write(`penthera mcp ${version}: stdio, roots ${opts.roots.join(", ")}${opts.allowHosts.length ? `, allowed hosts ${opts.allowHosts.join(", ")}` : ""}${opts.offline ? ", offline" : ""}\n`);
  await serve({
    input: process.stdin,
    write: (line) => out(line + "\n"),
    serverRoots: opts.roots,
    allowHosts: opts.allowHosts,
    offline: opts.offline,
    version,
    log: (m) => process.stderr.write(`penthera mcp: ${m}\n`),
  });
  return 0;
}
