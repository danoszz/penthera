/**
 * --giants on the command line: `penthera giants` (which tools are installed),
 * the flag checks, and the run after Penthera's own scan.
 */
import { parseArgs } from "node:util";
import { dirname, join, resolve } from "node:path";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { TOOLS, AREAS, areasOf, installHint, parseVersion, versionStatus } from "../../lib/giants/tools.js";
import { detectSandbox, minimalEnv, resolveTool, runTool } from "../../lib/giants/runner.js";
import { attachGiants, parseToolList, runGiants } from "../../lib/giants/index.js";
import { CODEQL_NOTICE } from "../../lib/giants/adapters/codeql.js";
import { loadPolicy } from "../../lib/install/policy.js";
import { bold, dim, green, yellow } from "./ansi.js";

export const GIANTS_HELP = `
  ${bold("penthera giants")}: the free scanners --giants can run, and whether you have them

  ${dim("Usage")}
    $ penthera giants              Each tool: found or not, path, version, install command
    $ penthera giants --json       The same as JSON

  ${dim("Scan flags")}  ${dim("(with --repo <path> or a URL)")}
        --giants                Run every supported tool that is installed (offline ones only)
        --with <list>           Run only these tools (implies --giants), e.g. gitleaks,trivy
        --without <list>        Skip these tools
        --giants-online         Also run tools or features that contact a service:
                                pip-audit, TruffleHog key verification, osv-scanner via its API
        --giants-timeout <s>    Seconds per tool (default 300)

  Penthera never installs or downloads a tool, its rules or its database.
  It reads PATH, skips anything inside the scanned project, and runs each
  tool with a minimal environment and, where it can, the network denied.
  CodeQL runs only with --with codeql. Docs: docs/commands/giants.md
`;

/** One row per tool: found, path, version, version status, install hint. */
export async function listTools({ cwd = process.cwd(), pathEnv = process.env.PATH || "", platform = process.platform } = {}) {
  const sandbox = detectSandbox();
  const rows = [];
  for (const tool of TOOLS) {
    const found = resolveTool(tool.bins, { root: null, cwd, pathEnv });
    const row = { id: tool.id, areas: areasOf(tool), mode: tool.mode, licence: tool.licence, minVersion: tool.minVersion, tested: tool.tested, found: Boolean(found.path), path: found.path, version: null, versionStatus: null, install: installHint(tool, platform), refused: found.refused, explicitOnly: Boolean(tool.explicitOnly), network: tool.network };
    if (found.path && tool.versionArgs) {
      const tmp = realpathSync(mkdtempSync(join(tmpdir(), "penthera-giants-")));
      try {
        const v = await runTool({ cmd: found.path, args: tool.versionArgs, cwd: tmp, env: minimalEnv({ tmp, keepHome: tool.keepHome, extra: tool.env || {} }), timeoutMs: 30_000, maxBytes: 1 << 20, network: "deny", sandbox });
        row.version = parseVersion(`${v.stdout}\n${v.stderr}`);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      row.versionStatus = versionStatus(tool, row.version);
    }
    rows.push(row);
  }
  return { sandbox, tools: rows };
}

const VERSION_NOTE = {
  tested: "",
  untested: "no recorded fixture for this version; runs with a warning",
  "below-minimum": "below the minimum; not run",
  unknown: "version unknown",
};

/** `penthera giants [--json]` */
export async function runGiantsCommand(argv) {
  let values;
  try {
    ({ values } = parseArgs({ args: argv, options: { json: { type: "boolean", default: false }, help: { type: "boolean", short: "h", default: false } } }));
  } catch (e) {
    process.stderr.write(`\n  error ${e.message}\n\n`);
    return 2;
  }
  if (values.help) {
    console.log(GIANTS_HELP);
    return 0;
  }
  const list = await listTools();
  if (values.json) {
    console.log(JSON.stringify({ schema: "penthera.giants-list/1", ...list }, null, 2));
    return 0;
  }
  const w = (s = "") => process.stdout.write(s + "\n");
  w("");
  w(`  ${bold("penthera giants")} ${dim("the free tools --giants can run; nothing is installed or downloaded")}`);
  w("");
  for (const area of AREAS) {
    w(`  ${bold(area.label)} ${dim(`(Penthera: ${area.penthera})`)}`);
    for (const t of list.tools.filter((x) => x.areas.includes(area.id))) {
      const name = t.id.padEnd(12);
      if (!t.found) {
        w(`    ${name} ${yellow("not found")}  ${dim(t.install)}`);
      } else {
        const v = t.version ? `${t.version}` : t.id === "zap" ? "version in its report" : "?";
        const note = [VERSION_NOTE[t.versionStatus] || "", t.explicitOnly ? `only with --with ${t.id}` : "", t.network === "online" ? "needs --giants-online" : ""].filter(Boolean).join("; ");
        w(`    ${name} ${green("found")}      ${v.padEnd(10)} ${dim(t.path)}${note ? `  ${yellow(note)}` : ""}`);
      }
      for (const r of t.refused) w(`    ${" ".repeat(12)} ${yellow("refused")} ${dim(`${r.path}: ${r.reason}`)}`);
    }
    w("");
  }
  w(`  ${dim(list.sandbox ? `Offline tools run with the network denied (${list.sandbox}).` : "No network sandbox (sandbox-exec or bwrap) here: tools' network use is not enforced.")}`);
  w(`  ${dim("Run them with: penthera --repo . --giants   (docs/commands/giants.md)")}`);
  w("");
  return 0;
}

/**
 * Check the --giants flags. Returns null when --giants is off, else the
 * options for runGiants(). Throws with a message for the user.
 */
export function giantsOptions(opts, { url, repo }) {
  const withList = parseToolList(opts.with, "--with");
  const without = parseToolList(opts.without, "--without");
  const on = Boolean(opts.giants || withList);
  for (const flag of ["without", "giants-online", "giants-timeout"]) {
    if (!on && opts[flag] != null && opts[flag] !== false) throw new Error(`--${flag} applies with --giants or --with.`);
  }
  if (!on) return null;
  if (!url && !repo) throw new Error("--giants needs --repo <path> or a URL: it runs the tools for that scan.");
  let timeoutS = null;
  if (opts["giants-timeout"] != null) {
    timeoutS = Number(opts["giants-timeout"]);
    if (!Number.isInteger(timeoutS) || timeoutS < 1 || timeoutS > 86_400) throw new Error(`--giants-timeout must be a whole number of seconds between 1 and 86400 (got "${opts["giants-timeout"]}").`);
  }
  return { with: withList, without, online: Boolean(opts["giants-online"]), timeoutS };
}

/**
 * What Penthera's own scan read, per --giants area, so an area is never shown
 * as unchecked when Penthera's rules ran there (and never as checked when they
 * read nothing).
 */
export function pentheraRead(merged, url) {
  const out = {};
  const families = Object.fromEntries((merged.coverage?.families || []).map((f) => [f.id, f]));
  const n = (k, w) => `${k} ${w}${k === 1 ? "" : "s"}`;
  for (const [area, family] of [["secrets", "secrets"], ["code", "routes"], ["infrastructure", "runtime-pins"]]) {
    const f = families[family];
    if (f?.ran) out[area] = { read: f.examined > 0, text: n(f.examined, "file") };
  }
  if (merged.deps) out.dependencies = { read: merged.deps.scanned > 0, text: n(merged.deps.scanned, "package") };
  else if (merged.coverage?.notRun?.some((x) => x.id === "deps")) out.dependencies = { read: false, text: "run penthera deps" };
  if (url && merged.reachable !== false && merged.executedProbes?.length) out.live = { read: true, text: n(merged.executedProbes.length, "check") };
  return out;
}

/**
 * Run the tools after Penthera's own scan and merge them into `merged`.
 * Returns the raw outputs (for the evidence bundle).
 */
export async function runGiantsForScan(merged, g, { opts, url, repo, deep, rateLimit, onPhase, write = (s) => process.stderr.write(s) }) {
  const policyRoot = repo ? resolve(repo) : process.cwd();
  const { policy, path: policyPath, warning } = loadPolicy(policyRoot);
  if (warning) write(`\n  ${yellow("warning")} ${warning}\n`);
  const gp = policy.giants;
  const rel = (p) => (p ? resolve(policyPath ? dirname(policyPath) : policyRoot, p) : null);
  if (g.with?.includes("codeql") && !gp.deny.includes("codeql")) write(`\n  ${yellow("CodeQL")} ${CODEQL_NOTICE}\n\n`);
  const languages = (merged.coverage?.languages || []).map((l) => l.language);
  const run = await runGiants({
    root: repo ? realpathSync(resolve(repo)) : null,
    url: url || null,
    typedUrl: url || null,
    with: g.with, without: g.without, online: g.online, timeoutS: g.timeoutS,
    deep, rate: rateLimit,
    policy: gp,
    settings: {
      semgrepRules: rel(gp.semgrepRules) || (process.env.PENTHERA_SEMGREP_RULES ? resolve(process.env.PENTHERA_SEMGREP_RULES) : null),
      nucleiTemplates: opts.nuclei ? resolve(opts.nuclei) : rel(gp.nucleiTemplates),
    },
    languages,
    pentheraRead: pentheraRead(merged, url),
    onPhase,
  });
  attachGiants(merged, run, { root: repo ? realpathSync(resolve(repo)) : null });
  return run.raw;
}
