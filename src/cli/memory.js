/**
 * `penthera memory show | verify | forget [--all] | suppress <id> --reason <text>`
 *
 * Selects the project the same way a scan does: --repo <path> (default: the
 * current directory) or --url <url> for URL-only scans.
 */
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import {
  openMemory, projectIdFor, memoryRoot, forgetAll, buildViews,
} from "../../lib/memory/index.js";
import { suppressSeverity, LEGACY_SUPPRESS_CAP } from "../../lib/memory/views.js";

const USAGE = `
  Usage
    $ penthera memory show     [--repo <path> | --url <url>] [--json]
    $ penthera memory verify   [--repo <path> | --url <url>]
    $ penthera memory forget   [--repo <path> | --url <url>] [--all]
    $ penthera memory suppress <finding-id> --reason <text> [--severity <level>] [--expires <date>]

  --severity is the most severe the finding may be and stay suppressed
  (default medium). If it escalates past that, it shows again.

  Memory lives in ${memoryRoot()} (override with PENTHERA_HOME).
  It is never read from the scanned repo, and nothing in it is ever executed.
`;

// Memory content is data from earlier runs: strip control characters so a
// stored string cannot drive the terminal (ANSI escapes, cursor moves).
const clean = (s) => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");

export async function runMemoryCommand(argv, { out = (s) => process.stdout.write(s + "\n"), err = (s) => process.stderr.write(s + "\n") } = {}) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        repo:    { type: "string", short: "r" },
        url:     { type: "string" },
        all:     { type: "boolean", default: false },
        json:    { type: "boolean", default: false },
        reason:  { type: "string" },
        expires: { type: "string" },
        severity: { type: "string" },
        help:    { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    err(`  ${e.message}`);
    return 2;
  }
  const { values: opts, positionals } = parsed;
  const cmd = positionals[0];
  if (opts.help || !cmd) { out(USAGE); return cmd || opts.help ? 0 : 2; }

  if (cmd === "forget" && opts.all) {
    const root = memoryRoot();
    const existed = forgetAll({ root });
    out(existed ? `  Removed all Penthera memory in ${root}` : `  No memory at ${root}`);
    return 0;
  }

  let project;
  try {
    project = opts.url ? projectIdFor({ url: opts.url }) : projectIdFor({ repo: resolve(opts.repo || ".") });
  } catch (e) {
    err(`  ${e.message}`);
    return 2;
  }
  const mem = openMemory(project.id, { label: project.label });

  switch (cmd) {
    case "verify": {
      const r = mem.verify();
      if (r.ok) {
        out(`  OK  ${r.count} event(s), chain intact${r.count ? `, tip ${r.tip.slice(0, 16)}` : ""}`);
        out(`      ${mem.file}`);
        return 0;
      }
      err(`  BROKEN  line ${r.brokenAt}: ${r.reason}`);
      err(`      ${mem.file}`);
      err(`      Memory is ignored by scans until this is fixed. \`penthera memory forget\` starts over.`);
      return 1;
    }

    case "show": {
      const r = mem.verify();
      const v = r.ok ? buildViews(mem.events()) : null;
      if (opts.json) {
        out(JSON.stringify({ projectId: project.id, file: mem.file, chain: r, views: v }, null, 2));
        return r.ok ? 0 : 1;
      }
      out(`  Project   ${clean(project.label)}`);
      out(`  Id        ${project.id}`);
      out(`  Log       ${mem.file}`);
      out(`  Chain     ${r.ok ? `ok, ${r.count} event(s)` : `BROKEN at line ${r.brokenAt}: ${r.reason}`}`);
      if (!v) return r.ok ? 0 : 1;
      out(`  Scans     ${v.scans}`);
      out(`  Median time to fix  ${v.medianTimeToFixDays == null ? "-" : `${v.medianTimeToFixDays}d`}`);
      out("");
      out("  Suppressions");
      if (!v.suppressions.length) out("    none");
      for (const s of v.suppressions) {
        out(`    ${clean(s.id)}  ${clean(s.reason)}  (by ${clean(s.actor)}, up to ${s.severity || LEGACY_SUPPRESS_CAP}${s.expires ? `, until ${clean(s.expires)}` : ""})`);
      }
      out("");
      out("  Recipe success rate");
      if (!v.recipeSuccess.length) out("    none yet");
      for (const x of v.recipeSuccess) {
        const rate = x.rate == null ? "-" : `${Math.round(x.rate * 100)}%`;
        out(`    ${clean(x.framework).padEnd(12)} ${clean(x.recipe).padEnd(28)} ${rate.padStart(4)}  (${x.verified} ok / ${x.failed} failed / ${x.applied} applied)`);
      }
      out("");
      out("  Probe yield per stack");
      const stacks = Object.keys(v.probeRanking);
      if (!stacks.length) out("    none yet");
      for (const st of stacks) {
        out(`    ${clean(st)}`);
        for (const p of v.probeRanking[st].slice(0, 10)) {
          out(`      ${clean(p.probe).padEnd(24)} ${p.yield.toFixed(2)} per run  (${p.findings} in ${p.runs})`);
        }
      }
      return 0;
    }

    case "forget": {
      const existed = mem.forget();
      out(existed ? `  Removed memory for ${clean(project.label)}` : `  No memory for ${clean(project.label)}`);
      return 0;
    }

    case "suppress": {
      const id = positionals[1];
      if (!id || !/^[0-9a-f]{16}$/.test(id)) { err("  suppress needs a finding id (16 hex chars, the id printed next to each finding)"); return 2; }
      const reason = (opts.reason || "").trim();
      if (!reason) { err("  suppress needs --reason <text>"); return 2; }
      if (opts.expires && Number.isNaN(Date.parse(opts.expires))) { err("  --expires is not a date"); return 2; }
      if (opts.severity != null && !suppressSeverity(opts.severity)) { err("  --severity must be critical, high, medium, low or info"); return 2; }
      const r = mem.verify();
      if (!r.ok) { err(`  Memory chain is broken at line ${r.brokenAt}; not appending. Run \`penthera memory verify\`.`); return 1; }
      mem.append({ type: "fp_suppressed", data: { id, reason, actor: "user", ...(opts.severity ? { severity: opts.severity } : {}), ...(opts.expires ? { expires: opts.expires } : {}) } });
      out(`  Suppressed ${id} for ${clean(project.label)}, up to ${opts.severity || LEGACY_SUPPRESS_CAP}`);
      out("  This applies to --memory scans and the fix loop on this machine. For the pre-commit hook and your team, add it to penthera.suppress.json.");
      return 0;
    }

    default:
      err(`  Unknown memory command "${clean(cmd)}"`);
      out(USAGE);
      return 2;
  }
}
