/**
 * `penthera brief <report.json...> [--json]`
 *
 * Merges one or more Penthera JSON reports (a repo, deps and agents scan) into
 * one agent brief and prints it. Reads only the files named; runs no scan.
 * Exit 0 on success, 2 on a usage error or a file that is not a report.
 */
import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { buildBrief, formatBrief } from "../report/brief.js";
import { markdownPathFromJson } from "../report/markdown.js";
import { writeCards, DEFAULT_CARD_OUT } from "../card/index.js";
import { formatJson } from "../reporter.js";

const HELP = `
  penthera brief <report.json...> [--json] [--card] [--card-out <path>]

  Merges Penthera JSON reports (written with -o) into one short brief:
  verdict, act on, check first, likely noise, not checked, next. Built for
  AI assistants to pass on as it is. Runs no scan; reads only these files.

    $ penthera --repo . -o reports/repo.json
    $ penthera deps . -o reports/deps.json
    $ penthera agents . -o reports/agents.json
    $ penthera brief reports/repo.json reports/deps.json reports/agents.json

  --json             Print the brief as JSON (schema penthera.brief/1).
  --card             Also write a share card of all the reports together:
                     penthera-card.png and penthera-card-og.png, each with an .svg.
  --card-out <path>  Where to write the card (default: penthera-card).
  See docs/commands/brief.md.
`;

export function runBrief(argv, { out = process.stdout, err = process.stderr, version = "", date } = {}) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: "boolean", default: false },
        card: { type: "boolean", default: false },
        "card-out": { type: "string" },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    err.write(`  ${e.message}\n${HELP}`);
    return 2;
  }
  const { values: opts, positionals: files } = parsed;
  if (opts.help) {
    out.write(HELP);
    return 0;
  }
  if (!files.length) {
    err.write(`  Name at least one JSON report.\n${HELP}`);
    return 2;
  }
  const results = [];
  for (const f of files) {
    let r;
    try {
      r = JSON.parse(readFileSync(f, "utf-8"));
    } catch (e) {
      err.write(`  ${f}: ${e.code === "ENOENT" ? "not found" : "not a JSON file"}\n`);
      return 2;
    }
    if (!r || !Array.isArray(r.findings)) {
      err.write(`  ${f}: not a Penthera report (no findings list)\n`);
      return 2;
    }
    results.push(r);
  }
  const brief = buildBrief(results, { reports: files.map(markdownPathFromJson) });
  out.write(opts.json ? formatJson(brief) : formatBrief(brief));
  if (opts.card || opts["card-out"]) {
    try {
      const { paths } = writeCards(brief, results, { version, out: opts["card-out"] || DEFAULT_CARD_OUT, date });
      err.write(`  Share card ${paths.filter((p) => p.endsWith(".png")).join(", ")} (and .svg; made offline, nothing uploaded)\n`);
    } catch (e) {
      err.write(`  ${e.code === "ECARDREFUSED" ? e.message : `The share card was not written: ${e.message}`}\n`);
      return 2;
    }
  }
  return 0;
}

/**
 * Whether a scan prints the brief instead of the terminal report: with
 * --brief, or by default when stdout is not a terminal (an agent or a pipe)
 * and this is not CI. PENTHERA_BRIEF=1 or 0 overrides the default.
 */
export function wantBrief(opts, { stdout = process.stdout, env = process.env } = {}) {
  if (opts.brief) return true;
  if (opts.verbose) return false;
  if (env.PENTHERA_BRIEF === "1") return true;
  if (env.PENTHERA_BRIEF === "0") return false;
  return !stdout.isTTY && !env.CI;
}

/** The exit 0 line goes on a terminal report of a URL or repo scan, not on a run that scanned neither. */
export function wantExitNote({ code, url, repo, opts, custom }) {
  return code === 0 && !!(url || repo) && !opts.json && !opts.quiet && !custom && !wantBrief(opts);
}

/** The full-report paths a brief points to. */
export function briefReports(opts) {
  return [opts.output && markdownPathFromJson(opts.output), opts.markdown].filter(Boolean);
}
