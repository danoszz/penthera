/**
 * `penthera diff [<ref>]`: only the findings this branch added.
 *
 * It scans the repo as it is now (your working tree, committed or not) and
 * the repo at the merge-base of HEAD and <ref> (default: main), then keeps the
 * findings the merge-base does not have, compared the way --baseline compares
 * (src/cli/baseline.js): by finding, severity and, for secrets and eval or
 * exec sinks, what each one holds. A key moved to another line is not new; a
 * second key in the same file is.
 *
 * The merge-base is read with `git archive` into a temporary folder that is
 * removed afterwards: nothing in the repo, its index or its work tree changes,
 * and git runs with the safe config (lib/git.js). Offline: nothing is fetched,
 * so <ref> is what your clone has.
 */
import { parseArgs } from "node:util";
import { existsSync, mkdirSync, realpathSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { git, gitToplevel } from "../../lib/git.js";
import { withTempDir } from "../../lib/tmp.js";
import { tagSalt } from "../../lib/secret-tags.js";
import { scanRepo } from "../scan-repo.js";
import { compareFindings } from "./baseline.js";
import { buildBrief, formatBrief } from "../report/brief.js";
import { exitCodeOf } from "../report/exit.js";
import { printReport, printFindings, printError, writeJsonReport, writeSarifReport, createProgress, formatJson } from "../reporter.js";
import { writeMarkdownReport, markdownPathFromJson } from "../report/markdown.js";
import { wantBrief, briefReports } from "./brief.js";

export const DIFF_SCHEMA = "penthera.diff/1";
// Tried in this order when no ref is named.
const DEFAULT_REFS = ["main", "origin/main", "master", "origin/master"];

export const DIFF_HELP = `
  penthera diff [<ref>] [--repo <path>] [--json] [--brief] [-o <file>] [--markdown <file>] [--sarif <file>]

  Only the findings this branch added: scans the repo now and at the
  merge-base with <ref> (default: main, then origin/main, master), and shows
  what the merge-base does not have. Offline; changes nothing in the repo.
  Exits 1 when a new finding is critical or high.

    $ penthera diff
    $ penthera diff origin/main --sarif new.sarif

  -r, --repo <path>      The repo to compare (default: .)
      --json             Print the result as JSON (schema ${DIFF_SCHEMA})
      --brief            Print the agent brief of the new findings
  -o, --output <file>    Write the JSON report of the new findings (+ a .md next to it)
      --markdown <file>  Write a Markdown report of the new findings
      --sarif <file>     Write SARIF of the new findings (GitHub code scanning)
  -q, --quiet            New findings only, one per line
  See docs/commands/diff.md.
`;

const resolves = (cwd, ref) => {
  try {
    return git(cwd, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]).trim() || null;
  } catch {
    return null;
  }
};

/** The merge-base of HEAD and the ref, or { error }. */
export function mergeBaseOf(top, ref) {
  if (ref != null && (!ref || ref.startsWith("-") || /[\s\0]/.test(ref))) return { error: `Not a git ref: ${ref}` };
  if (!resolves(top, "HEAD")) return { error: "This repo has no commits yet, so there is no branch to compare." };
  const name = ref ?? DEFAULT_REFS.find((r) => resolves(top, r));
  if (!name) return { error: `No ${DEFAULT_REFS.slice(0, 3).join(", ")} or origin/master here. Name the branch to compare against: penthera diff <ref>.` };
  if (!resolves(top, name)) return { error: `${name} is not a branch, tag or commit in this repo. Fetch it first (git fetch), or name another: penthera diff <ref>.` };
  let sha;
  try {
    sha = git(top, ["merge-base", "HEAD", name]).trim();
  } catch {
    return { error: `HEAD and ${name} have no commit in common, so there is nothing to compare against.` };
  }
  return { ref: name, sha, head: resolves(top, "HEAD") };
}

/** The tree of `sha`, unpacked under `dir` (git archive, then tar). Returns its folder. Throws with a readable message. */
function extractTree(top, sha, dir) {
  const tar = join(dir, "base.tar");
  const tree = join(dir, "tree");
  mkdirSync(tree);
  // git archive leaves out paths the tree's .gitattributes marks export-ignore.
  git(top, ["archive", "--format=tar", "-o", tar, sha]);
  // Relative names, run from `dir`: GNU tar (Git for Windows) reads "C:\..." as host:path.
  const r = spawnSync("tar", ["-xf", "base.tar", "-C", "tree"], { cwd: dir, stdio: ["ignore", "ignore", "pipe"] });
  if (r.error || r.status !== 0) throw new Error(`could not unpack the merge-base (${r.error?.message || String(r.stderr || "").trim() || `tar exited ${r.status}`})`);
  return tree;
}

/**
 * Compare a scan of `root` with a scan of the merge-base. Returns the result
 * (the current scan with only the new findings) and the counts.
 */
export async function diffScan(root, { ref = null, onPhase = () => {}, scan = scanRepo } = {}) {
  const top = gitToplevel(root);
  if (!top) return { error: `${root} is not in a git repository.` };
  const base = mergeBaseOf(top, ref);
  if (base.error) return base;
  const current = await scan(root, { onPhase });
  const before = await withTempDir("penthera-diff-", async (dir) => {
    const at = join(extractTree(top, base.sha, dir), relative(top, realpathSync(root)));
    if (!existsSync(at) || !statSync(at).isDirectory()) return { findings: [] };
    return scan(at, { onPhase: () => {} });
  });
  // A file git ignores is on no branch: a local .env is not something this branch added.
  const local = current.findings.filter((f) => f.localOnly);
  const cmp = compareFindings(current.findings.filter((f) => !f.localOnly), { findings: before.findings, secretTagSalt: tagSalt() }, base.ref);
  const short = base.sha.slice(0, 7);
  const diff = {
    schema: DIFF_SCHEMA,
    ref: base.ref,
    mergeBase: base.sha,
    head: base.head,
    new: cmp.stats.newCount,
    fixed: cmp.stats.resolvedCount,
    unchanged: cmp.stats.unchangedCount,
    localOnly: local.length,
  };
  const limits = [
    `Only what this branch added against ${base.ref} (merge-base ${short}): ${diff.unchanged} found there too and ${diff.fixed} fixed since are left out. A full scan: penthera --repo .`,
    ...(local.length ? [`${local.length} finding${local.length === 1 ? "" : "s"} in files git ignores left out: they are on no branch.`] : []),
  ];
  const result = { ...current, findings: cmp.newFindings, diff, resolved: cmp.resolvedFindings };
  return { result, limits, diff };
}

export async function runDiff(argv, { version = "" } = {}) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        repo: { type: "string", short: "r" },
        json: { type: "boolean", default: false },
        brief: { type: "boolean", default: false },
        output: { type: "string", short: "o" },
        markdown: { type: "string" },
        sarif: { type: "string" },
        quiet: { type: "boolean", short: "q", default: false },
        verbose: { type: "boolean", short: "v", default: false },
        "no-footer": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    printError(e.message);
    process.stderr.write(DIFF_HELP);
    return 2;
  }
  const { values: opts, positionals } = parsed;
  if (opts.help) {
    process.stdout.write(DIFF_HELP);
    return 0;
  }
  if (positionals.length > 1) {
    printError(`diff takes one ref, got: ${positionals.join(" ")}`);
    return 2;
  }
  const root = resolve(opts.repo || ".");
  if (!existsSync(root)) {
    printError(`Path not found: ${root}`);
    return 2;
  }
  const quiet = opts.quiet || opts.json;
  let out;
  try {
    out = await diffScan(root, { ref: positionals[0] ?? null, onPhase: createProgress(quiet) });
  } catch (e) {
    printError(`Diff failed: ${e.message}`);
    return 2;
  }
  if (out.error) {
    printError(out.error);
    return 2;
  }
  const { result, limits, diff } = out;
  const { findingId } = await import("../../lib/memory/index.js");
  result.findings = result.findings.map((f) => ({ ...f, fid: findingId(f) }));
  result.brief = buildBrief(result, { reports: briefReports(opts), limits });

  const header = `  Diff against ${diff.ref} (merge-base ${diff.mergeBase.slice(0, 7)}): ${diff.new} new, ${diff.fixed} fixed, ${diff.unchanged} unchanged\n`;
  if (opts.json) process.stdout.write(formatJson(result));
  else if (wantBrief(opts)) process.stdout.write(formatBrief(result.brief));
  else if (opts.quiet) printFindings(result.findings);
  else {
    process.stderr.write(`\n${header}`);
    printReport(result, { verbose: opts.verbose, limit: limits[0] });
  }

  const mdOpts = { version, footer: !opts["no-footer"] };
  if (opts.output) {
    writeJsonReport(result, opts.output);
    writeMarkdownReport(result, markdownPathFromJson(opts.output), mdOpts);
  }
  if (opts.markdown) writeMarkdownReport(result, opts.markdown, mdOpts);
  if (opts.sarif) writeSarifReport(result, opts.sarif);
  if (!quiet && (opts.output || opts.markdown || opts.sarif)) {
    for (const [label, p] of [["JSON report    ", opts.output], ["Markdown report", opts.output && markdownPathFromJson(opts.output)], ["Markdown report", opts.markdown], ["SARIF report   ", opts.sarif]]) {
      if (p) process.stderr.write(`  ${label} ${p}\n`);
    }
    process.stderr.write("\n");
  }
  return exitCodeOf(result);
}
