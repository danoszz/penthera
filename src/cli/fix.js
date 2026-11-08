/**
 * `penthera fix`: plan and apply deterministic fix recipes, locally.
 *
 *   penthera fix --plan [--repo <path>] [-o <report.json>]
 *   penthera fix --apply <id> [--repo <path>] [-o <report.json>] [--yes] [--dry-run] [--allow-dirty]
 *
 * Planning never writes. Applying needs an explicit plan id plus approval (a
 * y/N prompt, or --yes), never pushes, and refuses a dirty git tree. Nothing
 * here touches the network, except the optional --fix-model fallback, which
 * only talks to Ollama on 127.0.0.1.
 */
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { readFileSync, existsSync, statSync } from "node:fs";
import { scanRepo } from "../scan-repo.js";
import { planFixes, redactPlan, applyDiff, assertCleanTree, findingKey, createModelFixer } from "../../lib/fix/index.js";
import { bold, dim, green, red, yellow, cyan } from "./ansi.js";
import { isProblem, fixesText, plural } from "../report/counts.js";

const HELP = `
  ${bold("penthera fix")} — plan and apply local fix recipes

  ${dim("Usage")}
    $ penthera fix --plan [--repo <path>]          Print a diff for each fixable finding
    $ penthera fix --apply <id> [--repo <path>]    Apply one planned diff (asks first)

  ${dim("Options")}
    -r, --repo <path>        Repo to fix (default: .)
    -o, --input <file>       Use findings from a JSON report (penthera ... -o report.json)
                             instead of a fresh repo scan
        --fix-model <name>   Ask a local Ollama model (127.0.0.1:11434 only) when no recipe
                             matches. Off by default; output needs human review
        --json               Print plans as JSON (recognised secrets masked)
        --yes                Approve the diff without the y/N prompt (for --apply)
        --dry-run            Check that the diff applies, write nothing
        --allow-dirty        Apply even with uncommitted changes in the repo
    -h, --help               Show this help

  Recipes: security headers, cookie flags, CORS allowlist, login rate limit,
  hardcoded secret to env var. Plans change after each apply: run --plan again.
`;

/**
 * Findings for the repo: a report's findings, or a fresh repo scan. The scan
 * runs the recipes' static checks itself, so the plan and the scan count the
 * same findings. `incomplete` lists what was not read or not checked (the
 * scan's own list): never dropped with the info notes, it makes the run exit 2.
 */
async function gatherFindings(repo, input) {
  if (input) {
    const report = JSON.parse(readFileSync(resolve(input), "utf-8"));
    return { findings: report.findings || [], fresh: false, incomplete: Array.isArray(report.incomplete) ? report.incomplete : [] };
  }
  const result = await scanRepo(repo, {});
  // The scan's own list, which holds the settings checks' too (a file they could not read or not fully check).
  const incomplete = [...(result.incomplete || [])];
  const seen = new Set();
  const findings = result.findings.filter((f) => {
    if (f.severity === "info" && f.category === "config") return false;
    const k = findingKey(f);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { findings, fresh: true, incomplete };
}

/** What was not read or checked, said on stderr; the caller exits 2. */
function reportIncomplete(incomplete) {
  if (!incomplete.length) return;
  process.stderr.write(`\n  ${yellow("Incomplete")} ${incomplete.length} input${incomplete.length === 1 ? " was" : "s were"} not read or not fully checked, so this plan may miss fixes (exit 2):\n`);
  for (const x of incomplete.slice(0, 20)) process.stderr.write(`    ${visible(x.file || x.title || "?")}${x.reason ? `: ${visible(x.reason)}` : ""}\n`);
}

/**
 * The plan's counts in the words every surface uses (src/report/counts.js):
 * problems in the run, how many of them a plan fixes, and the fixes planned.
 * A fix counts only when it covers a problem; `other` counts plans that touch
 * only likely noise or info (a cookie set in a test file), so a fix for noise
 * never shows as a fix still to do. The repo scan's fix line uses this too.
 */
export function planCounts(findings, plans) {
  const problems = new Set(findings.filter((f) => isProblem(f)).map(findingKey));
  const covered = new Set(plans.flatMap((p) => p.findings.map(findingKey)).filter((k) => problems.has(k)));
  const fixes = plans.filter((p) => p.findings.some((f) => problems.has(findingKey(f)))).length;
  return { problems: problems.size, covered: covered.size, fixes, other: plans.length - fixes, findings: findings.length };
}

const NAMED = { "\0": "\\0", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\v": "\\v", "\f": "\\f", "\r": "\\r", "\x1b": "\\e" };

/**
 * `s` with every control character (C0 except tab, DEL, C1) and every bidi
 * override shown as an escape such as \r or \e, so text from a scanned repo or
 * a model cannot move the cursor, erase a line or reorder what the reviewer sees.
 */
export function visible(s, { keepTabs = true } = {}) {
  return String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, (c) => {
    if (c === "\t" && keepTabs) return c;
    const code = c.charCodeAt(0);
    return NAMED[c] || (code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u{${code.toString(16)}}`);
  });
}

export function colorDiff(diff) {
  return String(diff).split("\n").map((raw) => {
    const l = visible(raw);
    if (/^(---|\+\+\+) /.test(l)) return bold(l);
    if (l.startsWith("@@")) return cyan(l);
    if (l.startsWith("+")) return green(l);
    if (l.startsWith("-")) return red(l);
    return l;
  }).join("\n");
}

export function printPlan(plan) {
  const v = (s) => visible(s, { keepTabs: false });
  const conf = plan.confidence === "needs-human-review" ? yellow(v(plan.confidence)) : v(plan.confidence);
  process.stdout.write(`\n  ${bold(v(plan.id))}  ${v(plan.title)}${plan.framework ? dim(` (${v(plan.framework)})`) : ""}  confidence: ${conf}  source: ${v(plan.source)}\n`);
  for (const f of plan.findings) process.stdout.write(`    ${dim("fixes")} [${v(f.severity || "?")}] ${v(f.title)}${f.url ? dim(` ${v(f.url)}`) : ""}\n`);
  for (const a of plan.ownerActions) process.stdout.write(`    ${yellow("owner action")} ${v(a)}\n`);
  process.stdout.write("\n" + colorDiff(plan.diff).replace(/^/gm, "    ").trimEnd() + "\n");
}

async function approve(plan, opts) {
  if (opts.yes) return true;
  if (!process.stdin.isTTY) {
    process.stderr.write(`  Not applying ${plan.id}: review the diff above, then re-run with --yes to approve it.\n`);
    return false;
  }
  const { initPrompt, confirm, closePrompt } = await import("./prompt.js");
  await initPrompt();
  const ok = await confirm(`\n  Apply ${plan.id} to the working tree?`, false);
  closePrompt();
  return ok;
}

export async function runFix(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: false,
      options: {
        plan: { type: "boolean", default: false },
        apply: { type: "string" },
        repo: { type: "string", short: "r" },
        input: { type: "string", short: "o" },
        "fix-model": { type: "string" },
        json: { type: "boolean", default: false },
        yes: { type: "boolean", default: false },
        "dry-run": { type: "boolean", default: false },
        "allow-dirty": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    process.stderr.write(`  ${red("Error")} ${e.message}\n${HELP}`);
    process.exit(2);
  }
  const opts = parsed.values;
  if (opts.help) {
    console.log(HELP);
    process.exit(0);
  }

  const repo = resolve(opts.repo || ".");
  if (!existsSync(repo) || !statSync(repo).isDirectory()) {
    process.stderr.write(`  ${red("Error")} Repo not found: ${repo}\n`);
    process.exit(2);
  }

  let model = null;
  if (opts["fix-model"]) model = createModelFixer({ model: opts["fix-model"] });

  let gathered;
  try {
    gathered = await gatherFindings(repo, opts.input);
  } catch (e) {
    process.stderr.write(`  ${red("Error")} Could not read findings: ${e.message}\n`);
    process.exit(2);
  }
  const { plans, unmatched, refused } = await planFixes(repo, gathered.findings, { model });
  const counts = planCounts(gathered.findings, plans);

  if (!opts.apply) {
    if (opts.json) {
      console.log(JSON.stringify({ repo, counts, plans: plans.map(redactPlan), unmatched: unmatched.map((f) => ({ title: f.title, category: f.category, severity: f.severity, url: f.url || null })), refused: refused.map((r) => ({ title: r.finding.title, reason: r.reason })), incomplete: gathered.incomplete.map((x) => ({ file: x.file || null, reason: x.reason || null })) }, null, 2));
      process.exit(gathered.incomplete.length ? 2 : 0);
    }
    process.stdout.write(`\n  ${bold("penthera fix")} ${dim(repo)}\n`);
    const other = counts.other ? `, and ${counts.other} for likely noise or info` : "";
    const headline = `${fixesText(counts.fixes, counts.covered, counts.problems)}${other}`;
    process.stdout.write(`  ${headline}${gathered.fresh ? " (fresh repo scan)" : ` (from ${opts.input})`}\n`);
    for (const p of plans) printPlan(redactPlan(p));
    for (const r of refused) process.stdout.write(`\n  ${yellow("Refused")} the model's fix for ${visible(r.finding.title)}: ${visible(r.reason)}\n`);
    const manual = unmatched.filter((f) => isProblem(f));
    if (manual.length) {
      process.stdout.write(`\n  ${dim(`${plural(manual.length, "problem")} without a recipe; fix by hand (\`penthera --repo . -o report.json\` writes an action plan)${model ? "" : " or try --fix-model <name>"}:`)}\n`);
      for (const f of manual.slice(0, 20)) process.stdout.write(`    [${visible(f.severity)}] ${visible(f.title)}\n`);
    }
    // The headline again at the end, so the last lines (`tail`) say what the plan holds.
    process.stdout.write(`\n  ${bold(headline)}\n`);
    if (plans.length) process.stdout.write(`  Apply one:  penthera fix --apply <id>${opts.repo ? ` --repo ${opts.repo}` : ""}${opts.input ? ` -o ${opts.input}` : ""}\n`);
    process.stdout.write("\n");
    reportIncomplete(gathered.incomplete);
    process.exit(gathered.incomplete.length ? 2 : 0);
  }

  const plan = plans.find((p) => p.id === opts.apply);
  if (!plan) {
    process.stderr.write(`  ${red("Error")} No plan with id ${opts.apply}. Plans change after each apply; run penthera fix --plan again.\n`);
    process.exit(2);
  }
  printPlan(redactPlan(plan));
  // Ask only about a change that can happen.
  if (!opts["allow-dirty"]) {
    try {
      assertCleanTree(repo);
    } catch (e) {
      process.stderr.write(`  ${red("Not applied")} ${e.message}\n`);
      process.exit(2);
    }
  }
  if (!opts["dry-run"] && !(await approve(plan, opts))) process.exit(1);

  let result;
  try {
    result = applyDiff(repo, plan.diff, { dryRun: opts["dry-run"], allowDirty: opts["allow-dirty"] });
  } catch (e) {
    process.stderr.write(`  ${red("Not applied")} ${e.message}\n`);
    process.exit(2);
  }
  const verb = result.applied ? "Applied" : "Dry run, would change";
  process.stdout.write(`\n  ${green(verb)} ${result.files.map((f) => f.path + (f.created ? " (new)" : "")).join(", ")}\n`);
  if (!result.applied) { reportIncomplete(gathered.incomplete); process.exit(gathered.incomplete.length ? 2 : 0); }

  // Verify by re-scanning. Report findings came from a scan we can't repeat here.
  if (gathered.fresh) {
    const after = await gatherFindings(repo, null);
    const still = new Set(after.findings.map(findingKey));
    for (const f of plan.findings) {
      const gone = !still.has(findingKey(f));
      process.stdout.write(`  ${gone ? green("verified") : yellow("still reported")} ${f.title}\n`);
    }
  } else {
    process.stdout.write(`  Re-run the scan that produced ${opts.input} to verify.\n`);
  }
  if (plan.ownerActions.length) {
    process.stdout.write(`\n  ${yellow("Still on you:")}\n`);
    for (const a of plan.ownerActions) process.stdout.write(`    - ${a}\n`);
  }
  process.stdout.write(`\n  Nothing was committed or pushed. Review with git diff, then commit it yourself.\n\n`);
  reportIncomplete(gathered.incomplete);
  process.exit(gathered.incomplete.length ? 2 : 0);
}
