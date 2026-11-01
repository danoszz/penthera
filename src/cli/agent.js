/**
 * `penthera agent --loop`: the local scan → fix → verify → learn loop.
 *
 *   penthera agent --loop [--repo <path>] [--url <url>] [--max-iterations 5]
 *                         [--auto low] [--run-tests] [--fix-model <name>] [--allow-dirty] [-o run.json]
 *
 * Every diff is shown and needs y (apply), n (not this run), s (skip for now)
 * or q (quit). Fixes land as local commits on penthera/fix-<yyyymmdd-hhmm>.
 * Nothing is pushed. See docs/local-loop.md.
 */
import { parseArgs } from "node:util";
import { resolve, dirname } from "node:path";
import { existsSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { createInterface } from "node:readline";
import { runLoop, loopVerdict, LoopError } from "../agent/loop.js";
import { hintCommand } from "../utils/invocation.js";
import { normalizeBaseUrl } from "../utils/url.js";
import { printPlan, visible } from "./fix.js";
import { bold, dim, green, red, yellow } from "./ansi.js";

const HELP = `
  ${bold("penthera agent --loop")} — scan, fix, verify and learn, on this machine only

  ${dim("Usage")}
    $ penthera agent --loop [--repo <path>] [--url <url>]

  ${dim("Options")}
    -r, --repo <path>          Repo to fix (default: .). Must be a clean git tree on a branch
    -u, --url <url>            Also scan this running app (egress limited to this host)
        --max-iterations <n>   Stop after n scan/fix rounds (default: 5)
        --auto low             Apply without asking only recipes that memory shows verified
                               3+ times on this framework with no failures
        --run-tests            Run the project's test script (node --run test) to verify
        --fix-model <name>     Ask a local Ollama model (127.0.0.1:11434 only) when no recipe
                               matches. Its diffs always need approval
        --allow-dirty          Start with uncommitted changes or a detached HEAD (files with
                               changes are never patched)
    -o, --output <file>        Write the loopRun JSON here
    -h, --help                 Show this help

  Each diff asks: y apply, n not this run, s skip for now, q quit.
  Fixes are committed on a local branch penthera/fix-<yyyymmdd-hhmm>. Nothing is
  pushed, fetched or opened as a pull request. Ctrl-C stops after the current step.
`;

/** Line reader that works for a TTY and for piped answers. EOF answers "n". */
function createAsker(signal) {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const lines = rl[Symbol.asyncIterator]();
  let eof = false;
  const aborted = new Promise((r) => signal.addEventListener("abort", () => r({ abort: true }), { once: true }));

  async function readLine(question) {
    process.stdout.write(question);
    if (eof) return null;
    const next = await Promise.race([lines.next(), aborted]);
    if (next.abort) return "q";
    if (next.done) { eof = true; return null; }
    if (!process.stdin.isTTY) process.stdout.write(`${next.value}\n`);
    return next.value.trim().toLowerCase();
  }

  return {
    async ask({ plan, iteration, index, total, memory }) {
      process.stdout.write(`\n  ${bold(`[${iteration}.${index}/${total}]`)}`);
      if (memory) process.stdout.write(dim(`  memory: ${memory.verified} verified, ${memory.failed} failed`));
      printPlan(plan);
      for (let tries = 0; tries < 5; tries++) {
        const a = await readLine(`\n  Apply this fix? ${dim("[y]es / [n]o / [s]kip / [q]uit")} `);
        if (a === null) {
          process.stdout.write(`\n  ${yellow("No more input")}: not applying (answer y on a terminal to apply).\n`);
          return "n";
        }
        if (a === "y" || a === "yes") return "y";
        if (a === "n" || a === "no") return "n";
        if (a === "s" || a === "skip") return "skip";
        if (a === "q" || a === "quit") return "quit";
      }
      return "skip";
    },
    close: () => rl.close(),
  };
}

export async function runAgent(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        loop: { type: "boolean", default: false },
        repo: { type: "string", short: "r" },
        url: { type: "string", short: "u" },
        "max-iterations": { type: "string" },
        auto: { type: "string" },
        "run-tests": { type: "boolean", default: false },
        "fix-model": { type: "string" },
        "allow-dirty": { type: "boolean", default: false },
        output: { type: "string", short: "o" },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    process.stderr.write(`  ${red("Error")} ${e.message}\n${HELP}`);
    return 2;
  }
  const opts = parsed.values;
  if (opts.help || !opts.loop) {
    console.log(HELP);
    return opts.help ? 0 : 2;
  }
  if (opts.auto != null && opts.auto !== "low") {
    process.stderr.write(`  ${red("Error")} --auto only accepts "low"\n`);
    return 2;
  }
  const maxIterations = opts["max-iterations"] == null ? 5 : Number(opts["max-iterations"]);
  if (!Number.isInteger(maxIterations) || maxIterations < 1 || maxIterations > 50) {
    process.stderr.write(`  ${red("Error")} --max-iterations must be a whole number from 1 to 50\n`);
    return 2;
  }
  const repo = resolve(opts.repo || ".");
  if (!existsSync(repo) || !statSync(repo).isDirectory()) {
    process.stderr.write(`  ${red("Error")} Repo not found: ${repo}\n`);
    return 2;
  }
  const rawUrl = opts.url || parsed.positionals[0];
  const url = rawUrl ? normalizeBaseUrl(rawUrl) : null;

  const controller = new AbortController();
  const handle = {};
  let interrupts = 0;
  const onSigint = () => {
    interrupts++;
    if (interrupts === 1) {
      process.stdout.write(`\n  ${yellow("Stopping")} after the current step. Ctrl-C again to revert the fix in flight and exit now.\n`);
      controller.abort();
      return;
    }
    let r = null;
    try { r = handle.revertPending?.(); } catch (e) { process.stdout.write(`\n  ${red("Revert failed")} ${visible(e.message)}\n`); }
    for (const f of r?.conflicts || []) process.stdout.write(`\n  ${yellow("Left as is")} ${visible(f)}: it changed after the fix was written\n`);
    for (const e of r?.errors || []) process.stdout.write(`\n  ${red("Not restored")} ${visible(e.path)}: ${visible(e.message)}\n`);
    process.stdout.write(`\n  ${red("Stopped.")} The fix branch holds only verified commits.\n`);
    process.exit(130);
  };
  process.on("SIGINT", onSigint);
  // A kill leaves no second chance: put back the fix in flight, then go.
  const onSigterm = () => {
    controller.abort();
    try { handle.revertPending?.(); } catch { /* the tree is left as it is, and the exit says so */ }
    process.exit(143);
  };
  process.on("SIGTERM", onSigterm);

  const asker = createAsker(controller.signal);
  process.stdout.write(`\n  ${bold("penthera agent --loop")} ${dim(repo)}${url ? dim(` + ${url}`) : ""}\n`);
  process.stdout.write(dim(`  local only: egress limited to ${url ? new URL(url).host : "no hosts (repo scan only)"}${opts["fix-model"] ? " and Ollama on 127.0.0.1:11434" : ""}; nothing is pushed\n`));

  let run;
  try {
    run = await runLoop({
      repo, url, maxIterations, auto: opts.auto || "off", runTests: opts["run-tests"],
      fixModel: opts["fix-model"] || null, allowDirty: opts["allow-dirty"],
      ask: asker.ask, log: (l) => process.stdout.write(`${String(l).split("\n").map((x) => visible(x)).join("\n")}\n`), signal: controller.signal, handle,
    });
  } catch (e) {
    asker.close();
    process.off("SIGINT", onSigint);
    process.off("SIGTERM", onSigterm);
    process.stderr.write(`  ${red("Not started")} ${e.message}\n`);
    return e instanceof LoopError ? 2 : 1;
  }
  asker.close();
  process.off("SIGINT", onSigint);
  process.off("SIGTERM", onSigterm);

  if (opts.output) {
    const out = resolve(opts.output);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, JSON.stringify({ loopRun: run }, null, 2) + "\n");
  }

  const t = run.totals;
  const verdict = loopVerdict(run);
  process.stdout.write(`\n  ${bold(verdict.clean ? "Done" : "Not done")}: ${verdict.headline}\n`);
  if (verdict.next) process.stdout.write(`  ${hintCommand(verdict.next)}\n`);
  process.stdout.write(`  ${run.stopReason} after ${t.iterations} iteration${t.iterations === 1 ? "" : "s"} (${(run.durationMs / 1000).toFixed(1)}s)\n`);
  process.stdout.write(`  ${green(`${t.verified} verified`)}, ${t.failed ? red(`${t.failed} failed and reverted`) : "0 failed"}, ${t.conflicts ? `${yellow(`${t.conflicts} left for you (files changed meanwhile)`)}, ` : ""}${t.declined} declined, ${t.skipped} skipped\n`);
  process.stdout.write(`  last scan: ${run.findings.initial ?? "?"} → ${run.findings.final ?? "?"} findings to act on\n`);
  if (run.gaveUp.length) {
    process.stdout.write(`  ${yellow(`gave up on ${run.gaveUp.length}`)} (not retried this run; fix by hand): ${run.gaveUp.map((g) => `${visible(g.title)} (${visible(g.reason)})`).join("; ")}\n`);
  }
  if (run.error) process.stdout.write(`  ${red("Error")} ${visible(run.error)}\n`);
  if (run.branch.left) process.stdout.write(`  No fixes landed, so you are back on ${bold(run.branch.base)}.${run.branch.removed ? "" : ` Branch ${run.branch.fix} is empty.`}\n`);
  else process.stdout.write(`  You are on branch ${bold(run.branch.fix)}. Review it with  git log --stat ${(run.branch.base !== run.branch.fix && run.branch.base) || run.branch.baseSha.slice(0, 12)}..${run.branch.fix}\n`);
  if (opts.output) process.stdout.write(`  loopRun written to ${opts.output}\n`);
  process.stdout.write(run.branch.left ? "  Nothing was changed or pushed.\n\n" : "  Nothing was pushed. Merge or push the branch yourself when you are happy with it.\n\n");

  if (run.stopReason === "interrupted") return 130;
  return verdict.clean ? 0 : 1;
}
