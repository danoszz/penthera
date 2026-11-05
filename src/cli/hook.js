/**
 * `penthera hook install|uninstall|run`: the pre-commit hook (lib/hook/).
 * Exit codes for `run`: 0 commit may go ahead, 1 blocked, 2 error (also blocks).
 */
import { parseArgs } from "node:util";
import { relative, resolve } from "node:path";
import { runHook, installHook, uninstallHook, fixHint } from "../../lib/hook/index.js";
import { printError } from "../reporter.js";
import { bold, dim, green, red, yellow, cyan } from "./ansi.js";

const HELP = `
  ${bold("penthera hook")} — block secrets, malicious agent config and risky lockfile changes before they are committed

  ${dim("Usage")}
    $ penthera hook install      Write .git/hooks/pre-commit (an existing hook is kept and runs first)
    $ penthera hook uninstall    Remove it and restore the hook it replaced
    $ penthera hook run          Check what is staged now (what the hook runs)

  ${dim("Options")}
        --policy <file>    Policy file (default: ./penthera.policy.json)
        --repo <dir>       run: the repo to check (default: the current folder)
        --force            install: write into core.hooksPath even when another tool manages it
        --json             run: print the result as JSON
    -v, --verbose          run: also list findings below the blocking severity
    -h, --help             Show this help

  ${dim("What it checks (staged content only, offline)")}
    Secrets and AI provider keys in staged files; \`penthera agents\` rules on staged
    .mcp.json, CLAUDE.md, AGENTS.md, .claude/, .cursor/ and skills/; and, when
    package-lock.json is staged, the capability diff against HEAD plus the license
    policy. Blocks on high and critical by default.

  ${dim("Policy")}  ${dim("(penthera.policy.json)")}
    { "hook": { "blockOn": "high", "ignore": ["tests/fixtures/**"],
                "checks": { "secrets": true, "agents": true, "deps": true, "licenses": true },
                "largeFiles": "block" } }   ${dim("// staged files over 16 MB: block or warn")}

  ${dim("Other hook managers")}
    pre-commit:  repo: https://github.com/danoszz/penthera, hooks: [{ id: penthera }]
    husky:       echo "npx --no-install penthera hook run" >> .husky/pre-commit
    lefthook:    pre-commit: { commands: { penthera: { run: npx --no-install penthera hook run } } }
`;

const SEV = { critical: red, high: red, medium: yellow, low: dim, info: dim };
const where = (f) => `${f.url}${f.line ? `:${f.line}` : ""}`;

function findingLine(f, mark) {
  const sev = (SEV[f.severity] || dim)(f.severity.toUpperCase().padEnd(8));
  const ev = f.evidence ? `  ${dim(f.evidence)}` : "";
  return `  ${mark} ${sev} ${cyan(where(f))}  ${f.title}${ev}  ${dim(`id ${f.id}`)}\n      ${dim("→")} ${fixHint(f)}`;
}

function printRun(r, { verbose }) {
  const L = [];
  const secs = (r.duration / 1000).toFixed(1);
  const what = [`${r.staged} staged file${r.staged === 1 ? "" : "s"}`, r.checked.agents && `${r.checked.agents} agent config`, r.checked.lockfiles && `${r.checked.lockfiles} lockfile`].filter(Boolean).join(", ");
  for (const w of r.warnings) L.push(`  ${yellow("!")} ${w}`);
  if (!r.blocking.length) {
    const below = r.below.length ? dim(` · ${r.below.length} below ${r.blockOn}${verbose ? "" : " (-v to list)"}`) : "";
    const sup = r.suppressed.length ? dim(` · ${r.suppressed.length} suppressed`) : "";
    L.push(`  ${green("✓")} ${bold("penthera")} ${what} checked in ${secs}s${below}${sup}`);
    if (verbose) for (const f of r.below) L.push(findingLine(f, yellow("!")));
    process.stderr.write(L.join("\n") + "\n");
    return;
  }
  L.push("");
  L.push(`  ${red("✗")} ${bold("penthera")} blocked this commit: ${r.blocking.length} finding${r.blocking.length === 1 ? "" : "s"} at ${r.blockOn} or above ${dim(`(${what}, ${secs}s)`)}`);
  L.push("");
  for (const f of r.blocking) L.push(findingLine(f, red("✗")));
  if (verbose) for (const f of r.below) L.push(findingLine(f, yellow("!")));
  else if (r.below.length) L.push(dim(`  + ${r.below.length} below ${r.blockOn}, not blocking (-v to list)`));
  L.push("");
  L.push(`  Fix and \`git add\` again. A false positive? Add it to penthera.suppress.json:`);
  L.push(dim(`    { "version": 1, "suppress": [{ "id": "${r.blocking[0].id}", "severity": "${r.blocking[0].severity}", "reason": "why this is safe" }] }`));
  L.push(`  To skip the check for one commit: ${bold("git commit --no-verify")} ${dim("(the finding still ships)")}`);
  L.push("");
  process.stderr.write(L.join("\n") + "\n");
}

export async function runHookCommand(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        policy: { type: "string" },
        repo: { type: "string" },
        force: { type: "boolean", default: false },
        json: { type: "boolean", default: false },
        verbose: { type: "boolean", short: "v", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    printError(e.message);
    return 2;
  }
  const { values: opts, positionals } = parsed;
  const sub = positionals[0];
  if (opts.help || !sub) {
    console.log(HELP);
    return sub || opts.help ? 0 : 2;
  }
  const cwd = opts.repo ? resolve(opts.repo) : process.cwd();
  const rel = (p) => relative(cwd, p) || p;
  try {
    if (sub === "install") {
      const r = installHook(cwd, { force: opts.force });
      console.log(`  ${green("✓")} ${r.updated ? "Updated" : "Installed"} ${rel(r.path)}`);
      if (r.chained) console.log(`  ${dim("▸")} Your existing hook moved to ${rel(r.chained)} and runs first; \`penthera hook uninstall\` puts it back.`);
      console.log(`  ${dim("▸")} Every commit now checks staged secrets, agent config and lockfile changes. Skip once with git commit --no-verify.`);
      return 0;
    }
    if (sub === "uninstall") {
      const r = uninstallHook(cwd);
      if (!r.removed) console.log(`  ${dim("No penthera pre-commit hook installed.")}`);
      else console.log(`  ${green("✓")} Removed ${rel(r.path)}${r.restored ? `; your previous hook is back in place` : ""}`);
      return 0;
    }
    if (sub === "run") {
      const r = await runHook(cwd, { policyPath: opts.policy ? resolve(opts.policy) : null });
      if (opts.json) console.log(JSON.stringify(r, null, 2));
      else printRun(r, { verbose: opts.verbose });
      return r.blocking.length ? 1 : 0;
    }
  } catch (e) {
    printError(e.message);
    if (sub === "run") process.stderr.write(`  ${dim("The commit is blocked because the check could not run. Skip it once with git commit --no-verify.")}\n`);
    return 2;
  }
  printError(`Unknown hook command "${sub}". Use install, uninstall or run.`);
  return 2;
}
