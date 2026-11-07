/**
 * `penthera install [pkg...]`: the install firewall CLI (lib/install/).
 *
 * Shows what an install would change (new packages, capabilities gained, new
 * install scripts and their commands), applies penthera.policy.json, and only
 * then runs `npm ci` on the reviewed lockfile. Exit codes: 0 installed (or a clean
 * --dry-run), 1 blocked or aborted (project untouched), 2 error.
 */
import { parseArgs } from "node:util";
import { resolve, relative } from "node:path";
import { existsSync } from "node:fs";
import { planInstall, applyInstall, scriptChanges, npmInfo } from "../../lib/install/index.js";
import { loadPolicy, RULE_LABELS, POLICY_FILE } from "../../lib/install/policy.js";
import { createProgress, printError } from "../reporter.js";
import { initPrompt, ask, closePrompt } from "./prompt.js";
import { bold, dim, green, red, yellow, cyan } from "./ansi.js";

const HELP = `
  ${bold("penthera install")} — install npm packages through a capability firewall

  ${dim("Usage")}
    $ penthera install <pkg> [<pkg>...]   Check, then install (asks when the policy says so)
    $ penthera install                    Same, for what package.json already lists

  ${dim("Options")}
    -y, --yes              Never prompt: install only if nothing breaches the policy (CI)
        --dry-run          Report only; never install
        --policy <file>    Policy file (default: ./${POLICY_FILE}, else built-in defaults)
        --dir <path>       Project folder (default: .)
    -D, --save-dev         Save as devDependencies
    -E, --save-exact       Save exact versions
        --offline          npm resolves from its cache only (no registry traffic at all)
        --allow-non-registry  Accept git and tarball-URL packages (refused by default)
        --json             Print the plan as JSON
    -v, --verbose          Show more evidence per capability
    -h, --help             Show this help

  ${dim("How it works")}
    npm resolves the new tree in a temporary copy with scripts disabled, new
    tarballs go into npm's cache (integrity-verified, never unpacked or run),
    and the \`penthera deps\` engine diffs capabilities against your lockfile.
    Nothing in your project changes until you approve. Then \`npm ci\` installs
    exactly the reviewed lockfile. Approved install scripts run; otherwise the
    install uses --ignore-scripts. A package Penthera could not read is held for
    approval whatever the policy says, and one whose lockfile claims an install
    script the scan did not find is always refused.

  ${dim("Policy")}  ${dim(`(${POLICY_FILE})`)}
    { "allow": ["@acme/*", "esbuild"], "deny": ["token-harvest"],
      "requireApproval": ["install-scripts", "startup-hook", "ai-config-write",
                          "ai-cli-invoke", "token-harvest", "obfuscated", "typosquat",
                          "unscanned"] }
    "script-mismatch" is always denied and "unscanned" always needs approval.
    The requireApproval list above is the default.
`;

const label = (id) => RULE_LABELS[id] || id;
const at = (i) => `${i.name}@${i.version}`;

function printPlan(plan, { policyPath, verbose }) {
  const L = [];
  const { items, denied, needsApproval } = plan.verdict;
  const added = items.filter((i) => i.change === "added");
  const upgraded = items.filter((i) => i.change === "upgraded");
  L.push("");
  L.push(`  ${bold("Changes")}   ${added.length} added · ${upgraded.length} upgraded · ${plan.removed.length} removed`);
  L.push("");
  if (items.length === 0 && plan.removed.length === 0) L.push(`  ${green("✓")} Nothing changes: the lockfile already has this.`);
  for (const i of [...upgraded, ...added]) {
    const head = i.change === "upgraded"
      ? `${yellow("▲")} ${bold(i.name)} ${i.from} → ${i.version}`
      : `${cyan("+")} ${bold(i.name)} ${i.version} ${dim("(new)")}`;
    const shown = i.flags.length ? i.flags : i.capabilities;
    const note = shown.length
      ? (i.change === "upgraded" ? red(`+ ${shown.map(label).join(", ")}`) : shown.map(label).join(", "))
      : dim(i.change === "upgraded" ? (i.compared ? "no new capabilities" : "old version not readable") : "no notable capabilities");
    L.push(`  ${head}  ${note}`);
    if (i.typosquatOf) L.push(`      ${yellow(`looks like ${i.typosquatOf}`)}: check this is the package you meant`);
    if (i.unscanned) L.push(`      ${red("not scanned")}: ${i.unscanned}`);
    if (i.flags.includes("install-scripts")) {
      for (const [hook, cmd] of Object.entries(i.installScripts || {})) {
        const was = i.previousInstallScripts?.[hook];
        L.push(`      ${red(hook)}: ${cmd}${was && was !== cmd ? dim(`  (was: ${was})`) : ""}`);
      }
    }
    const ev = plan.evidence?.[at(i)] || {};
    for (const id of i.flags.filter((f) => f !== "install-scripts")) {
      for (const e of (ev[id] || []).slice(0, verbose ? 3 : 1)) L.push(`      ${dim(`${e.file}:${e.line}`)}  ${e.snippet}`);
    }
  }
  for (const r of plan.removed) L.push(`  ${dim("−")} ${r.name} ${r.version} ${dim("(removed)")}`);

  L.push("");
  L.push(`  ${bold("Policy")}    ${policyPath ? relative(process.cwd(), policyPath) || policyPath : dim(`defaults (no ${POLICY_FILE})`)}`);
  for (const i of denied) L.push(`  ${red("✗")} ${at(i)}  ${red("denied")}: ${i.deny.map(label).join(", ")}`);
  for (const i of needsApproval) L.push(`  ${yellow("!")} ${at(i)}  needs approval: ${i.approval.map(label).join(", ")}`);
  for (const i of items.filter((x) => x.allowedBy && x.flags.length)) L.push(`  ${green("✓")} ${at(i)}  allowed by "${i.allowedBy}"`);
  if (plan.verdict.clean) L.push(`  ${green("✓")} Nothing breaches the policy.`);
  L.push("");
  process.stdout.write(L.join("\n") + "\n");
}

function planJson(plan, extra) {
  return {
    root: plan.root,
    specs: plan.specs,
    npm: { version: plan.npm.version, registry: plan.npm.registry },
    clean: plan.verdict.clean,
    changes: plan.verdict.items,
    removed: plan.removed,
    typosquats: plan.typosquats,
    ...extra,
  };
}

export async function runInstall(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        yes: { type: "boolean", short: "y", default: false },
        "dry-run": { type: "boolean", default: false },
        policy: { type: "string" },
        dir: { type: "string" },
        "save-dev": { type: "boolean", short: "D", default: false },
        "save-exact": { type: "boolean", short: "E", default: false },
        offline: { type: "boolean", default: false },
        "allow-non-registry": { type: "boolean", default: false },
        json: { type: "boolean", default: false },
        verbose: { type: "boolean", short: "v", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    printError(e.message);
    return 2;
  }
  const { values: opts, positionals: specs } = parsed;
  if (opts.help) {
    console.log(HELP);
    return 0;
  }
  const root = resolve(opts.dir || ".");
  if (!existsSync(root)) {
    printError(`Path not found: ${root}`);
    return 2;
  }
  const json = opts.json;
  const out = (s) => { if (!json) process.stdout.write(s); };

  let policy;
  let policyPath;
  try {
    let warning;
    ({ policy, path: policyPath, warning } = loadPolicy(root, opts.policy ? resolve(opts.policy) : null));
    if (warning) process.stderr.write(`\n  ${yellow("warning")} ${warning}\n`);
  } catch (e) {
    printError(e.message);
    return 2;
  }

  let plan;
  try {
    const info = await npmInfo(root);
    out(`\n  ${bold("penthera install")}  ${specs.length ? specs.join(" ") : dim("(package.json)")}  ${dim(`npm ${info.version}`)}\n`);
    out(`  ${bold("Network")}   ${opts.offline
      ? "npm runs with --offline (its cache only). Penthera makes no network calls."
      : `npm contacts ${cyan(info.registry)} to resolve and download. That is the only egress; Penthera itself makes no network calls.`}\n\n`);
    plan = await planInstall(root, specs, {
      policy,
      info,
      saveDev: opts["save-dev"],
      saveExact: opts["save-exact"],
      offline: opts.offline,
      allowNonRegistry: opts["allow-non-registry"],
      onPhase: createProgress(json),
    });
  } catch (e) {
    printError(e.message);
    return 2;
  }

  if (!json) printPlan(plan, { policyPath, verbose: opts.verbose });
  const { denied, needsApproval, clean } = plan.verdict;
  const untouched = "Project untouched.";
  const finish = (code, action, extra = {}) => {
    if (json) console.log(JSON.stringify(planJson(plan, { action, ...extra }), null, 2));
    return code;
  };

  if (opts["dry-run"]) {
    out(`  ${dim("--dry-run: nothing installed.")}\n\n`);
    return finish(clean ? 0 : 1, "dry-run");
  }
  if (denied.length) {
    out(`  ${red("Blocked")}: ${denied.length} package(s) denied by policy. ${untouched}\n  Add them to "allow" in ${POLICY_FILE} if you trust them.\n\n`);
    return finish(1, "blocked");
  }

  const scripts = scriptChanges(plan);
  let runScripts = true;
  if (!clean) {
    if (opts.yes) {
      out(`  ${red("Blocked")}: ${needsApproval.length} package(s) need approval and --yes only installs when nothing breaches the policy. ${untouched}\n\n`);
      return finish(1, "blocked");
    }
    // A package that could not be read may have install scripts nobody saw.
    const withScripts = scripts.length > 0 || needsApproval.some((i) => i.approval.includes("unscanned"));
    await initPrompt();
    const answer = (await ask(withScripts
      ? `  Install anyway? [y]es, run the install scripts / [s]kip scripts / [N]o: `
      : `  Install anyway? [y/N]: `)).toLowerCase();
    closePrompt();
    if (answer === "y" || answer === "yes") runScripts = true;
    else if (withScripts && (answer === "s" || answer === "skip")) runScripts = false;
    else {
      out(`\n  Aborted. ${untouched}\n\n`);
      return finish(1, "aborted");
    }
  }

  out(`\n  ${dim("▸")} npm ci${runScripts ? "" : " --ignore-scripts"} ${dim("(installs exactly the reviewed lockfile)")}\n`);
  let applied;
  try {
    applied = await applyInstall(plan, { runScripts, offline: opts.offline });
  } catch (e) {
    printError(e.message);
    return finish(2, "failed");
  }
  if (applied.allowScriptsAdded.length) out(`  ${dim("▸")} Approved install scripts pinned in package.json allowScripts: ${applied.allowScriptsAdded.join(", ")}\n`);
  if (!runScripts && scripts.length) out(`  ${yellow("!")} Install scripts skipped for ${scripts.map(at).join(", ")}. Run \`npm rebuild <pkg>\` later if a package needs them.\n`);
  if (applied.drift.length) out(`  ${yellow("!")} npm's lockfile differs from the reviewed one: ${applied.drift.slice(0, 5).join(", ")}. Run \`penthera deps --base HEAD\` to review.\n`);
  out(`  ${green("✓")} Installed.\n\n`);
  return finish(0, "installed", { scriptsRan: runScripts, allowScriptsAdded: applied.allowScriptsAdded, drift: applied.drift });
}
