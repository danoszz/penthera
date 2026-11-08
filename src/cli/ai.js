/**
 * AI mode on the command line: `--ai` on a repo scan, and `penthera ai`.
 *
 * preflightAi() runs before anything is scanned: it finds Ollama, picks the
 * model, works out its route (local or ollama-cloud) and asks for consent.
 * Outcomes:
 * - run:   consent given; the hunt runs after the rules.
 * - skip:  AI mode does not run this time (Ollama not running, no model,
 *          the user said no). The rules-only scan goes on; the report says why.
 * - exit:  the run stops before scanning with exit 2 (a run that cannot ask
 *          and has no --ai-consent or policy; a policy that turns AI mode off;
 *          a bad flag).
 *
 * `penthera ai models` lists Ollama's models and which run on this computer.
 * `penthera ai consent` prints the local consent log.
 */
import { createInterface } from "node:readline";
import { basename, resolve } from "node:path";
import { parseArgs } from "node:util";
import { askConsent, consentLogPath, logConsent, readConsentLog, CLOUD_HOST } from "../../lib/ai/consent.js";
import { createOllama, OllamaError } from "../../lib/ai/ollama.js";
import { parseBudget } from "../../lib/ai/hunt.js";
import { loadPolicy } from "../../lib/install/policy.js";
import { bold, dim, yellow } from "./ansi.js";

function askOnStderr(question) {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((done) => rl.question(question, (a) => { rl.close(); done(a); }));
}

/**
 * @param {object} p
 * @param {object} p.opts - parsed CLI options (ai-model, ai-budget, ai-consent, ai-scope, json)
 * @param {string} p.repo - repository path
 * @param {boolean} [p.interactive]
 * @param {(q: string) => Promise<string>} [p.ask]
 * @param {(t: string) => void} [p.write]
 * @param {object} [p.ollama]
 * @param {object} [p.env]
 */
export async function preflightAi({ opts, repo, interactive, ask = askOnStderr, write = (t) => process.stderr.write(t), ollama = createOllama(), env = process.env }) {
  const isInteractive = interactive ?? (process.stdin.isTTY === true && process.stderr.isTTY === true && !opts.json);
  let budget;
  try {
    budget = parseBudget(opts["ai-budget"]);
  } catch (e) {
    return { exit: 2, message: e.message };
  }
  let policyAllow = null;
  try {
    const { policy, warning } = loadPolicy(repo);
    // The policy can turn AI mode off; one that could not be read is not taken as consent.
    if (warning) return { exit: 2, message: `${warning.replace(/ The scan used the default policy.*$/, "")} AI mode does not run until it can be read.` };
    policyAllow = policy.ai?.allow ?? null;
  } catch (e) {
    return { exit: 2, message: e.message };
  }
  if (policyAllow && policyAllow.length === 0) {
    return { exit: 2, message: "penthera.policy.json turns AI mode off for this repository (\"ai\": { \"allow\": [] })." };
  }

  // A run that cannot ask and was given no consent stops here, before Ollama is contacted.
  if (!isInteractive && opts["ai-consent"] == null && !policyAllow) {
    return { exit: 2, message: "AI mode needs consent, and this run cannot ask. Add --ai-consent local (or ollama-cloud for a cloud model), or \"ai\": { \"allow\": [\"local\"] } in penthera.policy.json." };
  }

  let models;
  try {
    models = await ollama.models();
  } catch (e) {
    return { skip: true, reason: e instanceof OllamaError ? e.message : `Ollama could not be read: ${e.message}` };
  }

  let model;
  if (opts["ai-model"]) {
    model = models.find((m) => m.name === opts["ai-model"] || m.name === `${opts["ai-model"]}:latest`);
    if (!model) return { skip: true, reason: `Ollama has no model named ${opts["ai-model"]}. \`penthera ai models\` lists what is installed.` };
  } else if (!models.length) {
    return { skip: true, reason: "Ollama has no models installed. Pull one, for example `ollama pull qwen2.5-coder:7b`, then run again." };
  } else if (!isInteractive) {
    return { skip: true, reason: "Name the model with --ai-model <name> in a run that cannot ask. `penthera ai models` lists them." };
  } else {
    model = await chooseModel(models, { ask, write });
    if (!model) return { skip: true, declined: true, reason: "No model chosen; AI mode is off for this run." };
  }

  const project = `./${basename(resolve(repo))}`;
  const consent = await askConsent({
    route: model.route,
    model: model.name,
    project,
    maxUnits: budget.units,
    flag: opts["ai-consent"] ?? null,
    policyAllow,
    interactive: isInteractive,
    ask,
    write,
    modelInfo: model,
    env,
  });
  if (!consent.ok) {
    if (consent.declined) return { skip: true, declined: true, reason: `${consent.reason} The scan runs with rules only; add --ai again to be asked.` };
    return { exit: 2, message: consent.reason };
  }
  const iface = consent.via === "terminal" ? "terminal" : consent.via;
  logConsent({ project: resolve(repo), route: model.route, model: model.name, digest: model.digest, via: iface }, env);
  return { run: true, model, consent, budget, scope: opts["ai-scope"] || null };
}

async function chooseModel(models, { ask, write }) {
  const list = [...models.filter((m) => m.route === "local"), ...models.filter((m) => m.route !== "local")];
  write(`\n  ${bold("Which model?")} Installed in Ollama:\n`);
  list.forEach((m, i) => write(`    ${i + 1}. ${m.name}${m.route === "local" ? "" : dim(`  runs on ${CLOUD_HOST}`)}\n`));
  const a = String(await ask(`\n  Model [1-${list.length}, Enter to skip AI mode]: `)).trim();
  const n = Number.parseInt(a, 10);
  return Number.isInteger(n) && n >= 1 && n <= list.length ? list[n - 1] : null;
}

/** One line at the top of an AI run, and the progress line per unit. */
export function aiHeader(model) {
  return model.route === "local"
    ? `  AI: ${model.name} on this computer · nothing sent off it`
    : `  AI: ${model.name} on ${CLOUD_HOST} · code sent there through your local Ollama`;
}

// ── penthera ai ────────────────────────────────────────────────────────────

const HELP = `
  penthera ai models       Ollama's models, and which run on this computer
  penthera ai consent      The consent log: what AI mode was allowed, when, for which project

  AI mode itself runs with a repo scan: penthera --repo . --ai
  See docs/ai-mode.md.
`;

export async function runAiCommand(argv, { out = process.stdout, err = process.stderr, ollama = createOllama(), env = process.env } = {}) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: true, options: { json: { type: "boolean", default: false }, help: { type: "boolean", short: "h", default: false } } });
  } catch (e) {
    err.write(`  ${e.message}\n${HELP}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) { out.write(HELP); return 0; }
  const action = positionals[0];
  if (action === "models") {
    let models;
    try {
      models = await ollama.models();
    } catch (e) {
      err.write(`  ${e.message}\n`);
      return 2;
    }
    if (values.json) { out.write(JSON.stringify(models, null, 2) + "\n"); return 0; }
    if (!models.length) { out.write("  Ollama has no models. Pull one, for example `ollama pull qwen2.5-coder:7b`.\n"); return 0; }
    out.write(`\n  ${bold("Ollama models")} ${dim("(127.0.0.1:11434)")}\n\n`);
    for (const m of models) {
      out.write(`    ${m.name.padEnd(36)} ${m.route === "local" ? "runs on this computer" : yellow(`runs on ${CLOUD_HOST}`)}\n`);
      if (m.remoteReason) out.write(`    ${" ".repeat(36)} ${dim(m.remoteReason)}\n`);
    }
    out.write(`\n  ${dim(`A model on ${CLOUD_HOST} sends your code there, and needs its own consent.`)}\n\n`);
    return 0;
  }
  if (action === "consent") {
    const log = readConsentLog(env);
    if (values.json) { out.write(JSON.stringify(log, null, 2) + "\n"); return 0; }
    out.write(`\n  ${bold("AI mode consent log")} ${dim(consentLogPath(env))}\n`);
    out.write(`  ${dim("Asked on every run; nothing here is used to skip a question.")}\n\n`);
    if (!log.length) { out.write("  No AI runs yet.\n\n"); return 0; }
    for (const e of log.slice(-50)) {
      out.write(`    ${String(e.at).slice(0, 19).replace("T", " ")}  ${String(e.route).padEnd(13)} ${String(e.model).padEnd(28)} ${e.via}  ${dim(e.project)}\n`);
    }
    if (log.length > 50) out.write(`\n  ${dim(`${log.length - 50} older entries in the file.`)}\n`);
    out.write("\n");
    return 0;
  }
  (action ? err : out).write(HELP);
  return action ? 2 : 0;
}
