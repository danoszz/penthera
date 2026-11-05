#!/usr/bin/env node
/**
 * Every rule Penthera runs, read from the code that runs it, for the rule gate
 * (tests/rule-gate.test.js). Nothing here is typed by hand: a rule added to the
 * engine shows up here, and the gate then asks for a fixture that fires it.
 *
 *   node scripts/rule-inventory.mjs     prints the rules as JSON
 *
 * Dev tooling: not in the npm package.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const read = (file) => readFileSync(join(ROOT, file), "utf-8");
const SEVERE = new Set(["critical", "high"]);

/** `rule: "x"` literals in a file, with the first severity literal within three lines. */
function raisedRules(file) {
  const lines = read(file).split("\n");
  const out = new Map();
  lines.forEach((line, i) => {
    for (const m of line.matchAll(/\brule: "([a-z0-9][a-z0-9.-]*)"/g)) {
      // A severity on the rule's own line wins: neighbouring rules sit within three lines too.
      const own = line.slice(m.index).match(/severity: "(critical|high|medium|low|info)"/)?.[1];
      const near = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
      const sev = own || near.match(/severity: "(critical|high|medium|low|info)"/)?.[1] || "varies";
      const prev = out.get(m[1]) || { severities: new Set(), file, line: i + 1 };
      prev.severities.add(sev);
      out.set(m[1], prev);
    }
  });
  return out;
}

/** @returns {Promise<{ id: string, family: string, severities: string[], severe: boolean, file: string }[]>} */
export async function ruleInventory() {
  const rules = [];
  const add = (id, family, severities, file) => rules.push({ id, family, severities: [...severities], severe: [...severities].some((s) => SEVERE.has(s)), file });

  // Agent config rules: every rule the OWASP map names, and every rule the code raises.
  const { RULE_OWASP } = await import("../lib/agents/owasp.js");
  const raised = new Map();
  for (const f of readdirSync(join(ROOT, "lib/agents")).filter((n) => n.endsWith(".js"))) {
    for (const [id, r] of raisedRules(`lib/agents/${f}`)) {
      const prev = raised.get(id);
      if (prev) for (const s of r.severities) prev.severities.add(s);
      else raised.set(id, r);
    }
  }
  for (const id of new Set([...Object.keys(RULE_OWASP), ...raised.keys()])) {
    const r = raised.get(id);
    add(`agents/${id}`, "agents", r ? r.severities : ["varies"], r?.file || "lib/agents/owasp.js");
  }

  // Secret patterns: the built-in ones and the signed pack's.
  const { activeSecretPatterns } = await import("../lib/whitebox/secrets.js");
  for (const p of activeSecretPatterns()) add(`secret:${p.name}`, "secrets", [p.severity], p.pack ? `pack:${p.pack}` : "lib/whitebox/secrets.js");

  // Dependency capabilities.
  const { CAPABILITIES } = await import("../lib/deps/capabilities.js");
  for (const [id, c] of Object.entries(CAPABILITIES)) add(`deps:${id}`, "deps", [c.severity], "lib/deps/capabilities.js");

  // Live-check templates.
  const { BUILT_IN_TEMPLATES } = await import("../lib/templates.js");
  for (const t of BUILT_IN_TEMPLATES) add(`template:${t.id}`, "templates", [t.info?.severity || "info"], "lib/templates.js");

  // Runtime advisories and end-of-life lines, from the signed packs.
  const { rulesOf } = await import("../lib/rules/index.js");
  for (const a of rulesOf("runtime-advisory")) add(`runtime:${a.id}`, "runtime", [a.severity], `pack:${a.pack || "runtime"}`);
  for (const e of rulesOf("runtime-eol")) add(`runtime:${e.id}`, "runtime", ["high"], `pack:${e.pack || "runtime"}`);

  const seen = new Set();
  return rules.filter((r) => (seen.has(r.id) ? false : seen.add(r.id)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(await ruleInventory(), null, 2)}\n`);
}
