/**
 * Fix recipes: deterministic, local fixes for common findings.
 *
 * A recipe is { id, matches(finding), detect(repoPath), plan(repoPath, finding,
 * framework) } and may add probe(repoPath), a static check that reports the
 * finding from source so a fix can be verified without a live server. plan()
 * returns { diff, files, ownerActions, confidence } or null when it cannot find
 * a safe anchor. Recipes never write: applyDiff() is the separate step that does.
 */
import { createHash } from "node:crypto";
import { findSecretsInText } from "../whitebox/secrets.js";
import headers from "./recipes/headers.js";
import cookies from "./recipes/cookies.js";
import cors from "./recipes/cors.js";
import rateLimit from "./recipes/rate-limit.js";
import secrets from "./recipes/secrets.js";

export { applyDiff, assertCleanTree, restoreFiles, FixError } from "./apply.js";
export { createPatch, parsePatch, applyHunks } from "./diff.js";
export { createModelFixer } from "./model.js";

export const RECIPES = [headers, cookies, cors, rateLimit, secrets];

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Findings from every recipe's static probe (headers, cookies, CORS, auth rate limits). */
export function probeRepo(repoPath, recipes = RECIPES) {
  return recipes.flatMap((r) => {
    if (!r.probe) return [];
    try {
      return r.probe(repoPath);
    } catch {
      return [];
    }
  });
}

export function findingKey(f) {
  return `${f.category || ""}|${f.title || ""}|${f.url || ""}|${f.file || ""}`;
}

function planId(recipeId, diff) {
  return `${recipeId}-${createHash("sha256").update(diff).digest("hex").slice(0, 8)}`;
}

const brief = (f) => ({ title: f.title, severity: f.severity, category: f.category, url: f.url || null, file: f.file || null });

/**
 * How many of a scan's findings a recipe could take, for the line a scan prints.
 * It only compares them: planning reads the repo, and a scan has to stay fast.
 *
 * @param {object[]} findings
 * @returns {number}
 */
export function fixSummary(findings, recipes = RECIPES) {
  return findings.filter((f) => recipes.some((r) => r.matches(f))).length;
}

/**
 * Plan fixes for findings. Findings that resolve to the same diff (say, five
 * missing headers fixed by one middleware) share one plan.
 *
 * @param {string} repoPath
 * @param {object[]} findings
 * @param {{ model?: { plan(repoPath, finding): Promise<object|null> }, recipes?: object[] }} [opts]
 * @returns {Promise<{ plans: object[], unmatched: object[], refused: { finding: object, reason: string }[] }>}
 *   refused: findings whose model diff edited a protected file; they are in unmatched too.
 */
export async function planFixes(repoPath, findings, opts = {}) {
  const recipes = opts.recipes || RECIPES;
  const plans = new Map();
  const unmatched = [];
  const refused = [];
  const frameworks = new Map();
  const sorted = [...(findings || [])].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  const add = (plan, finding) => {
    const id = planId(plan.recipe, plan.diff);
    const existing = plans.get(id);
    if (existing) {
      if (!existing.findings.some((f) => findingKey(f) === findingKey(finding))) existing.findings.push(brief(finding));
      return;
    }
    plans.set(id, { id, ...plan, findings: [brief(finding)] });
  };

  for (const finding of sorted) {
    let planned = false;
    for (const recipe of recipes) {
      if (!recipe.matches(finding)) continue;
      if (!frameworks.has(recipe.id)) frameworks.set(recipe.id, recipe.detect(repoPath));
      const framework = frameworks.get(recipe.id);
      if (!framework) continue;
      let p = null;
      try {
        p = recipe.plan(repoPath, finding, framework);
      } catch {
        p = null; // a recipe that trips over unexpected code declines rather than guessing
      }
      if (!p?.diff) continue;
      add({
        recipe: recipe.id,
        title: recipe.title,
        framework,
        source: "recipe",
        confidence: p.confidence || "medium",
        diff: p.diff,
        files: p.files,
        ownerActions: p.ownerActions || [],
        redactions: p.redactions || [],
      }, finding);
      planned = true;
      break;
    }
    if (planned) continue;
    if (opts.model && finding.severity !== "info") {
      let p = null;
      try {
        p = await opts.model.plan(repoPath, finding);
      } catch (e) {
        if (e?.code === "PROTECTED") refused.push({ finding, reason: e.message });
        p = null;
      }
      if (p?.diff) {
        add({ recipe: "local-model", title: "Model-suggested fix", framework: null, redactions: [], ...p }, finding);
        continue;
      }
    }
    unmatched.push(finding);
  }
  return { plans: [...plans.values()], unmatched, refused };
}

/** Mask redacted values (hardcoded secrets) so a plan is safe to print or store. */
export function redactPlan(plan, { context = false } = {}) {
  const flagged = (plan.redactions || []).filter(Boolean);
  const shown = [];
  // Only the dashboard's approval window asks for this: the same masks, on the local screen, nowhere else.
  const framed = [];
  let unchanged = 0;
  let unchangedHidden = 0;
  let masked = false;
  let contextMasked = false;
  let keySide = null;
  const flush = () => {
    if (unchanged) shown.push(`… ${unchanged} line${unchanged === 1 ? "" : "s"} unchanged`);
    unchangedHidden += unchanged;
    unchanged = 0;
  };
  const lines = plan.diff.split("\n");
  for (const [i, line] of lines.entries()) {
    const bare = line.replace(/\r$/, ""); // CRLF is dropped by the masks, which isn't hiding anything
    // A key's body has no marks of its own, so its side of the diff stays hidden
    // until the END line. A hunk can cut a block short, so a new hunk ends it too.
    if (line.startsWith("@@ ") || fileHeader(lines, i)) keySide = null;
    const hide = keySide === line[0] || (PEM_BEGIN.test(line) && /^[+-]/.test(line));
    if (PEM_BEGIN.test(line) && !PEM_END.test(line)) keySide = line[0];
    else if (PEM_END.test(line) && keySide === line[0]) keySide = null;
    // No unchanged line is shown: a secret beside a change can take any shape.
    if (line[0] === " ") {
      unchanged++;
      // The masks read changed lines, so an unchanged line goes through as one. They can't catch
      // every shape, so a line that names a secret or holds a long quoted value isn't shown at all.
      const kept = hide ? " [key block hidden]" : CONTEXT_HIDE.test(line) ? " [line hidden]" : ` ${redactLine(`+${line.slice(1)}`, flagged, true).slice(1)}`;
      if (kept !== bare) contextMasked = true;
      framed.push(kept);
      continue;
    }
    flush();
    const out = hide && /^[+-]/.test(line) ? `${line[0]}[key block hidden]` : redactLine(line, flagged, !fileHeader(lines, i));
    if (out !== bare) masked = true;
    shown.push(out);
    framed.push(out);
  }
  flush();
  const { redactions, ...rest } = plan;
  return { ...rest, diff: shown.join("\n"), redacted: masked || (context && contextMasked), unchangedHidden, ...(context ? { contextDiff: framed.join("\n") } : {}) };
}

const PEM_BEGIN = /-----BEGIN [A-Z0-9 ]*(?:KEY|CERTIFICATE)[A-Z0-9 ]*-----/;
const PEM_END = /-----END [A-Z0-9 ]*(?:KEY|CERTIFICATE)[A-Z0-9 ]*-----/;
const BASE64_LINE = /^[\s'"`]*[A-Za-z0-9+/]{40,}={0,2}[\s'"`+,;]*$/;
const URL_PASSWORD = /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"`]*:([^\s@'"`/]+)@/gi;
const QUERY_SECRET = /([?&](?:api[_-]?key|key|token|access_token|secret|password|sig|signature)=)[^&\s'"`]+/gi;
const TOKEN_SHAPE = /\b(?:https:\/\/hooks\.slack\.com\/services\/[\w/]+|xox[a-z]-[\w-]{8,}|gh[pousr]_\w{16,}|github_pat_\w{16,}|AKIA[0-9A-Z]{12,}|sk[-_](?:live|test|proj|ant)[-_][\w-]{8,}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*)/g;
const SECRET_WORD = /secret|passw|pass(?![a-z])|\bpw\b|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|bearer|\bdsn\b/i;
const HEX_OR_UUID = /['"`](?:[0-9a-f]{32,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"`]/i;
const QUOTED = /(['"`])([^'"`\n]{8,})\1/g;
const ALL_QUOTED = /(['"`]).*(['"`])/;
const IMPORT_LINE = /^\s*(?:(?:import|export)\b[^=;]*['"`][^'"`]+['"`]\s*;?|(?:const|let|var)\s+[\w$]+\s*=\s*require\(['"`][^'"`]+['"`]\)\s*;?)\s*$/;
// Long quoted values, and a user:password on a command line. The first is broad on purpose.
const CONTEXT_HIDE = new RegExp(`${SECRET_WORD.source}|['"\`][^'"\`]{8,}['"\`]|\\s-u\\s+\\S+:\\S+`, "i");
const SECRET_FLAG = /(--?(?:password|passwd|pwd|token|secret|api[_-]?key)[= ]\s*)(?!\*\*\*)[^\s'"`]+/gi;
const SETTING = /^(\s*(?:export\s+)?[\w.-]+\s*[=:]\s*)\S.*$/; // .env, shell and YAML
const MAX_LITERAL_ENTROPY = 3.9; // bits per character: above this a long literal is treated as a key

function entropyOf(text) {
  const counts = new Map();
  for (const ch of text) counts.set(ch, (counts.get(ch) || 0) + 1);
  return [...counts.values()].reduce((sum, n) => sum - (n / text.length) * Math.log2(n / text.length), 0);
}

const maskValue = (value) => (value.length <= 12 ? "***" : `${value.slice(0, 4)}…${value.slice(-4)}`);

/** A file's "--- a" and "+++ b" pair. Alone, either mark is a changed line that starts with "--" or "++". */
const fileHeader = (lines, i) => (lines[i].startsWith("--- ") && lines[i + 1]?.startsWith("+++ ")) || (lines[i].startsWith("+++ ") && lines[i - 1]?.startsWith("--- "));

/** A changed diff line as it may be shown: no value that looks like a secret. */
function redactLine(line, flagged, content = false) {
  const sign = line[0];
  if (!"+-".includes(sign) || (!content && /^(?:---|\+\+\+) /.test(line))) return line;
  if (PEM_BEGIN.test(line) || BASE64_LINE.test(line.slice(1))) return `${sign}[key block hidden]`;
  let text = line.slice(1).replace(/\r$/, "");
  for (const value of flagged) text = text.split(value).join(maskValue(value));
  text = text.replace(URL_PASSWORD, (m, password) => m.replace(`:${password}@`, ":***@"));
  text = text.replace(QUERY_SECRET, "$1***").replace(SECRET_FLAG, "$1***").replace(TOKEN_SHAPE, maskValue);
  for (const hit of findSecretsInText(text)) {
    const value = hit.match.match(/['"`]([^'"`]+)['"`]$/)?.[1] || hit.match;
    text = text.split(value).join(maskValue(value));
  }
  const named = SECRET_WORD.test(text);
  // Next to a word like "password" a value cannot be told from a secret.
  const imported = IMPORT_LINE.test(text);
  text = text.replace(HEX_OR_UUID, (m) => `${m[0]}***${m[0]}`);
  if (named && !imported) text = text.replace(ALL_QUOTED, "$1***$2");
  text = text.replace(QUOTED, (m, quote, value) => {
    const key = !/\s/.test(value) && value.length >= 20 && !/^https?:\/\//.test(value) && entropyOf(value) >= MAX_LITERAL_ENTROPY;
    return key ? `${quote}${maskValue(value)}${quote}` : m;
  });
  if (named && !/['"`]/.test(text)) text = text.replace(SETTING, "$1***");
  return sign + text;
}
