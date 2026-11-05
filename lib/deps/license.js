/**
 * License policy for `penthera deps --license-policy` and the `licenses`
 * section of penthera.policy.json.
 *
 *   "licenses": {
 *     "preset": "permissive",          // permissive | weak-copyleft-ok | no-agpl
 *     "allow": ["Python-2.0"],         // added to the preset's allow list
 *     "deny": ["WTFPL"],               // added to the preset's deny list
 *     "allowPackages": ["@acme/*"],    // packages exempt from the policy (globs, @version pins)
 *     "unknown": "warn"                // missing / non-SPDX licenses: "warn" (medium) or "block" (high)
 *   }
 *
 * An allow list, when non-empty, is exhaustive: every license in a package's
 * expression must be on it (for OR, one branch is enough). A deny list always
 * wins. `UNLICENSED` (npm's word for "no rights granted") breaches any policy
 * unless the package is in allowPackages. Everything here is pure and offline:
 * license fields come from the lockfile, else the installed package.json.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseJson } from "../json-text.js";
import { readRepoFile } from "../fs-safe.js";

const SPDX = JSON.parse(readFileSync(new URL("./spdx.json", import.meta.url), "utf-8"));
const byLower = (ids) => new Map(ids.map((id) => [id.toLowerCase(), id]));
const LICENSES = byLower([...SPDX.licenses, ...SPDX.deprecated]);
const EXCEPTIONS = byLower(SPDX.exceptions);

// Deprecated GNU ids mean "-only"; "+" means "-or-later". Normalising both
// sides lets a deny of "GPL-3.0-only" catch a package that says "GPL-3.0".
const GNU = /^(A?GPL|LGPL|GFDL)-(\d\.\d)$/;
const LEGACY_WITH = /^(GPL-[23]\.0)-with-(GCC|autoconf|bison|classpath|font)-exception$/i;

// ── SPDX expression parser ────────────────────────────────────────────────

export class SpdxError extends Error {}

function tokenize(s) {
  const out = [];
  const re = /\s*(?:(\()|(\))|([A-Za-z0-9][A-Za-z0-9.+:-]*))\s*/y;
  let i = 0;
  while (i < s.length) {
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m || m[0].length === 0) {
      if (/^\s*$/.test(s.slice(i))) break;
      throw new SpdxError(`unexpected character "${s[i]}" at ${i}`);
    }
    i = re.lastIndex;
    out.push(m[1] || m[2] || m[3]);
  }
  return out;
}

const OPS = new Set(["AND", "OR", "WITH"]);
// SPDX operators are uppercase; lowercase "and"/"or" are common enough on npm
// ("MIT or Apache-2.0") that rejecting them only produces noise.
const op = (t) => (t && OPS.has(t.toUpperCase()) ? t.toUpperCase() : null);

/**
 * Parse an SPDX license expression into a tree.
 *   { type: "license", id, plus, exception, known }  (id canonical-cased when known)
 *   { type: "and" | "or", args: [...] }
 * Precedence: WITH binds tightest, then AND, then OR. Throws SpdxError.
 */
export function parseSpdx(input) {
  if (typeof input !== "string" || !input.trim()) throw new SpdxError("empty expression");
  const tokens = tokenize(input);
  let pos = 0;
  const peek = () => tokens[pos];

  function license() {
    const t = tokens[pos++];
    if (t === undefined) throw new SpdxError("expression ends early");
    if (t === "(" ) {
      const e = orExpr();
      if (tokens[pos++] !== ")") throw new SpdxError("missing )");
      return e;
    }
    if (t === ")" || op(t)) throw new SpdxError(`expected a license, got "${t}"`);
    let id = t;
    let plus = false;
    if (id.endsWith("+")) { plus = true; id = id.slice(0, -1); }
    if (!id || id.includes("+")) throw new SpdxError(`bad license id "${t}"`);
    const ref = /^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$/.test(id);
    const canon = LICENSES.get(id.toLowerCase());
    const node = { type: "license", id: canon || id, plus, exception: null, known: !!canon || ref, ref };
    if (op(peek()) === "WITH") {
      pos++;
      const ex = tokens[pos++];
      if (ex === undefined || ex === "(" || ex === ")" || op(ex)) throw new SpdxError("WITH needs an exception id");
      node.exception = EXCEPTIONS.get(ex.toLowerCase()) || ex;
      if (!EXCEPTIONS.has(ex.toLowerCase())) node.known = false;
    }
    return node;
  }
  function chain(type, next) {
    const args = [next()];
    while (op(peek()) === type.toUpperCase()) { pos++; args.push(next()); }
    if (args.length === 1) return args[0];
    // Flatten (a AND (b AND c)) into one list.
    return { type, args: args.flatMap((a) => (a.type === type ? a.args : [a])) };
  }
  const andExpr = () => chain("and", license);
  const orExpr = () => chain("or", andExpr);

  const tree = orExpr();
  if (pos < tokens.length) throw new SpdxError(`unexpected "${tokens[pos]}"`);
  return tree;
}

/** Every license leaf of a tree. */
export function leaves(tree) {
  return tree.type === "license" ? [tree] : tree.args.flatMap(leaves);
}

/** Print a tree back as a canonical expression. */
export function formatSpdx(tree, parent = null) {
  if (tree.type === "license") return `${tree.id}${tree.plus ? "+" : ""}${tree.exception ? ` WITH ${tree.exception}` : ""}`;
  const s = tree.args.map((a) => formatSpdx(a, tree.type)).join(` ${tree.type.toUpperCase()} `);
  return parent && parent !== tree.type ? `(${s})` : s;
}

/** The id a policy compares: deprecated GNU forms and "+" resolved. */
export function canonicalId(id, plus = false) {
  const legacy = LEGACY_WITH.exec(id);
  if (legacy) return `${legacy[1]}-only`;
  const gnu = GNU.exec(id.replace(/\+$/, ""));
  if (gnu) return `${gnu[1]}-${gnu[2]}-${plus || id.endsWith("+") ? "or-later" : "only"}`;
  return (LICENSES.get(id.toLowerCase()) || id).replace(/\+$/, "");
}

// ── Reading a package's license field ─────────────────────────────────────

/** package.json `license` / legacy `licenses: [{ type }]` → an expression string or null. */
export function licenseField(meta) {
  if (!meta || typeof meta !== "object") return null;
  const one = (v) => (typeof v === "string" ? v : v && typeof v === "object" && typeof v.type === "string" ? v.type : null);
  const l = one(meta.license);
  if (l && l.trim()) return l.trim();
  if (Array.isArray(meta.licenses)) {
    const all = meta.licenses.map(one).filter(Boolean);
    if (all.length) return all.length === 1 ? all[0] : `(${all.join(" OR ")})`;
  }
  return null;
}

/**
 * Classify a raw license string.
 * @returns {{ kind: "spdx"|"unlicensed"|"missing"|"custom"|"unknown", raw, expression?, tree? }}
 *   unknown: not valid SPDX, or names an id the SPDX list does not have
 */
export function classifyLicense(raw) {
  const s = typeof raw === "string" ? raw.trim() : "";
  if (!s || /^(NONE|NOASSERTION)$/i.test(s)) return { kind: "missing", raw: s || null };
  if (/^UNLICEN[SC]ED$/i.test(s)) return { kind: "unlicensed", raw: s };
  if (/^SEE LICEN[SC]E IN\b/i.test(s)) return { kind: "custom", raw: s };
  let tree;
  try {
    tree = parseSpdx(s);
  } catch (e) {
    return { kind: "unknown", raw: s, error: e.message };
  }
  const expression = formatSpdx(tree);
  const unknownIds = leaves(tree).filter((l) => !l.known).map((l) => l.id + (l.exception ? ` WITH ${l.exception}` : ""));
  if (unknownIds.length) return { kind: "unknown", raw: s, expression, tree, unknownIds };
  return { kind: "spdx", raw: s, expression, tree };
}

// ── Presets and policy ────────────────────────────────────────────────────

const PERMISSIVE = [
  "MIT", "MIT-0", "ISC", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "Apache-2.0", "Zlib",
  "Unlicense", "CC0-1.0", "BlueOak-1.0.0", "BSL-1.0", "Python-2.0", "PSF-2.0",
  "CC-BY-3.0", "CC-BY-4.0", "Unicode-DFS-2016", "Unicode-3.0", "X11", "WTFPL",
];
const WEAK_COPYLEFT = [
  "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
  "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "Artistic-2.0", "CC-BY-SA-4.0",
];
const NETWORK_COPYLEFT = ["AGPL-1.0-only", "AGPL-1.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"];

export const LICENSE_PRESETS = Object.freeze({
  permissive: { allow: PERMISSIVE, deny: [], about: "permissive licenses only (MIT, ISC, BSD, Apache-2.0, ...)" },
  "weak-copyleft-ok": { allow: [...PERMISSIVE, ...WEAK_COPYLEFT], deny: [], about: "permissive plus weak copyleft (LGPL, MPL, EPL, CDDL)" },
  "no-agpl": { allow: [], deny: NETWORK_COPYLEFT, about: "anything except AGPL and SSPL (network copyleft)" },
});

const LICENSE_FIELDS = ["preset", "allow", "deny", "allowPackages", "unknown"];

/** Validate and complete a `licenses` policy section. Throws on bad input. */
export function normalizeLicensePolicy(raw, label = "licenses") {
  if (typeof raw === "string") raw = { preset: raw };
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${label}: expected an object or a preset name`);
  const extra = Object.keys(raw).filter((k) => !LICENSE_FIELDS.includes(k));
  if (extra.length) throw new Error(`${label}: unknown field(s) ${extra.join(", ")} (expected ${LICENSE_FIELDS.join(", ")})`);
  const preset = raw.preset ?? null;
  if (preset !== null && !LICENSE_PRESETS[preset]) {
    throw new Error(`${label}: unknown preset "${preset}". Known: ${Object.keys(LICENSE_PRESETS).join(", ")}`);
  }
  const list = (field) => {
    const v = raw[field] ?? [];
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || !x.trim())) throw new Error(`${label}: "${field}" must be an array of non-empty strings`);
    return v.map((x) => x.trim());
  };
  const unknown = raw.unknown ?? "warn";
  if (!["warn", "block"].includes(unknown)) throw new Error(`${label}: "unknown" must be "warn" or "block"`);
  const base = preset ? LICENSE_PRESETS[preset] : { allow: [], deny: [] };
  const allow = [...new Set([...base.allow, ...list("allow")])];
  const deny = [...new Set([...base.deny, ...list("deny")])];
  if (!allow.length && !deny.length) throw new Error(`${label}: give a preset, an allow list or a deny list`);
  return { preset, allow, deny, allowPackages: list("allowPackages"), unknown };
}

const globRe = (pattern) => new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");

/** Does one policy entry ("MIT", "GPL-3.0", "AGPL-*", "GPL-2.0-only WITH Classpath-exception-2.0") match a leaf? */
function entryMatches(entry, leaf) {
  const id = canonicalId(leaf.id, leaf.plus);
  const [e, ex] = entry.split(/\s+WITH\s+/i);
  if (ex && (!leaf.exception || leaf.exception.toLowerCase() !== ex.toLowerCase())) return false;
  if (e.includes("*")) return globRe(e).test(id) || globRe(e).test(leaf.id);
  return canonicalId(e).toLowerCase() === id.toLowerCase();
}

/** Is a package exempt via allowPackages (name globs, optional @version)? */
export function packageExempt(allowPackages, name, version) {
  return allowPackages.find((entry) => {
    const at = entry.lastIndexOf("@");
    const [n, v] = at > 0 ? [entry.slice(0, at), entry.slice(at + 1)] : [entry, null];
    return globRe(n).test(name) && (!v || v === "*" || v === version);
  }) || null;
}

/**
 * Check one parsed expression against a policy.
 * @returns {{ ok: boolean, offending: string[] }} offending: the licenses that broke it
 */
export function evaluateExpression(tree, policy) {
  if (tree.type === "license") {
    const denied = policy.deny.some((e) => entryMatches(e, tree));
    const allowed = !policy.allow.length || policy.allow.some((e) => entryMatches(e, tree));
    return denied || !allowed ? { ok: false, offending: [formatSpdx(tree)], denied } : { ok: true, offending: [] };
  }
  const parts = tree.args.map((a) => evaluateExpression(a, policy));
  if (tree.type === "or") {
    return parts.some((p) => p.ok) ? { ok: true, offending: [] } : { ok: false, offending: [...new Set(parts.flatMap((p) => p.offending))], denied: parts.some((p) => p.denied) };
  }
  const bad = parts.filter((p) => !p.ok);
  return bad.length ? { ok: false, offending: [...new Set(bad.flatMap((p) => p.offending))], denied: bad.some((p) => p.denied) } : { ok: true, offending: [] };
}

// ── Findings ──────────────────────────────────────────────────────────────

const policyName = (p) => (p.preset ? `the "${p.preset}" preset` : "the license policy");

/** Read a package's license: lockfile field first, else its installed package.json. */
export function packageLicense(pkg, treeRoot) {
  if (pkg.license) return { raw: pkg.license, from: "lockfile" };
  if (treeRoot) {
    try {
      // A regular file up to 5 MiB: a package.json linked to /dev/zero, or a FIFO, is skipped.
      const meta = parseJson(readRepoFile(join(treeRoot, pkg.path, "package.json"), { followLinks: true, maxBytes: 5 * 1024 * 1024 }));
      return { raw: licenseField(meta), from: "package.json" };
    } catch { /* not installed */ }
  }
  return { raw: null, from: null };
}

/**
 * Apply a license policy to lockfile packages.
 * @param {{ name, version, path, license? }[]} pkgs
 * @param {object} policy from normalizeLicensePolicy
 * @param {{ treeRoot?: string, lockfileHasLicenses?: boolean }} opts
 * @returns {{ findings: object[], summary: object }}
 */
export function checkLicenses(pkgs, policy, opts = {}) {
  const findings = [];
  const counts = {};
  const summary = { policy: policy.preset || "custom", checked: 0, notChecked: 0, exempt: 0, breaches: 0, unlicensed: 0, missing: 0, unknown: 0, counts };
  const unknownSeverity = policy.unknown === "block" ? "high" : "medium";
  const seen = new Set();
  for (const p of pkgs) {
    const at = `${p.name}@${p.version}`;
    if (seen.has(at)) continue;
    seen.add(at);
    const { raw, from } = packageLicense(p, opts.treeRoot);
    // A v1 lockfile has no license fields: an uninstalled package was simply not checked.
    if (!from && !opts.lockfileHasLicenses) { summary.notChecked++; continue; }
    summary.checked++;
    const c = classifyLicense(raw);
    const shown = c.expression || c.raw || "none";
    counts[shown] = (counts[shown] || 0) + 1;
    const exemptBy = packageExempt(policy.allowPackages, p.name, p.version);
    if (exemptBy) { summary.exempt++; continue; }

    const base = { category: "license", source: "license-policy", method: "license-policy", url: p.path, package: p.name, version: p.version, license: c.raw };
    const fix = `Replace ${p.name}, or exempt it with "allowPackages": ["${p.name}"] in the licenses section of penthera.policy.json if your legal review accepts it.`;
    if (c.kind === "spdx") {
      const r = evaluateExpression(c.tree, policy);
      if (r.ok) continue;
      summary.breaches++;
      findings.push({
        ...base,
        title: `${at}: license ${c.expression} ${r.denied ? "denied by the license policy" : `not allowed by ${policyName(policy)}`}`,
        severity: "high",
        confidence: "confirmed",
        description: `${p.name} is licensed ${c.expression}; ${r.offending.join(", ")} ${r.denied ? "is on the deny list" : "is not on the allow list"} (${from === "lockfile" ? "license field in the lockfile" : "installed package.json"}). ${fix}`,
      });
    } else if (c.kind === "unlicensed") {
      summary.unlicensed++;
      findings.push({
        ...base,
        title: `${at}: UNLICENSED (no rights granted)`,
        severity: "high",
        confidence: "confirmed",
        description: `${p.name} declares "UNLICENSED": its authors grant no right to use, copy or ship it. This is normal for private packages and a problem for anything else. ${fix}`,
      });
    } else {
      summary[c.kind === "missing" ? "missing" : "unknown"]++;
      const what = c.kind === "missing" ? "no license" : c.kind === "custom" ? `a custom license (${c.raw})` : `a license that is not valid SPDX (${c.raw}${c.unknownIds ? `: unknown ${c.unknownIds.join(", ")}` : ""})`;
      findings.push({
        ...base,
        title: `${at}: ${c.kind === "missing" ? "no license declared" : c.kind === "custom" ? "custom license" : `unknown license ${c.raw}`}`,
        severity: unknownSeverity,
        confidence: "likely",
        description: `${p.name} declares ${what}, so the policy cannot be checked automatically. Read its license file before shipping it. ${fix}`,
      });
    }
  }
  return { findings, summary };
}
