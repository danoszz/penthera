/**
 * The merge for --giants (spec-giants.md, "Merging"; fixed in E14's
 * pre-registration before any combination is scored).
 *
 * Two findings are the same when their keys match:
 *
 *   secret            file, line, and the secret's value (hashed); two tools
 *                     on the same key in the same place merge, two keys on
 *                     one line do not. When either finding has no value (a
 *                     line inside a private key block, a tool that masks
 *                     it), file and line alone decide, for every tool
 *                     (E14 § 9, 2026-10-27)
 *   code              file, line, and a shared CWE; a finding without a CWE
 *                     merges only with the same tool's same rule
 *   dependency or     ecosystem, package, version, and a shared advisory id
 *   container vuln    across aliases (CVE, GHSA, OSV, PYSEC)
 *   infrastructure    file, resource, and a shared check id; no merge across
 *                     tools without a shared id
 *   web               URL, parameter, and a shared CWE
 *
 * A merged finding keeps every source and the highest severity.
 *
 * The default, until E14 reports (spec decision 3), is Penthera-first: a tool
 * finding that matches a Penthera finding is folded into it ("found by
 * Penthera, gitleaks"), and Penthera's confidence and remediation lead. The
 * rest are merged among themselves and listed in their own section, "also
 * reported by other tools", not in Penthera's list.
 */
import { findSecretsInText } from "../whitebox/secrets.js";
import { secretTokens } from "./adapters/gitleaks.js";
import { maxSeverity, readLine, secretHash } from "./finding.js";

export const DEFAULT_MERGE = "penthera-first";

const intersects = (a = [], b = []) => a.some((x) => b.includes(x));
const upper = (xs = []) => xs.map((x) => String(x).toUpperCase());
const sameTool = (a, b) => a.sources[0]?.tool === b.sources[0]?.tool && a.sources[0]?.ruleId === b.sources[0]?.ruleId;
const VULN = new Set(["dependency-vuln", "container-vuln"]);

function normUrl(u) {
  try {
    const x = new URL(u);
    return `${x.protocol}//${x.host.toLowerCase()}${x.pathname.replace(/\/+$/, "") || "/"}`;
  } catch {
    return String(u || "").toLowerCase();
  }
}

/** True when two findings (tool or Penthera, in the shape of makeFinding) are the same finding. */
export function sameFinding(a, b) {
  const ka = a.key || {};
  const kb = b.key || {};
  if (a.category === "secret" && b.category === "secret") {
    if (a.file !== b.file || a.line !== b.line) return false;
    if (!ka.secretHashes?.length || !kb.secretHashes?.length) return true;
    return intersects(ka.secretHashes, kb.secretHashes);
  }
  if (a.category === "code" && b.category === "code") {
    if (a.file !== b.file || a.line !== b.line) return false;
    if (ka.cwe?.length && kb.cwe?.length) return intersects(upper(ka.cwe), upper(kb.cwe));
    return sameTool(a, b);
  }
  if (VULN.has(a.category) && a.category === b.category) {
    return ka.ecosystem === kb.ecosystem && ka.pkg === kb.pkg && ka.version === kb.version && intersects(upper(ka.advisories), upper(kb.advisories));
  }
  if (a.category === "infra-misconfig" && b.category === "infra-misconfig") {
    return a.file === b.file && (ka.resource || null) === (kb.resource || null) && intersects(upper(ka.checkIds), upper(kb.checkIds));
  }
  if (a.category === "web" && b.category === "web") {
    if (normUrl(a.url) !== normUrl(b.url) || (ka.parameter || null) !== (kb.parameter || null)) return false;
    if (ka.cwe?.length && kb.cwe?.length) return intersects(upper(ka.cwe), upper(kb.cwe));
    return sameTool(a, b);
  }
  return false;
}

/** Fold a group of same findings into one: the first leads; every source kept; highest severity. */
function combine(group) {
  const [lead, ...rest] = group;
  if (!rest.length) return lead;
  const sources = [];
  for (const f of group) for (const s of f.sources) if (!sources.some((x) => x.tool === s.tool && x.ruleId === s.ruleId)) sources.push(s);
  const foundBy = [...new Set(group.flatMap((f) => f.foundBy || [f.source]))];
  const key = { ...lead.key };
  for (const f of rest) {
    for (const k of ["secretHashes", "cwe", "advisories", "checkIds"]) {
      if (Array.isArray(f.key?.[k])) key[k] = [...new Set([...(key[k] || []), ...f.key[k]])].sort();
    }
  }
  return { ...lead, severity: group.reduce((s, f) => maxSeverity(s, f.severity), lead.severity), sources, foundBy, key };
}

/**
 * Merge same findings among the tools' own findings. Order is kept: the
 * earliest finding of each group leads, so the tool order decides.
 */
export function mergeToolFindings(findings) {
  const parent = findings.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  // Bucket first so the pairwise check stays small.
  const buckets = new Map();
  findings.forEach((f, i) => {
    const b = VULN.has(f.category) ? `${f.category}|${f.key?.ecosystem}|${f.key?.pkg}|${f.key?.version}`
      : f.category === "web" ? `web|${normUrl(f.url)}`
        : `${f.category}|${f.file}|${f.category === "infra-misconfig" ? "" : f.line}`;
    if (!buckets.has(b)) buckets.set(b, []);
    buckets.get(b).push(i);
  });
  for (const idx of buckets.values()) {
    for (let x = 0; x < idx.length; x++) {
      for (let y = x + 1; y < idx.length; y++) {
        if (sameFinding(findings[idx[x]], findings[idx[y]])) parent[find(idx[y])] = find(idx[x]);
      }
    }
  }
  const groups = new Map();
  findings.forEach((f, i) => {
    const r = find(i);
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r).push(f);
  });
  return [...groups.values()].map(combine);
}

// Penthera's code-pattern names as CWE ids, for the code key.
const PATTERN_CWE = [
  [/eval|new function|vm\./i, "CWE-95"],
  [/command|exec|shell/i, "CWE-78"],
  [/sql/i, "CWE-89"],
  [/xss|innerhtml|dangerouslysetinnerhtml/i, "CWE-79"],
  [/path traversal|traversal/i, "CWE-22"],
  [/ssrf/i, "CWE-918"],
  [/redirect/i, "CWE-601"],
  [/deserial/i, "CWE-502"],
];

/**
 * A Penthera finding in the merge's terms, or null when no tool can report
 * the same thing (Penthera's header, TLS and agent checks have no tool
 * counterpart here). Secret values are read back from the file, hashed, and
 * never kept.
 */
export function pentheraKeyed(f, root) {
  const file = f.file || f.url;
  if (f.category === "secrets" && f.source === "secret-scan" && file && root) {
    const lines = Array.isArray(f.lines) && f.lines.length ? f.lines : f.line ? [f.line] : [];
    return lines.map((line) => {
      const text = readLine(root, file, line);
      const hashes = text == null ? [] : findSecretsInText(text, { path: file }).flatMap((h) => secretTokens(h.match)).map(secretHash);
      return { category: "secret", file, line, key: { secretHashes: [...new Set(hashes)] }, sources: [] };
    });
  }
  if (f.category === "code-pattern" && file && f.line) {
    const name = `${f.pattern || ""} ${f.title || ""}`;
    const cwe = PATTERN_CWE.filter(([re]) => re.test(name)).map(([, id]) => id);
    return cwe.length ? [{ category: "code", file, line: f.line, key: { cwe: cwe.slice(0, 1) }, sources: [] }] : [];
  }
  if (Array.isArray(f.cwe) && f.cwe.length && /^https?:/i.test(f.url || "")) {
    return [{ category: "web", url: f.url, key: { cwe: f.cwe, parameter: f.parameter || null }, sources: [] }];
  }
  return [];
}

/**
 * Penthera-first: fold the tools' findings that match a Penthera finding into
 * it, merge the rest among themselves.
 * @param {object[]} penthera - Penthera's own findings
 * @param {object[]} tools - every adapter's findings, in tool order
 * @param {{ root?: string|null }} [o]
 * @returns {{ findings: object[], also: object[], folded: number }}
 */
export function mergePentheraFirst(penthera, tools, { root = null } = {}) {
  const merged = mergeToolFindings(tools);
  const keyed = penthera.map((f) => pentheraKeyed(f, root));
  const findings = penthera.map((f) => ({ ...f }));
  const also = [];
  let folded = 0;
  for (const t of merged) {
    const hit = keyed.findIndex((ks) => ks.some((k) => sameFinding(k, t)));
    if (hit < 0) { also.push(t); continue; }
    const p = findings[hit];
    folded += t.sources.length;
    // A fold keeps the more severe of the two, never Penthera's by default (R10, B05).
    p.severity = maxSeverity(p.severity, t.severity);
    p.foundBy = [...new Set([...(p.foundBy || ["penthera"]), ...t.foundBy])];
    p.alsoReportedBy = [...(p.alsoReportedBy || []), ...t.sources.filter((s) => !(p.alsoReportedBy || []).some((x) => x.tool === s.tool && x.ruleId === s.ruleId))];
  }
  return { findings, also: also.map(publicFinding), folded };
}

/** A tool finding as it goes into a report: the secret hashes stay in memory. */
export function publicFinding(f) {
  if (!f.key?.secretHashes) return f;
  const { secretHashes, ...key } = f.key;
  return { ...f, key };
}
