/**
 * The finding shape for other tools' findings (spec-giants.md, "Findings from
 * other tools"), and the helpers every adapter shares: paths relative to the
 * scanned root, severity tables, secret masking and hashing.
 *
 * `source` stays a string on every finding, as on Penthera's own: the tool's
 * name. Baselines, memory and the audit loop key on it. The detail the spec
 * asks for (tool, version, rule id, rule URL) is in `sources`, a list, because
 * a merged finding keeps every tool that reported it.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { basename, isAbsolute, relative, sep } from "node:path";
import { maskRaw } from "../whitebox/secrets.js";
import { readRepoFile } from "../fs-safe.js";
import { findingId } from "../memory/views.js";

export const CATEGORIES = ["secret", "code", "dependency-vuln", "infra-misconfig", "container-vuln", "web"];
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** The more severe of two severities. */
export function maxSeverity(a, b) {
  return (SEVERITY_RANK[a] ?? 5) <= (SEVERITY_RANK[b] ?? 5) ? a : b;
}

/**
 * A CVSS-style score (0–10, as SARIF `security-severity` carries it) as a
 * severity: 9.0 and up critical, 7.0 high, 4.0 medium, above 0 low.
 */
export function severityFromScore(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return null;
  if (n >= 9) return "critical";
  if (n >= 7) return "high";
  if (n >= 4) return "medium";
  if (n > 0) return "low";
  return "info";
}

/** A tool's own severity word (CRITICAL, High, moderate, …) as Penthera's. */
export function severityFromWord(word) {
  const w = String(word || "").toLowerCase();
  if (w === "critical") return "critical";
  if (w === "high" || w === "error") return "high";
  if (w === "medium" || w === "moderate" || w === "warning") return "medium";
  if (w === "low" || w === "note") return "low";
  if (w === "info" || w === "informational" || w === "unknown" || w === "none") return "info";
  return null;
}

/**
 * A path a tool printed, relative to the scanned root with forward slashes.
 * Tools print absolute paths, paths relative to the root, or (checkov) paths
 * that start with the root folder's own name; each is tried in that order.
 */
export function relPath(root, p) {
  if (p == null || p === "") return null;
  let s = String(p).replace(/^file:\/\//, "");
  try { s = decodeURIComponent(s); } catch { /* keep as is */ }
  if (root && isAbsolute(s)) {
    const rel = relative(root, s);
    if (!rel.startsWith("..")) return rel.split(sep).join("/");
    // macOS: /tmp is /private/tmp, and tools print either.
    const alt = s.startsWith("/private/") ? s.slice("/private".length) : "/private" + s;
    const rel2 = relative(root, alt);
    if (!rel2.startsWith("..")) return rel2.split(sep).join("/");
    // Checkov's file_path: relative to the scanned folder, with a leading slash.
    if (existsSync(`${root}${s}`)) return s.replace(/^\/+/, "").split(sep).join("/");
    return s.split(sep).join("/");
  }
  s = s.split(sep).join("/").replace(/^(\.\/)+/, "").replace(/^\/+/, "");
  if (root && !existsSync(`${root}/${s}`)) {
    const head = basename(root) + "/";
    if (s.startsWith(head) && existsSync(`${root}/${s.slice(head.length)}`)) return s.slice(head.length);
  }
  return s;
}

/** "file:line" (or the file alone) for a title, so two hits of one rule in one file get different ids. */
export function where(file, line) {
  return `${file || "?"}${line ? `:${line}` : ""}`;
}

/** Positive integer or null. */
export function lineOf(n) {
  const v = Number(n);
  return Number.isInteger(v) && v > 0 ? v : null;
}

/** SHA-256 of a secret value, for the merge key only; never written to a report. */
export function secretHash(value) {
  return value ? createHash("sha256").update(String(value)).digest("hex") : null;
}

/**
 * The secret value inside a matched span (`token = "abc…"` → `abc…`): the
 * last quoted string, else what follows the last `=` or `:`, else the span.
 * Penthera's rules and the tools match spans of different widths; the value
 * is what they share.
 */
export function secretValue(span) {
  const s = String(span || "").trim();
  const quoted = [...s.matchAll(/["'`]([^"'`]{4,})["'`]/g)];
  if (quoted.length) return quoted[quoted.length - 1][1];
  const m = /[=:]\s*([^=:\s,;]+)[\s,;]*$/.exec(s);
  return m ? m[1] : s;
}

/** Text of line `line` (1-based) of a file under root, or null. Reads files only under root. */
export function readLine(root, file, line) {
  if (!root || !file || !line || isAbsolute(file) || file.split("/").includes("..")) return null;
  try {
    return readRepoFile(`${root}/${file}`, { root, maxBytes: 16 * 1024 * 1024 }).split("\n")[line - 1] ?? null;
  } catch {
    return null;
  }
}

/**
 * The forms a secret takes in JSON output: as written, JSON-escaped (\" and
 * \\), and as Go's encoding/json writes it (also <, > and & as \u003c,
 * \u003e and \u0026), each with the mask it gets in that form.
 */
function secretForms(s) {
  const json = JSON.stringify(s).slice(1, -1);
  const go = json.replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
  const maskJson = JSON.stringify(maskRaw(s)).slice(1, -1);
  return [[s, maskRaw(s)], [json, maskJson], [go, maskJson], [go.replace(/\//g, "\\/"), maskJson]];
}

/** Mask every occurrence of each secret in a text (raw output kept for the evidence bundle), JSON-escaped forms included. */
export function maskSecretsIn(text, secrets) {
  let out = String(text);
  const forms = [...new Set(secrets.filter((x) => typeof x === "string" && x.length >= 4))].flatMap(secretForms);
  for (const [form, masked] of forms.sort((a, b) => b[0].length - a[0].length)) {
    if (form !== masked) out = out.split(form).join(masked);
  }
  return out;
}

/** Strip control characters from text a tool printed: it is data, shown as text. */
export function clean(s, max = 500) {
  if (s == null) return "";
  const t = String(s).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
}

/**
 * One finding from another tool, in Penthera's shape.
 * @param {object} p
 * @param {{ id: string, version: string|null }} p.tool
 * @param {string} p.ruleId
 * @param {string|null} [p.ruleUrl]
 * @param {string} p.category - one of CATEGORIES
 * @param {string} p.severity - one of SEVERITIES
 * @param {string} p.title
 * @param {string} [p.description]
 * @param {string|null} [p.file] - relative to the scanned root
 * @param {number|null} [p.line]
 * @param {string|null} [p.url] - for live findings
 * @param {object} [p.key] - merge-key fields: cwe[], ecosystem, pkg, version, advisories[], resource, checkIds[], parameter, secretHash
 * @param {string} [p.remediation]
 */
export function makeFinding(p) {
  const sev = SEVERITIES.includes(p.severity) ? p.severity : "medium";
  const f = {
    severity: sev,
    title: clean(p.title, 200),
    description: clean(p.description || p.title, 2000),
    url: p.file || p.url || null,
    ...(p.file ? { file: p.file } : {}),
    ...(p.line ? { line: p.line } : {}),
    category: p.category,
    source: p.tool.id,
    method: `giants:${p.tool.id}`,
    confidence: "likely",
    sources: [{ tool: p.tool.id, version: p.tool.version || null, ruleId: clean(p.ruleId, 200), ruleUrl: p.ruleUrl ? clean(p.ruleUrl, 500) : null }],
    foundBy: [p.tool.id],
    ...(p.remediation ? { remediation: clean(p.remediation, 1000) } : {}),
    key: p.key || {},
  };
  f.fid = findingId(f);
  return f;
}
