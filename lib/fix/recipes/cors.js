/**
 * Recipe: replace a wildcard or reflect-any CORS policy with an explicit
 * allowlist read from CORS_ALLOWED_ORIGINS. Guidance: remediation rule "cors",
 * references/remediation.md#cors.
 *
 * Handles cors() with no options (Express `cors`, Hono `hono/cors`, Fastify
 * `@fastify/cors` registered bare), `origin: "*"` / `origin: true` inside those
 * calls, and the `origin || "*"` fallback the route scanner flags.
 */
import { detectFramework, readText, walkCodeFiles, insertAfterImports, envExampleChange, toDiff, isTypeScript, lineIndex } from "../util.js";
import { keepWorst } from "../probe-cap.js";

const ENV = "CORS_ALLOWED_ORIGINS";

function corsModule(source) {
  return /['"](?:cors|hono\/cors|@fastify\/cors)['"]/.test(source);
}

/** [{ index, length, replacement, line }] for each wildcard CORS site in `source`. */
function wildcardSites(source) {
  const sites = [];
  if (corsModule(source)) {
    const name = source.match(/import\s+(?:\{\s*)?(\w+)(?:\s*\})?\s+from\s+['"](?:cors|hono\/cors|@fastify\/cors)['"]/)?.[1]
      || source.match(/(?:const|let|var)\s+(?:\{\s*)?(\w+)(?:\s*\})?\s*=\s*require\(\s*['"](?:cors|@fastify\/cors)['"]\s*\)/)?.[1]
      || "cors";
    // cors() with no options defaults to Access-Control-Allow-Origin: *.
    for (const m of source.matchAll(new RegExp(`\\b${name}\\(\\s*\\)`, "g"))) {
      sites.push({ index: m.index, length: m[0].length, replacement: `${name}({ origin: allowedOrigins })` });
    }
    // Fastify: app.register(cors) with no options.
    for (const m of source.matchAll(new RegExp(`\\.register\\(\\s*${name}\\s*\\)`, "g"))) {
      sites.push({ index: m.index, length: m[0].length, replacement: `.register(${name}, { origin: allowedOrigins })` });
    }
    // origin: "*" or origin: true (reflects any origin) on a line that configures CORS.
    // Each line is tested once, however many hits it holds: a long line can't make this quadratic.
    const named = new RegExp(`\\b${name}\\b`);
    // Matches come in order, so the current line's end only moves forward
    // (lastIndexOf back to the line start would rescan a long line on every hit).
    let lineStart;
    let lineEnd = -1;
    let hasName = false;
    for (const m of source.matchAll(/\borigin\s*:\s*(?:(['"])\*\1|true\b)/g)) {
      if (lineEnd !== -2 && (lineEnd === -1 || m.index > lineEnd)) {
        lineStart = source.lastIndexOf("\n", m.index) + 1; // scans back no further than the last line's end
        const end = source.indexOf("\n", m.index);
        lineEnd = end < 0 ? -2 : end;
        hasName = named.test(source.slice(lineStart, end < 0 ? undefined : end));
      }
      if (!hasName) continue;
      sites.push({ index: m.index, length: m[0].length, replacement: "origin: allowedOrigins" });
    }
  }
  // The `origin || "*"` fallback (lib/attack-surface.js RISK:cors-wildcard).
  for (const site of fallbackSites(source)) {
    sites.push({ index: site.index, length: site.length, replacement: `(allowedOrigins.find((o) => o === ${site.expr}) ?? "")` });
  }
  return sites.sort((a, b) => a.index - b.index);
}

const EXPR_CHAR = /[\w$.]/;
const GET_ORIGIN = /\.get\(\s{0,16}['"]origin['"]\s{0,16}\)$/;

/**
 * Every `expr || "*"`, where expr is a run of word characters, `$` and dots,
 * optionally followed by `.get("origin")`. Same sites as the regex
 * /([\w$.]+(?:\.get\(\s*['"]origin['"]\s*\))?)\s*\|\|\s*(['"])\*\2/g, found in
 * linear time: that regex retries every start in a long run of word characters,
 * so 80 KB of letters took seven seconds. Each `|| "*"` is found first, then the
 * expression is read backwards from it; those backward stretches never overlap.
 *
 * @returns {{ index: number, length: number, expr: string }[]}
 */
export function fallbackSites(source) {
  const out = [];
  for (const m of source.matchAll(/\|\|\s*(['"])\*\1/g)) {
    let end = m.index;
    while (end > 0 && /\s/.test(source[end - 1])) end--;
    let runEnd = end;
    const get = GET_ORIGIN.exec(source.slice(Math.max(0, end - 64), end));
    if (get) runEnd = end - get[0].length;
    let start = runEnd;
    while (start > 0 && EXPR_CHAR.test(source[start - 1])) start--;
    if (start === runEnd) continue; // nothing before `||` that the regex would take
    out.push({ index: start, length: m.index + m[0].length - start, expr: source.slice(start, end) });
  }
  return out;
}

function helperLines(file) {
  const ts = isTypeScript(file) ? ": string[]" : "";
  return [
    `// Allowed CORS origins, comma-separated in ${ENV} (added by penthera fix).`,
    `const allowedOrigins${ts} = (process.env.${ENV} || "")`,
    '  .split(",")',
    "  .map((o) => o.trim())",
    "  .filter(Boolean);",
  ];
}

function candidateFiles(repoPath, finding) {
  const files = walkCodeFiles(repoPath);
  const named = finding.url && files.includes(finding.url) ? [finding.url] : files;
  return named.map((file) => ({ file, source: readText(repoPath, file) })).filter((f) => f.source);
}

export default {
  id: "cors-allowlist",
  title: "Restrict CORS to an allowlist from the environment",
  matches(finding) {
    return finding.category === "cors" || finding.category === "cors-misconfiguration" || /cors-wildcard/i.test(finding.title || "");
  },
  detect(repoPath) {
    return detectFramework(repoPath) || "node";
  },
  plan(repoPath, finding) {
    const changes = [];
    for (const { file, source } of candidateFiles(repoPath, finding)) {
      const sites = wildcardSites(source);
      if (sites.length === 0) continue;
      let after = source;
      for (const s of [...sites].reverse()) after = after.slice(0, s.index) + s.replacement + after.slice(s.index + s.length);
      if (!/\ballowedOrigins\s*=/.test(source)) after = insertAfterImports(after, helperLines(file));
      changes.push({ file, before: source, after });
    }
    if (changes.length === 0) return null;
    changes.push(envExampleChange(repoPath, ENV, "https://app.example.com", "Comma-separated origins allowed to call this API cross-origin"));
    const change = toDiff(changes);
    if (!change) return null;
    return {
      ...change,
      ownerActions: [
        `Set ${ENV} in every environment to the exact origins that call this API (for example https://app.example.com). With it unset, all cross-origin requests are refused.`,
      ],
      confidence: "high",
    };
  },
  probeSource: probeCors,
  probe(repoPath) {
    const findings = [];
    for (const file of walkCodeFiles(repoPath)) {
      const source = readText(repoPath, file);
      if (source) findings.push(...probeCors(file, source));
    }
    return findings;
  },
};

/** Wildcard CORS in one file. At most PROBE_CAP per file. */
export function probeCors(file, source) {
  if (!/\*|origin|cors/i.test(source)) return [];
  const lineOf = lineIndex(source);
  return keepWorst(wildcardSites(source).map((s) => ({
    severity: "medium",
    title: "CORS allows any origin (cors-wildcard)",
    description: `Set in ${file}:${lineOf(s.index)}`,
    url: file,
    file,
    line: lineOf(s.index),
    category: "cors",
    source: "fix-probe:cors",
  })), file);
}
