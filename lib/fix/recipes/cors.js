/**
 * Recipe: replace a wildcard or reflect-any CORS policy with an explicit
 * allowlist read from CORS_ALLOWED_ORIGINS. Guidance: remediation rule "cors",
 * references/remediation.md#cors.
 *
 * Handles cors() with no options (Express `cors`, Hono `hono/cors`, Fastify
 * `@fastify/cors` registered bare), `origin: "*"` / `origin: true` inside those
 * calls, and the `origin || "*"` fallback the route scanner flags.
 */
import { detectFramework, readText, walkCodeFiles, insertAfterImports, envExampleChange, toDiff, isTypeScript } from "../util.js";
import { lineIndex } from "../../linear-text.js";

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
    // Where the name is, and where lines start, found once: a search back for
    // the line and a test of the whole line per site was quadratic on one long line.
    const uses = [...source.matchAll(new RegExp(`\\b${name}\\b`, "g"))].map((u) => u.index);
    const lineOf = lineIndex(source);
    const usesLine = new Set(uses.map(lineOf));
    for (const m of source.matchAll(/\borigin\s*:\s*(?:(['"])\*\1|true\b)/g)) {
      if (!usesLine.has(lineOf(m.index))) continue;
      sites.push({ index: m.index, length: m[0].length, replacement: "origin: allowedOrigins" });
    }
  }
  // The `origin || "*"` fallback (lib/attack-surface.js RISK:cors-wildcard).
  for (const m of source.matchAll(/(?<![\w$.])([\w$.]+(?:\.get\(\s*['"]origin['"]\s*\))?)\s*\|\|\s*(['"])\*\2/g)) {
    const expr = m[1];
    sites.push({ index: m.index, length: m[0].length, replacement: `(allowedOrigins.find((o) => o === ${expr}) ?? "")` });
  }
  return sites.sort((a, b) => a.index - b.index);
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
      // One pass: rebuilding the whole text per site was quadratic in the sites.
      let after = "";
      let at = 0;
      for (const s of sites) { if (s.index < at) continue; after += source.slice(at, s.index) + s.replacement; at = s.index + s.length; }
      after += source.slice(at);
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
  probe(repoPath) {
    const findings = [];
    for (const file of walkCodeFiles(repoPath)) {
      const source = readText(repoPath, file);
      if (!source) continue;
      for (const s of wildcardSites(source)) {
        findings.push({
          severity: "medium",
          title: "CORS allows any origin (cors-wildcard)",
          description: `Set in ${file}:${source.slice(0, s.index).split("\n").length}`,
          url: file,
          category: "cors",
          source: "fix-probe:cors",
        });
      }
    }
    return findings;
  },
};
