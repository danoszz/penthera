/**
 * Scan repository source for hardcoded secrets.
 */
import { readdirSync, readFileSync, lstatSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage",
  "reports", ".security-results", "vendor",
]);

const SKIP_FILES = /\.(png|jpg|jpeg|gif|webp|ico|woff|woff2|ttf|eot|zip|tar|gz|pdf|lock)$/i;

// Values that clearly aren't real secrets: placeholders, redactions, and the
// dummy/probe credentials that security tooling (Penthera included) hardcodes
// to test login endpoints, e.g. `password: "invalid-password-12345"`. Matched
// against the assigned value only, with word boundaries so a real secret that
// merely contains one of these substrings isn't suppressed. A value that is
// only a template placeholder (`"${apiKey}"`, `"{{ api_key }}"`) holds no
// secret either: it is filled in at runtime.
const TEST_VALUE = /\b(?:placeholder|example|changeme|dummy|sample|redacted|invalid|fake|test|your)\b|xxx|\*{3,}|^\$\{[^}]+\}$|^\{\{[^}]+\}\}$/i;

const SECRET_PATTERNS = [
  { name: "AWS access key", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "GitHub token", pattern: /ghp_[a-zA-Z0-9]{36,}/, severity: "critical" },
  // AI provider keys. Vibecoded apps leak these more than any other credential,
  // often via a NEXT_PUBLIC_/VITE_ variable or a committed notebook. Specific
  // prefixes come first so a key is reported under its real provider.
  { name: "Anthropic API key", pattern: /sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,}/, severity: "critical" },
  { name: "OpenRouter API key", pattern: /sk-or-v1-[a-f0-9]{64}/, severity: "critical" },
  { name: "OpenAI API key", pattern: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/, severity: "critical" },
  { name: "OpenAI API key (legacy format)", pattern: /sk-[a-zA-Z0-9]{20,}/, severity: "critical" },
  // AIza keys are also Firebase web keys, which are public by design, so this
  // is high rather than critical: it matters if the key has Gemini/Vertex access.
  { name: "Google API key (Gemini / Firebase / Maps)", pattern: /AIza[0-9A-Za-z_-]{35}/, severity: "high" },
  { name: "Groq API key", pattern: /gsk_[A-Za-z0-9]{48,}/, severity: "critical" },
  { name: "Hugging Face token", pattern: /hf_[A-Za-z0-9]{34,}/, severity: "critical" },
  { name: "Replicate API token", pattern: /r8_[A-Za-z0-9]{37,}/, severity: "critical" },
  { name: "xAI API key", pattern: /xai-[A-Za-z0-9]{70,}/, severity: "critical" },
  { name: "Perplexity API key", pattern: /pplx-[A-Za-z0-9]{40,}/, severity: "critical" },
  { name: "LangSmith API key", pattern: /lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}/, severity: "high" },
  { name: "Pinecone API key", pattern: /pcsk_[A-Za-z0-9_]{50,}/, severity: "high" },
  { name: "Stripe secret key", pattern: /sk_live_[a-zA-Z0-9]{20,}/, severity: "critical" },
  {
    name: "Generic API key assignment",
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    severity: "high",
    skipIf: TEST_VALUE,
  },
  {
    name: "Hardcoded password",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{4,}['"]/i,
    severity: "high",
    skipIf: TEST_VALUE,
  },
  { name: "GCP/Firebase service account", pattern: /"private_key"\s*:\s*"-----BEGIN/, severity: "critical" },
  { name: "Private key block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "critical" },
  {
    name: "JWT secret assignment",
    pattern: /(?:jwt[_-]?secret|session[_-]?secret)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    severity: "high",
    skipIf: TEST_VALUE,
  },
];

const SCAN_EXTENSIONS = new Set([
  ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".java",
  ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".sh",
  ".ipynb", // notebooks are a classic place for a pasted provider key
]);

/** Would the repo scan read this file? `relPath` uses forward slashes (git paths). */
export function isSecretScanTarget(relPath) {
  const parts = relPath.split("/");
  if (parts.slice(0, -1).some((d) => SKIP_DIRS.has(d))) return false;
  const entry = parts[parts.length - 1];
  if (SKIP_FILES.test(entry)) return false;
  const ext = entry.includes(".") ? entry.slice(entry.lastIndexOf(".")) : "";
  return SCAN_EXTENSIONS.has(ext) || entry.startsWith(".env");
}

// A subfolder with its own `.git` (a nested repo, submodule or worktree, such
// as the ones coding agents create under .claude/worktrees) is a separate
// project: scanning it would report its secrets as this repo's. Scan it on its
// own instead. Symlinked folders are not followed, so a link cannot pull files
// from outside the repo into the scan or loop forever.
export function isNestedRepo(dir, root) {
  return dir !== root && existsSync(join(dir, ".git"));
}

function walkFiles(dir, files = [], root = dir) {
  if (!existsSync(dir) || isNestedRepo(dir, root)) return files;
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      walkFiles(full, files, root);
    } else if (!SKIP_FILES.test(entry)) {
      const ext = entry.includes(".") ? entry.slice(entry.lastIndexOf(".")) : "";
      if (SCAN_EXTENSIONS.has(ext) || entry.startsWith(".env")) files.push(full);
    }
  }
  return files;
}

export function maskMatch(match) {
  return match.length <= 8 ? "***" : match.slice(0, 4) + "…" + match.slice(-4);
}

/**
 * Find secrets in a string of text (a source file, a JS bundle, a config).
 * Returns one hit per rule: `{ name, severity, match }`, with the raw match so
 * callers decide how to mask it. At most one rule fires per provider key: once a
 * specific AI-provider rule matches a span, broader rules skip that span.
 */
export function findSecretsInText(content) {
  const hits = [];
  const claimed = [];
  for (const rule of SECRET_PATTERNS) {
    const match = content.match(rule.pattern);
    if (!match) continue;
    // For assignment-style rules, test the placeholder/dummy filter against
    // the assigned value only (not the whole `key = "value"` match), so a
    // variable named e.g. `testToken` can't mask a real secret.
    const value = (match[0].match(/['"]([^'"]+)['"]/) || [, match[0]])[1];
    if (rule.skipIf && rule.skipIf.test(value)) continue;
    const start = match.index;
    const end = start + match[0].length;
    if (claimed.some(([a, b]) => start < b && end > a)) continue;
    claimed.push([start, end]);
    hits.push({ name: rule.name, severity: rule.severity, match: match[0] });
  }
  return hits;
}

export function scanSecrets(repoPath) {
  const findings = [];

  for (const filePath of walkFiles(repoPath)) {
    let content;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const rel = relative(repoPath, filePath);

    for (const hit of findSecretsInText(content)) {
      findings.push({
        severity: hit.severity,
        title: `${hit.name} in source`,
        description: `Possible secret in \`${rel}\`: \`${maskMatch(hit.match)}\``,
        url: rel,
        category: "secrets",
        source: "secret-scan",
      });
    }
  }

  return findings;
}
