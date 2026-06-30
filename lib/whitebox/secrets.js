/**
 * Scan repository source for hardcoded secrets.
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage",
  "reports", ".security-results", "vendor",
]);

const SKIP_FILES = /\.(png|jpg|jpeg|gif|webp|ico|woff|woff2|ttf|eot|zip|tar|gz|pdf|lock)$/i;

const SECRET_PATTERNS = [
  { name: "AWS access key", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "GitHub token", pattern: /ghp_[a-zA-Z0-9]{36,}/, severity: "critical" },
  { name: "OpenAI API key", pattern: /sk-[a-zA-Z0-9]{20,}/, severity: "critical" },
  { name: "Stripe secret key", pattern: /sk_live_[a-zA-Z0-9]{20,}/, severity: "critical" },
  {
    name: "Generic API key assignment",
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    severity: "high",
  },
  {
    name: "Password in source",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{4,}['"]/i,
    severity: "high",
    skipIf: /placeholder|example|changeme|xxx|\*\*\*/i,
  },
  { name: "Private key block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "critical" },
  { name: "GCP/Firebase service account", pattern: /"private_key"\s*:\s*"-----BEGIN/, severity: "critical" },
  {
    name: "JWT secret assignment",
    pattern: /(?:jwt[_-]?secret|session[_-]?secret)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    severity: "high",
  },
];

const SCAN_EXTENSIONS = new Set([
  ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".java",
  ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".sh",
]);

function walkFiles(dir, files = []) {
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walkFiles(full, files);
    } else if (!SKIP_FILES.test(entry)) {
      const ext = entry.includes(".") ? entry.slice(entry.lastIndexOf(".")) : "";
      if (SCAN_EXTENSIONS.has(ext) || entry.startsWith(".env")) files.push(full);
    }
  }
  return files;
}

function maskMatch(match) {
  return match.length <= 8 ? "***" : match.slice(0, 4) + "…" + match.slice(-4);
}

export function scanSecrets(repoPath) {
  const findings = [];
  const seen = new Set();

  for (const filePath of walkFiles(repoPath)) {
    let content;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const rel = relative(repoPath, filePath);

    for (const rule of SECRET_PATTERNS) {
      const match = content.match(rule.pattern);
      if (!match) continue;
      if (rule.skipIf && rule.skipIf.test(match[0])) continue;

      const key = `${rel}::${rule.name}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        severity: rule.severity,
        title: `${rule.name} in source`,
        description: `Possible secret in \`${rel}\`: \`${maskMatch(match[0])}\``,
        url: rel,
        category: "secrets",
        source: "secret-scan",
      });
    }
  }

  return findings;
}
