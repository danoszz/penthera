/**
 * Nuclei Community Template Loader
 *
 * Parses and executes community-authored Nuclei YAML templates.
 * Supports the most common Nuclei template features:
 *   - HTTP requests with method, path, headers, body
 *   - Matchers: status, word, regex, negative-word, negative-regex, dsl
 *   - Extractors: regex, json, kval
 *   - Variables and dynamic helpers ({{BaseURL}}, {{Hostname}}, {{rand_int}})
 *   - Multi-request templates with matchers-condition
 *
 * Requires the `yaml` npm package (zero-dependency YAML parser).
 *
 * Usage:
 *   import { loadTemplatesFromDir, executeTemplates } from "./lib/nuclei-loader.js";
 *   const templates = await loadTemplatesFromDir("/path/to/nuclei-templates/http");
 *   const findings = await executeTemplates("https://target.com", templates);
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, extname } from "node:path";
import { executeTemplate } from "./templates.js";

let yamlParse = null;

/** Lazy-load YAML parser (fails gracefully if not installed) */
async function getYamlParser() {
  if (yamlParse) return yamlParse;
  try {
    const mod = await import("yaml");
    yamlParse = mod.parse || mod.default?.parse;
    return yamlParse;
  } catch {
    return null;
  }
}

/**
 * Load Nuclei YAML templates from a directory (recursively).
 *
 * @param {string} dir - Path to templates directory
 * @param {object} opts - { maxDepth, tags, severity, exclude }
 * @returns {object[]} Parsed template objects
 */
export async function loadTemplatesFromDir(dir, opts = {}) {
  const parse = await getYamlParser();
  if (!parse) {
    throw new Error(
      'YAML parser not installed. Run: npm install yaml\n' +
      'The "yaml" package is zero-dependency and needed to parse Nuclei community templates.',
    );
  }

  if (!existsSync(dir)) {
    throw new Error(`Template directory not found: ${dir}`);
  }

  const templates = [];
  const maxDepth = opts.maxDepth || 5;
  const tags = opts.tags ? new Set(opts.tags) : null;
  const severity = opts.severity ? new Set(opts.severity) : null;
  const exclude = opts.exclude ? new Set(opts.exclude) : null;

  function walk(currentDir, depth = 0) {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = readdirSync(currentDir);
    } catch {
      return;
    }

    for (const entry of entries) {
      const full = join(currentDir, entry);
      try {
        const stat = statSync(full);
        if (stat.isDirectory()) {
          walk(full, depth + 1);
        } else if (extname(entry) === ".yaml" || extname(entry) === ".yml") {
          const template = parseTemplateFile(full, parse);
          if (template && shouldInclude(template, { tags, severity, exclude })) {
            templates.push(template);
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  }

  walk(dir);
  return templates;
}

/**
 * Parse a single Nuclei YAML template file.
 */
function parseTemplateFile(filePath, parse) {
  try {
    const content = readFileSync(filePath, "utf-8");
    const doc = parse(content);

    if (!doc || !doc.id || !doc.info) return null;

    // Only support HTTP templates for now
    if (!doc.http && !doc.requests) return null;

    // Normalize: some templates use "requests" instead of "http"
    const http = doc.http || doc.requests || [];

    return {
      id: doc.id,
      info: {
        name: doc.info.name || doc.id,
        severity: doc.info.severity || "info",
        tags: typeof doc.info.tags === "string"
          ? doc.info.tags.split(",").map((t) => t.trim())
          : (doc.info.tags || []),
        description: doc.info.description || "",
        reference: doc.info.reference || [],
        classification: doc.info.classification || {},
      },
      variables: doc.variables || {},
      http: http.map(normalizeHttpBlock),
      _source: filePath,
    };
  } catch {
    return null; // Skip unparseable templates
  }
}

/**
 * Normalize an HTTP request block to our internal format.
 */
function normalizeHttpBlock(block) {
  const normalized = {
    method: block.method || "GET",
    path: Array.isArray(block.path) ? block.path[0] : (block.path || "/"),
    headers: block.headers || {},
    body: block.body || null,
    matchers: (block.matchers || []).map(normalizeMatcher),
    "matchers-condition": block["matchers-condition"] || "or",
    extractors: block.extractors || [],
  };

  // Handle raw requests
  if (block.raw && Array.isArray(block.raw)) {
    const rawReq = block.raw[0];
    const methodMatch = rawReq.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/);
    if (methodMatch) {
      normalized.method = methodMatch[1];
      normalized.path = methodMatch[2];
    }
  }

  return normalized;
}

/**
 * Normalize a matcher to our internal format.
 */
function normalizeMatcher(matcher) {
  const norm = { ...matcher };

  // Nuclei uses "status" as an array, we do too
  if (norm.type === "status" && typeof norm.status === "number") {
    norm.status = [norm.status];
  }

  // Handle "negative" flag on word/regex matchers
  if (norm.negative && norm.type === "word") {
    norm.type = "negative-word";
    delete norm.negative;
  }
  if (norm.negative && norm.type === "regex") {
    norm.type = "negative-regex";
    delete norm.negative;
  }

  return norm;
}

/**
 * Check if a template should be included based on filters.
 */
function shouldInclude(template, filters) {
  const { tags, severity, exclude } = filters;

  if (exclude && exclude.has(template.id)) return false;

  if (severity) {
    const sev = template.info.severity?.toLowerCase();
    if (!severity.has(sev)) return false;
  }

  if (tags) {
    const templateTags = template.info.tags || [];
    if (!templateTags.some((t) => tags.has(t))) return false;
  }

  return true;
}

/**
 * Execute loaded community templates against a target.
 * Uses the same execution engine as built-in templates.
 *
 * @param {string} baseUrl
 * @param {object[]} templates - Parsed template objects
 * @param {object} opts - { onPhase, concurrency }
 * @returns {object[]} Findings
 */
export async function executeTemplates(baseUrl, templates, opts = {}) {
  const progress = opts.onPhase || (() => {});
  const findings = [];

  for (let i = 0; i < templates.length; i++) {
    const template = templates[i];

    if (i % 50 === 0) {
      progress(`Running community templates... ${i}/${templates.length}`);
    }

    try {
      // Resolve {{BaseURL}} and {{Hostname}} in paths
      const hostname = new URL(baseUrl).hostname;
      const resolved = {
        ...template,
        http: template.http.map((block) => ({
          ...block,
          path: block.path
            .replace(/\{\{BaseURL\}\}/g, "")
            .replace(/\{\{Hostname\}\}/g, hostname)
            .replace(/\{\{RootURL\}\}/g, ""),
        })),
      };

      const templateFindings = await executeTemplate(baseUrl, resolved);
      for (const f of templateFindings) {
        findings.push({
          severity: f.severity,
          title: f.name,
          description: f.description || "",
          url: f.matchedUrl,
          status: f.status,
          category: f.tags?.[0] || "community-template",
          source: "nuclei-community",
          templateId: f.templateId,
          classification: template.info.classification,
        });
      }
    } catch {
      // Skip templates that error during execution
    }
  }

  return findings;
}

/**
 * Get stats about a template directory.
 */
export async function getTemplateStats(dir) {
  const templates = await loadTemplatesFromDir(dir);
  const bySeverity = {};
  const byTag = {};

  for (const t of templates) {
    const sev = t.info.severity || "unknown";
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    for (const tag of t.info.tags) {
      byTag[tag] = (byTag[tag] || 0) + 1;
    }
  }

  return {
    total: templates.length,
    bySeverity,
    topTags: Object.entries(byTag)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 20)
      .map(([tag, count]) => ({ tag, count })),
  };
}
