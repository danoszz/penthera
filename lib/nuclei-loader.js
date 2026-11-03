/**
 * Nuclei Community Template Loader
 *
 * Parses and executes community-authored Nuclei YAML templates.
 *
 * This is a useful subset of Nuclei, not a reimplementation of it. Supported:
 *   - HTTP requests with method, path, headers, body
 *   - Matchers: status, word, regex, negative-word, negative-regex
 *   - Extractors: regex, json
 *   - Placeholders: {{BaseURL}}, {{Hostname}}, {{RootURL}}
 *
 * Not supported, and reported rather than silently ignored (see
 * collectUnsupported): dsl matchers, kval extractors, dynamic helpers such as
 * {{rand_int}}, payload/attack modes, workflows, and multi-request chaining.
 * Only the first path or raw entry of a request block is executed. A template
 * relying on any of these will not match, so the loader says so instead of
 * letting it look like a clean result.
 *
 * Parses templates with the yaml package vendored in lib/vendor/yaml.
 *
 * Usage:
 *   import { loadTemplatesFromDir, executeTemplates } from "./lib/nuclei-loader.js";
 *   const templates = await loadTemplatesFromDir("/path/to/nuclei-templates/http");
 *   const findings = await executeTemplates("https://target.com", templates);
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, extname } from "node:path";
import { parse } from "./vendor/yaml/index.js";
import { executeTemplate } from "./templates.js";

/**
 * Load Nuclei YAML templates from a directory (recursively).
 *
 * @param {string} dir - Path to templates directory
 * @param {object} opts - { maxDepth, tags, severity, exclude }
 * @returns {object[]} Parsed template objects
 */
export async function loadTemplatesFromDir(dir, opts = {}) {
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
      // Features this loader can't execute. Non-empty means the template will
      // not match even if the target is vulnerable.
      unsupported: collectUnsupported(doc),
      _source: filePath,
    };
  } catch {
    return null; // Skip unparseable templates
  }
}

/**
 * Report the Nuclei features a template needs that this loader does not
 * implement. A template using any of them silently fails to match, which reads
 * like "no vulnerability found", so callers surface this instead.
 *
 * @returns {string[]} human-readable reasons, empty when fully supported
 */
export function collectUnsupported(template) {
  const reasons = new Set();
  const blocks = template?.http || template?.requests || [];

  if (Array.isArray(blocks) && blocks.length > 1) {
    reasons.add("multi-request chaining (only the first request runs)");
  }

  for (const block of Array.isArray(blocks) ? blocks : []) {
    if (Array.isArray(block?.path) && block.path.length > 1) {
      reasons.add("multiple paths (only the first is requested)");
    }
    if (Array.isArray(block?.raw) && block.raw.length > 1) {
      reasons.add("multiple raw requests (only the first is sent)");
    }
    if (block?.payloads || block?.attack) reasons.add("payload/attack modes");
    for (const m of block?.matchers || []) {
      if (m?.type === "dsl") reasons.add("dsl matchers");
      if (m?.part && !["body", "header", "all", "response"].includes(m.part)) {
        reasons.add(`matcher part "${m.part}"`);
      }
    }
    for (const e of block?.extractors || []) {
      if (e?.type === "kval") reasons.add("kval extractors");
    }
  }

  const asText = JSON.stringify(blocks || "");
  if (/\{\{\s*rand_/.test(asText)) reasons.add("dynamic helpers ({{rand_*}})");
  if (template?.workflows) reasons.add("workflows");

  return [...reasons];
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

