/**
 * Plugin / templates API — load and run custom YAML security templates.
 *
 * Programmatic usage:
 *   import { loadTemplatesFromPaths, runTemplateScan } from "penthera/plugins";
 *   const templates = await loadTemplatesFromPaths(["./my-templates"]);
 *   const findings = await runTemplateScan("https://app.example", templates);
 */
import { existsSync, statSync } from "node:fs";
import { extname, resolve } from "node:path";
import {
  loadTemplatesFromDir,
  executeTemplates,
} from "./nuclei-loader.js";
import {
  runBuiltInTemplates,
  executeTemplate,
  BUILT_IN_TEMPLATES,
} from "./templates.js";

export { loadTemplatesFromDir, executeTemplates, runBuiltInTemplates, executeTemplate, BUILT_IN_TEMPLATES };

/**
 * Load templates from one or more directories (Nuclei-compatible YAML).
 *
 * @param {string[]} paths
 * @param {object} opts - passed to loadTemplatesFromDir
 */
export async function loadTemplatesFromPaths(paths, opts = {}) {
  const seen = new Set();
  const templates = [];

  for (const raw of paths) {
    const dir = resolve(raw);
    if (!existsSync(dir)) {
      throw new Error(`Template path not found: ${dir}`);
    }
    if (!statSync(dir).isDirectory()) {
      throw new Error(`Template path must be a directory: ${dir}`);
    }

    const loaded = await loadTemplatesFromDir(dir, opts);
    for (const t of loaded) {
      if (seen.has(t.id)) continue;
      seen.add(t.id);
      templates.push(t);
    }
  }

  return templates;
}

/**
 * Execute templates against a target URL.
 *
 * @param {string} baseUrl
 * @param {object[]} templates
 * @param {object} opts
 */
export async function runTemplateScan(baseUrl, templates, opts = {}) {
  return executeTemplates(baseUrl, templates, opts);
}

/**
 * Parse --templates CLI value (comma-separated paths).
 */
export function parseTemplatePaths(value) {
  if (!value) return [];
  return value.split(",").map((p) => p.trim()).filter(Boolean);
}
