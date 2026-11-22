/**
 * Shared tables for the sink scan (code-sinks.js) and the route records
 * (frameworks.js), so a source or sink added in one place reaches both
 * (Mythos A4, A6, 12 Nov 2026; checklist row 26, twin lists).
 *
 * Other readers of request data keep their own, narrower questions and are
 * named here so a change is made in each: missing-checks.js REQUEST_READ (does
 * a webhook read the body?) and attack-surface.js detectInputs (which fields).
 */

/**
 * Request data, as a regex source: Express and Koa fields, the Web Request API
 * (`await request.json()`, `request.formData()`, `request.url`, `nextUrl`), and
 * the readers of a URL or a form (`searchParams.get(`, `formData.get(`).
 * Additions only: every form main knew still matches.
 */
export const REQUEST_SOURCE = [
  String.raw`\b(?:req|request|ctx\.request)\.(?:body|query|params|headers|cookies|files?)\b`,
  String.raw`\b(?:req|request)\s*\.\s*(?:json|formData|text|arrayBuffer|blob)\s*\(`,
  String.raw`\b(?:req|request)\s*\.\s*(?:url|nextUrl)\b`,
  String.raw`\bnextUrl\s*\.\s*searchParams\b`,
  String.raw`\b(?:searchParams|formData)\s*\.\s*(?:get|getAll)\s*\(`,
].join("|");

/** Module names whose functions run a string as code. */
export const VM_MODULE = String.raw`(?:node:)?vm`;
export const VM_METHODS = "runInContext|runInNewContext|runInThisContext|compileFunction";

/**
 * Any call that runs a string as code, for a route file's record: `eval(`,
 * `eval?.(`, `eval.call(`, `new Function(`, `Function(`, and the vm module's
 * runners. A name boundary keeps `retrieval(` out (Mythos B1).
 */
export const EVAL_ANY = String.raw`(?<![\w$])eval(?=\s*[(/?.)])|(?<![\w$.])(?:new\s+)?Function\s*\(|\bvm\s*\.\s*(?:${VM_METHODS})\s*\(|\bnew\s+vm\s*\.\s*Script\s*\(`;
