/**
 * A tiny report template language for `--report-template file.md`.
 *
 *   {{summary.critical}}               a value, HTML- and Markdown-escaped
 *   {{#each findings}}…{{/each}}       loop over an array; inside, `this` is the
 *                                      item, `@index` is 0-based, and names fall
 *                                      back to the enclosing scopes
 *   {{#if x}}…{{else}}…{{/if}}         truthy test (an empty array is false)
 *
 * That is the whole language. There are no helpers, no expressions, no raw
 * output, no partials or file includes, and no way to reach a prototype: paths
 * are dotted identifiers, `__proto__`, `constructor` and `prototype` are
 * rejected when the template is parsed, and lookups only read own properties.
 * Values are never parsed as template text, so a finding title that contains
 * `{{…}}` prints as text.
 */

export class TemplateError extends Error {
  constructor(message, line) {
    super(line ? `${message} (line ${line})` : message);
    this.name = "TemplateError";
    this.line = line || null;
  }
}

const MAX_TEMPLATE = 256 * 1024;
const MAX_DEPTH = 32;
const MAX_OUTPUT = 8 * 1024 * 1024;
const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);
const SEGMENT = /^(?:[A-Za-z_][A-Za-z0-9_-]*|\d+)$/;

function parsePath(raw, line) {
  if (raw === "this" || raw === "@index") return [raw];
  const parts = raw.split(".");
  const start = parts[0] === "this" ? 1 : 0;
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (FORBIDDEN.has(p)) throw new TemplateError(`"${p}" is not allowed in a template path`, line);
    if (i >= start && !SEGMENT.test(p)) throw new TemplateError(`Bad template path "${raw}"`, line);
  }
  return parts;
}

/** Parse a template into a tree. Throws TemplateError on any syntax it does not know. */
export function parseTemplate(src) {
  if (typeof src !== "string") throw new TemplateError("Template must be a string");
  if (src.length > MAX_TEMPLATE) throw new TemplateError(`Template is larger than ${MAX_TEMPLATE} bytes`);
  const root = { type: "root", body: [] };
  const stack = [root];
  let target = root.body;
  let line = 1;
  let last = 0;
  // The template is the user's own --report-template file, never scanned input.
  // eslint-disable-next-line regexp/no-super-linear-move
  const re = /\{\{([\s\S]*?)\}\}/g;
  let m;
  while ((m = re.exec(src))) {
    if (m.index > last) target.push({ type: "text", value: src.slice(last, m.index) });
    line += countLines(src.slice(last, m.index));
    last = re.lastIndex;
    const tag = m[1].trim();
    const top = stack[stack.length - 1];
    let mm;
    if ((mm = /^#(each|if)\s+(\S+)$/.exec(tag))) {
      if (stack.length > MAX_DEPTH) throw new TemplateError("Blocks are nested too deeply", line);
      const node = { type: mm[1], path: parsePath(mm[2], line), body: [], alt: null, line };
      target.push(node);
      stack.push(node);
      target = node.body;
    } else if (tag === "else") {
      if (top.type !== "if" || top.alt) throw new TemplateError("{{else}} outside {{#if}}", line);
      top.alt = [];
      target = top.alt;
    } else if ((mm = /^\/(each|if)$/.exec(tag))) {
      if (top.type !== mm[1]) throw new TemplateError(`Unexpected {{/${mm[1]}}}`, line);
      stack.pop();
      const parent = stack[stack.length - 1];
      target = parent.alt ?? parent.body;
    } else if (/^[A-Za-z_@][\w.@-]*$/.test(tag)) {
      target.push({ type: "var", path: parsePath(tag, line), line });
    } else {
      throw new TemplateError(`Unsupported tag {{${tag.slice(0, 40)}}}`, line);
    }
    line += countLines(m[0]);
  }
  if (stack.length > 1) {
    const open = stack[stack.length - 1];
    throw new TemplateError(`Unclosed {{#${open.type}}}`, open.line);
  }
  if (last < src.length) target.push({ type: "text", value: src.slice(last) });
  return root;
}

function countLines(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) n++;
  return n;
}

function own(obj, key) {
  if (obj === null || typeof obj !== "object") return undefined;
  if (Array.isArray(obj) && !/^\d+$/.test(key)) return key === "length" ? obj.length : undefined;
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

function lookup(scopes, path) {
  if (path[0] === "@index") return scopes[scopes.length - 1].index;
  if (path[0] === "this") {
    let v = scopes[scopes.length - 1].value;
    for (let i = 1; i < path.length && v !== undefined; i++) v = own(v, path[i]);
    return v;
  }
  for (let s = scopes.length - 1; s >= 0; s--) {
    const first = own(scopes[s].value, path[0]);
    if (first === undefined) continue;
    let v = first;
    for (let i = 1; i < path.length && v !== undefined; i++) v = own(v, path[i]);
    return v;
  }
  return undefined;
}

const HTML = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/**
 * Escape a value for Markdown that may also be rendered as HTML: HTML entities
 * for & < > " ', a backslash before Markdown punctuation, newlines folded to a
 * space (so a value cannot start a heading, list or table row), and control
 * characters dropped. Non-primitive values render as nothing.
 */
export function escapeValue(v) {
  if (v === null || v === undefined) return "";
  if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") return "";
  return String(v)
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f\u2028\u2029]/g, "")
    .replace(/\r?\n|\r/g, " ")
    .replace(/[\\`*_[\]{}()#|!~]/g, "\\$&")
    .replace(/[&<>"']/g, (c) => HTML[c])
    .replace(/^([-+.=])/, "\\$1")
    .replace(/^(\d+)\./, "$1\\.");
}

function truthy(v) {
  if (Array.isArray(v)) return v.length > 0;
  return Boolean(v);
}

function emit(out, s) {
  out.size += s.length;
  if (out.size > MAX_OUTPUT) throw new TemplateError(`Rendered report is larger than ${MAX_OUTPUT} bytes`);
  out.parts.push(s);
}

function renderNodes(nodes, scopes, out) {
  for (const n of nodes) {
    if (n.type === "text") emit(out, n.value);
    else if (n.type === "var") emit(out, escapeValue(lookup(scopes, n.path)));
    else if (n.type === "if") renderNodes(truthy(lookup(scopes, n.path)) ? n.body : (n.alt || []), scopes, out);
    else if (n.type === "each") {
      const list = lookup(scopes, n.path);
      if (!Array.isArray(list)) continue;
      for (let i = 0; i < list.length; i++) {
        scopes.push({ value: list[i], index: i });
        renderNodes(n.body, scopes, out);
        scopes.pop();
      }
    }
  }
}

/** Render a template string (or a tree from parseTemplate) against a data object. */
export function renderTemplate(template, data) {
  const tree = typeof template === "string" ? parseTemplate(template) : template;
  const out = { parts: [], size: 0 };
  renderNodes(tree.body, [{ value: data, index: 0 }], out);
  return out.parts.join("");
}
