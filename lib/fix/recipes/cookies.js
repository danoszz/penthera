/**
 * Recipe: Secure, HttpOnly and SameSite on cookies set in code (Express
 * res.cookie, Fastify reply.setCookie, Hono setCookie, Next.js cookies().set).
 * Guidance: remediation rule "cookie", references/remediation.md#insecure-cookies.
 *
 * Only single-line calls with a literal cookie name and either no options or an
 * inline options object are edited. Explicit `httpOnly: false` and the like are
 * left alone: someone chose them, and a human should revisit that choice.
 */
import { detectFramework, readText, walkCodeFiles, splitCallArgs, toDiff } from "../util.js";
import { lineIndex } from "../../linear-text.js";

const CALLS = [
  { re: /\b\w+\.cookie\s*\(/g, name: 0, options: 2 }, // Express
  { re: /\b\w+\.setCookie\s*\(/g, name: 0, options: 2 }, // Fastify (@fastify/cookie)
  { re: /(?<![\w.$])setCookie\s*\(/g, name: 1, options: 3, sameSite: "Lax" }, // Hono (hono/cookie)
  { re: /\b(?:cookies\(\)\)?|cookies|cookieStore)\.set\s*\(/g, name: 0, options: 2 }, // Next.js
];

const FLAGS = [
  { key: "httpOnly", label: "HttpOnly" },
  { key: "secure", label: "Secure" },
  { key: "sameSite", label: "SameSite" },
];

const literal = (s) => s.match(/^(['"`])([^'"`$]+)\1$/)?.[2] ?? null;

/** Every cookie-setting call in `source`, with which flags are missing. */
function cookieCalls(source) {
  const calls = [];
  // Next.js: `const store = await cookies(); store.set(...)`.
  // Any `name.set(`, then a lookup: the store names spelled out as an
  // alternation tried every name at every position (Vercel Security Review, 2.3.2).
  const stores = new Set([...source.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?cookies\(\)/g)].map((m) => m[1]));
  const specs = stores.size ? [...CALLS, { re: /\b(\w+)\.set\s*\(/g, stores, name: 0, options: 2 }] : CALLS;
  // Reading the calls' arguments may take at most this many characters of
  // the file; past it the rest is not checked and `calls.incomplete` says so.
  const budget = { left: CALL_READ_FACTOR * source.length + 1024 * 1024 };
  for (const spec of specs) {
    spec.re.lastIndex = 0;
    for (const m of source.matchAll(spec.re)) {
      if (spec.stores && !spec.stores.has(m[1])) continue;
      const open = m.index + m[0].length - 1;
      const parsed = splitCallArgs(source, open, budget);
      if (parsed?.over) { calls.incomplete = true; break; }
      if (!parsed) continue;
      const name = parsed.args[spec.name] && literal(parsed.args[spec.name].text);
      if (!name) continue;
      const opt = parsed.args[spec.options];
      if (parsed.args.length > spec.options + 1) continue;
      if (opt && !/^\{[\s\S]*\}$/.test(opt.text)) {
        calls.push({ name, index: m.index, fixable: false, missing: [] }); // options in a variable: can't see them
        continue;
      }
      const text = opt?.text || "";
      const missing = FLAGS.filter((f) => !new RegExp(`\\b${f.key}\\s*:`).test(text) || new RegExp(`\\b${f.key}\\s*:\\s*false\\b`).test(text));
      const absent = FLAGS.filter((f) => !new RegExp(`\\b${f.key}\\s*:`).test(text));
      calls.push({ name, index: m.index, spec, parsed, opt, missing, absent, fixable: parsed.args.length >= spec.options });
    }
  }
  const out = calls.sort((a, b) => a.index - b.index);
  if (calls.incomplete) out.incomplete = true;
  return out;
}
const CALL_READ_FACTOR = 8;



/** The edit that adds a call's missing flags: { start, end, text } replaces source[start, end), or null. */
function callEdit(source, call) {
  const sameSite = call.spec.sameSite || "lax";
  const adds = call.absent.map((f) => (f.key === "sameSite" ? `sameSite: "${sameSite}"` : `${f.key}: true`));
  if (adds.length === 0) return null;
  if (!call.opt) {
    const last = call.parsed.args[call.parsed.args.length - 1];
    return { start: last.end, end: last.end, text: `, { ${adds.join(", ")} }` };
  }
  const start = source.indexOf("{", call.opt.start);
  const end = source.lastIndexOf("}", call.opt.end);
  const inner = source.slice(start + 1, end).trim().replace(/,\s*$/, "");
  const obj = inner ? `{ ${inner}, ${adds.join(", ")} }` : `{ ${adds.join(", ")} }`;
  return { start, end: end + 1, text: obj };
}

/** All the calls' edits in one pass (rebuilding the text per call was quadratic in the calls). */
function fixCalls(source, calls) {
  let out = "";
  let at = 0;
  for (const e of calls.map((c) => callEdit(source, c)).filter(Boolean).sort((a, b) => a.start - b.start)) {
    if (e.start < at) continue; // a call inside another call's options
    out += source.slice(at, e.start) + e.text;
    at = e.end;
  }
  return out + source.slice(at);
}

/**
 * The code files that set cookies, and the code files that could not be read
 * (refused, over the read limit, gone): those are not a pass, the probe names
 * them and the fix run is incomplete.
 */
function filesSettingCookies(repoPath) {
  const files = [];
  const unread = [];
  for (const file of walkCodeFiles(repoPath)) {
    const source = readText(repoPath, file);
    if (source === null) unread.push(file);
    else if (/cookie|cookies/i.test(source)) files.push({ file, source });
  }
  return { files, unread };
}

export default {
  id: "cookie-flags",
  title: "Set Secure, HttpOnly and SameSite on cookies",
  matches(finding) {
    return finding.category === "cookie";
  },
  detect(repoPath) {
    return detectFramework(repoPath) || "node";
  },
  plan(repoPath, finding) {
    const name = (finding.title || "").match(/Cookie "([^"]+)"/)?.[1];
    if (!name) return null;
    const changes = [];
    for (const { file, source } of filesSettingCookies(repoPath).files) {
      const targets = cookieCalls(source).filter((c) => c.name === name && c.fixable && c.absent.length);
      if (targets.length === 0) continue;
      const after = fixCalls(source, targets);
      changes.push({ file, before: source, after });
    }
    const change = toDiff(changes);
    if (!change) return null;
    return {
      ...change,
      ownerActions: [
        `If "${name}" must be readable from browser JavaScript or sent cross-site, revisit HttpOnly or SameSite for it; the defaults here are the safe choice for session cookies.`,
        "Secure cookies are not sent over plain http, so local development needs https or a NODE_ENV check.",
      ],
      confidence: "high",
    };
  },
  probe(repoPath) {
    const findings = [];
    const { files, unread } = filesSettingCookies(repoPath);
    // A file the cookie check could not read: named, and the run is incomplete.
    for (const file of unread) {
      findings.push({
        severity: "info",
        title: `Cookie calls not checked, file not read: ${file}`,
        description: `${file} could not be read (refused, over the read limit or gone), so its cookie calls were not checked for Secure, HttpOnly and SameSite. The run is incomplete and exits 2.`,
        url: file,
        category: "config",
        source: "fix-probe:cookies",
        incomplete: { file, reason: "not read" },
      });
    }
    for (const { file, source } of files) {
      // Line starts once per file: counting from the start per call was quadratic.
      const lineOf = lineIndex(source);
      const calls = cookieCalls(source);
      // Not every call read (one long line of calls): said, never a silent pass.
      if (calls.incomplete) {
        findings.push({
          severity: "info",
          title: `Cookie calls not all checked: ${file}`,
          description: `${file} has more cookie calls on long lines than the cookie check reads in one file, so some calls were not checked for Secure, HttpOnly and SameSite. The run is incomplete and exits 2.`,
          url: file,
          category: "config",
          source: "fix-probe:cookies",
          incomplete: { file, reason: "not all cookie calls read" },
        });
      }
      for (const call of calls) {
        if (call.missing.length === 0) continue;
        findings.push({
          severity: /sess|token|auth|jwt|sid/i.test(call.name) ? "medium" : "low",
          title: `Cookie "${call.name}" ${call.missing.map((f) => `missing ${f.label}`).join(", ")}`,
          description: `Set in ${file}:${lineOf(call.index)}`,
          url: file,
          category: "cookie",
          source: "fix-probe:cookies",
        });
      }
    }
    return findings;
  },
};
