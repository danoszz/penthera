/**
 * Recipe: Secure, HttpOnly and SameSite on cookies set in code (Express
 * res.cookie, Fastify reply.setCookie, Hono setCookie, Next.js cookies().set).
 * Guidance: remediation rule "cookie", references/remediation.md#insecure-cookies.
 *
 * Only single-line calls with a literal cookie name and either no options or an
 * inline options object are edited. Explicit `httpOnly: false` and the like are
 * left alone: someone chose them, and a human should revisit that choice.
 */
import { detectFramework, readText, walkCodeFiles, splitCallArgs, toDiff, lineIndex } from "../util.js";
import { worstKeeper } from "../probe-cap.js";

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

// Next.js: `const store = await cookies(); store.set(...)`. Any `name.set(` is
// matched once and kept when the name is a store: no list of names in a regex,
// so no cap on how many stores a file declares.
const STORE_DECL = /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?cookies\(\)/g;
const STORE_SET = /\b(\w+)\.set\s*\(/g;

/**
 * Every cookie-setting call in `source`, with which flags are missing, passed
 * to `visit` one at a time, so a file with many calls never holds them all.
 * A call two patterns match (a store named `cookieStore`) is visited once.
 * Calls arrive per pattern, not in file order; `call.index` is the offset.
 */
function eachCookieCall(source, visit) {
  const stores = new Set();
  for (const m of source.matchAll(STORE_DECL)) stores.add(m[1]);
  const specs = stores.size ? [...CALLS, { re: STORE_SET, name: 0, options: 2, store: true }] : CALLS;
  const seen = new Set();
  for (const spec of specs) {
    spec.re.lastIndex = 0;
    for (const m of source.matchAll(spec.re)) {
      if (spec.store && !stores.has(m[1])) continue;
      const open = m.index + m[0].length - 1;
      if (seen.has(open)) continue;
      seen.add(open);
      const parsed = splitCallArgs(source, open);
      if (!parsed) continue;
      const name = parsed.args[spec.name] && literal(parsed.args[spec.name].text);
      if (!name) continue;
      const opt = parsed.args[spec.options];
      if (parsed.args.length > spec.options + 1) continue;
      if (opt && !/^\{[\s\S]*\}$/.test(opt.text)) {
        visit({ name, index: m.index, fixable: false, missing: [] }); // options in a variable: can't see them
        continue;
      }
      const text = opt?.text || "";
      const missing = FLAGS.filter((f) => !new RegExp(`\\b${f.key}\\s*:`).test(text) || new RegExp(`\\b${f.key}\\s*:\\s*false\\b`).test(text));
      const absent = FLAGS.filter((f) => !new RegExp(`\\b${f.key}\\s*:`).test(text));
      visit({ name, index: m.index, spec, parsed, opt, missing, absent, fixable: parsed.args.length >= spec.options });
    }
  }
}

/** The calls that set cookie `name`, in file order (the fix edits these). */
function callsNamed(source, name) {
  const calls = [];
  eachCookieCall(source, (c) => {
    if (c.name === name) calls.push(c);
  });
  return calls.sort((a, b) => a.index - b.index);
}

function fixCall(source, call) {
  const sameSite = call.spec.sameSite || "lax";
  const adds = call.absent.map((f) => (f.key === "sameSite" ? `sameSite: "${sameSite}"` : `${f.key}: true`));
  if (adds.length === 0) return source;
  if (!call.opt) {
    const last = call.parsed.args[call.parsed.args.length - 1];
    return source.slice(0, last.end) + `, { ${adds.join(", ")} }` + source.slice(last.end);
  }
  const start = source.indexOf("{", call.opt.start);
  const end = source.lastIndexOf("}", call.opt.end);
  const inner = source.slice(start + 1, end).trim().replace(/,\s*$/, "");
  const obj = inner ? `{ ${inner}, ${adds.join(", ")} }` : `{ ${adds.join(", ")} }`;
  return source.slice(0, start) + obj + source.slice(end + 1);
}

/** Code files that set cookies, read one at a time (never all sources held at once). */
function* filesSettingCookies(repoPath) {
  for (const file of walkCodeFiles(repoPath)) {
    const source = readText(repoPath, file);
    if (source && /cookie|cookies/i.test(source)) yield { file, source };
  }
}

/** Cookies set in one file without Secure, HttpOnly or SameSite. At most PROBE_CAP per file, the worst kept as it goes. */
export function probeCookies(file, source) {
  if (!/cookie/i.test(source)) return [];
  const lineOf = lineIndex(source);
  const worst = worstKeeper(file);
  eachCookieCall(source, (call) => {
    if (call.missing.length === 0) return;
    const line = lineOf(call.index);
    worst.add({
      severity: /sess|token|auth|jwt|sid/i.test(call.name) ? "medium" : "low",
      title: `Cookie "${call.name}" ${call.missing.map((f) => `missing ${f.label}`).join(", ")}`,
      description: `Set in ${file}:${line}`,
      url: file,
      file,
      line,
      category: "cookie",
      source: "fix-probe:cookies",
    }, call.index);
  });
  return worst.result();
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
    for (const { file, source } of filesSettingCookies(repoPath)) {
      const targets = callsNamed(source, name).filter((c) => c.fixable && c.absent.length);
      if (targets.length === 0) continue;
      let after = source;
      // Edit from the end so earlier offsets stay valid.
      for (const call of [...targets].reverse()) after = fixCall(after, call);
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
  probeSource: probeCookies,
  probe(repoPath) {
    const findings = [];
    for (const file of walkCodeFiles(repoPath)) {
      const source = readText(repoPath, file);
      if (source) findings.push(...probeCookies(file, source));
    }
    return findings;
  },
};
