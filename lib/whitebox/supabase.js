/**
 * Supabase checks for a repo scan: the two leaks most common in a Supabase
 * app's own code.
 *
 *   - supabase-service-role-exposed: a service-role key, or the variable that
 *     holds it, reaches the browser. The key bypasses row-level security, and
 *     whatever ships in a bundle ships to every visitor. Four ways: a literal
 *     key in client code, a key assigned to a public env name (NEXT_PUBLIC_,
 *     VITE_ and the like), a public env name for the key, or a build config
 *     that inlines it (next.config `env`, vite `define` or `envPrefix`).
 *     Client code that reads the key under a server-only name is reported at
 *     potential confidence: the value is undefined there, unless a build
 *     config exposes it.
 *   - supabase-service-role-committed: a literal service-role key committed
 *     in server code, a migration, a doc. Not in the browser, but in git.
 *   - supabase-rls-disabled: a migration creates a table in an exposed schema
 *     (public, or [api] schemas in supabase/config.toml) and no migration
 *     enables row-level security on it, or a later one disables it.
 *   - supabase-policy-open: a permissive policy for anon, authenticated or
 *     public whose USING or WITH CHECK is `true`.
 *   - supabase-sql-unchecked: SQL this check could not read whole (it ends
 *     inside a string or comment, or builds tables in dynamic SQL).
 *
 * A key is recognised by its shape and its claims, never by a model: a JWT
 * (`eyJ….eyJ….sig`) whose payload says "role":"service_role", or a new-style
 * `sb_secret_` key. The signature is not checked; the claims are public data.
 * Reports show the claim, never the value.
 *
 * Every parser here is a single forward pass. A file over the cap, refused
 * (a link out, a FIFO) or past the work budget makes the scan incomplete
 * (exit 2); nothing it couldn't read passes as clean.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync } from "node:fs";
import { join, posix, relative, sep } from "node:path";
import { isSecretScanTarget, isSecretSkipDir, isNestedRepo, isVirtualenv } from "./secrets.js";
import { readRepoFile, isRefused } from "../fs-safe.js";

export const SUPABASE_RULES = {
  "supabase-service-role-exposed": "secrets",
  "supabase-service-role-committed": "secrets",
  "supabase-rls-disabled": "auth-bypass",
  "supabase-policy-open": "auth-bypass",
  "supabase-sql-unchecked": "unchecked",
};

/** A migration this large is far past any real one; it is not read, and the scan is incomplete. */
export const MAX_SQL_BYTES = 16 * 1024 * 1024;
/** More migration files than this in one project: the rest are not read, and the scan is incomplete. */
export const MAX_SQL_FILES = 20_000;
/** Files are read in chunks this large; a key across a chunk edge is still seen whole. */
const CHUNK_BYTES = 8 * 1024 * 1024;
/** Longer than any JWT the key rule reads (three segments of at most MAX_SEGMENT). */
const CHUNK_OVERLAP = 16 * 1024;
/** A Supabase key's JWT segment is a few hundred characters; one this long is not an API key. */
const MAX_SEGMENT = 4096;
/** Import edges are read from code files up to this size; a larger one is a bundle. */
const MAX_IMPORT_PARSE_BYTES = 2 * 1024 * 1024;
const MAX_LINES_PER_FINDING = 50;

// ── Names ────────────────────────────────────────────────────────────────

// Env prefixes a framework inlines into the client bundle.
const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "NUXT_PUBLIC_", "PUBLIC_", "GATSBY_", "VUE_APP_"];
const publicPrefixOf = (name) => PUBLIC_PREFIXES.find((p) => name.startsWith(p)) || null;
/** A variable name for the service-role key, the new secret key or the JWT secret. */
export function isServiceRoleName(name) {
  const n = name.toUpperCase();
  return /SERVICE_?ROLE/.test(n) || (n.includes("SUPABASE") && n.includes("SECRET"));
}

// ── Files ────────────────────────────────────────────────────────────────

const CODE_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"]);
const HTML_EXT = new Set([".html", ".htm"]);
const RESOLVE_EXT = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".json"];
const extOf = (name) => {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "";
};
const isEnvFile = (name) => name.startsWith(".env") || /\.env(?:\.[\w.-]{1,64})?$/.test(name);
const isTestPath = (rel) => /(?:^|\/)(?:tests?|__tests__|__mocks__|fixtures?|e2e|cypress|playwright)\//i.test(rel) || /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(rel);

/** Server-only by path: route handlers, API folders, edge functions, scripts, `.server.` files. */
function isServerPath(rel) {
  return /(?:^|\/)(?:pages|src\/pages)\/api\//.test(rel) ||
    /(?:^|\/)route\.[cm]?[jt]sx?$/.test(rel) ||
    /(?:^|\/)middleware\.[cm]?[jt]s$/.test(rel) ||
    /(?:^|\/)supabase\/functions\//.test(rel) ||
    /(?:^|\/)(?:server|api|scripts|netlify\/functions|functions|lambda|workers?)\//.test(rel) ||
    /\.server\.[cm]?[jt]sx?$/.test(rel) || /(?:^|\/)\+(?:page|layout)\.server\.[jt]s$/.test(rel) || /(?:^|\/)\+server\.[jt]s$/.test(rel) ||
    /(?:^|\/)[^/]+\.config\.[cm]?[jt]s$/.test(rel);
}

/** Does the text start with a "use client" (or "use server") directive, after comments? One pass over the head. */
export function directiveOf(text) {
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  for (;;) {
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text.startsWith("//", i)) { const nl = text.indexOf("\n", i); if (nl === -1) return null; i = nl + 1; continue; }
    if (text.startsWith("/*", i)) { const end = text.indexOf("*/", i + 2); if (end === -1) return null; i = end + 2; continue; }
    break;
  }
  const m = /^(["'])use (client|server)\1/.exec(text.slice(i, i + 16));
  return m ? m[2] : null;
}
const SERVER_ONLY_IMPORT = /\bimport\s*["']server-only["']/;

// ── The walk ─────────────────────────────────────────────────────────────

/**
 * One walk for both checks: the files the key rules read, every package.json
 * (to tell an app's framework), and every supabase/ project folder.
 */
function walk(root, ignoredDirs) {
  const files = [];
  const packages = [];
  const projects = [];
  const visit = (dir) => {
    if (isNestedRepo(dir, root) || (dir !== root && (isVirtualenv(dir) || ignoredDirs.has(dir)))) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (isSecretSkipDir(e.name)) continue;
      const full = join(dir, e.name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      const rel = relative(root, full).split(sep).join("/");
      if (st.isDirectory()) {
        if (e.name === "supabase") projects.push(rel);
        visit(full);
      } else if (st.isFile()) {
        if (e.name === "package.json") packages.push(rel);
        if (isSecretScanTarget(rel) || extOf(e.name) === ".sql" || isEnvFile(e.name)) files.push({ rel, full, size: st.size });
      }
    }
  };
  visit(root);
  return { files, packages, projects };
}

/** The apps in this repo: each package.json folder and what it builds. */
function appsOf(root, packages) {
  const apps = [];
  for (const rel of packages) {
    let pkg;
    try { pkg = JSON.parse(readRepoFile(join(root, rel), { root, maxBytes: 1024 * 1024, label: rel })); } catch { continue; }
    const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
    const has = (n) => Object.hasOwn(deps, n);
    const dir = posix.dirname(rel) === "." ? "" : posix.dirname(rel);
    // An SSR framework decides per file; a single-page app or a mobile app ships all its source.
    const ssr = has("next") || has("@sveltejs/kit") || has("nuxt") || has("astro") || has("@remix-run/react") || has("@remix-run/node") || has("@tanstack/react-start") || has("@solidjs/start");
    const spa = !ssr && (has("vite") || has("react-scripts") || has("expo") || has("react-native") || has("@vue/cli-service") || has("@angular/core") || has("parcel"));
    apps.push({ dir, next: has("next"), spa });
  }
  // The deepest folder first, so a file belongs to its nearest package.json.
  return apps.sort((a, b) => b.dir.length - a.dir.length);
}
const appOf = (apps, rel) => apps.find((a) => a.dir === "" || rel.startsWith(a.dir + "/")) || null;
const inApp = (app, rel) => (app && app.dir ? rel.slice(app.dir.length + 1) : rel);

// ── Reading in chunks ────────────────────────────────────────────────────

function openRegular(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
    const st = fstatSync(fd);
    if (!st.isFile()) { closeSync(fd); return null; }
    return { fd, size: st.size };
  } catch {
    if (fd !== undefined) closeSync(fd);
    return null;
  }
}

/** `{ text, linesBefore, start }` chunks that overlap by CHUNK_OVERLAP bytes. */
function* chunksOf(fd, size, chunk = CHUNK_BYTES) {
  let start = 0;
  let linesBefore = 0;
  while (start < size) {
    const len = Math.min(size - start, chunk);
    const buf = Buffer.alloc(len);
    let off = 0;
    for (let n; off < len && (n = readSync(fd, buf, off, len - off, start + off)) > 0;) off += n;
    yield { text: buf.subarray(0, off).toString("utf-8"), linesBefore, first: start === 0 };
    if (off < len || start + len >= size) return;
    const step = len > CHUNK_OVERLAP ? len - CHUNK_OVERLAP : len;
    for (let i = buf.indexOf(10); i !== -1 && i < step; i = buf.indexOf(10, i + 1)) linesBefore++;
    start += step;
  }
}

function lineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}
function lineAt(starts, index) {
  let lo = 0;
  let hi = starts.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (starts[mid] <= index) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

// ── Keys ─────────────────────────────────────────────────────────────────

const B64URL = new Uint8Array(128);
for (const c of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") B64URL[c.charCodeAt(0)] = 1;
const isB64 = (code) => code < 128 && B64URL[code] === 1;
function runEnd(text, i) {
  while (i < text.length && isB64(text.charCodeAt(i))) i++;
  return i;
}

const SERVICE_ROLE_CLAIM = /"role"\s*:\s*"service_role"/;

/**
 * Every Supabase service-role key in the text: `{ index, end, kind, demo }`.
 * kind is "jwt" (a JWT whose payload claims role service_role) or "secret"
 * (an `sb_secret_` key). One forward pass: a run of base64url characters that
 * is not a JWT is skipped whole, so a long run of `eyJeyJ…` costs its length.
 */
export function findServiceKeys(text) {
  const out = [];
  for (let at = text.indexOf("eyJ"); at !== -1; ) {
    const e1 = runEnd(text, at);
    let next = e1 + 1;
    if (text[e1] === "." && text.startsWith("eyJ", e1 + 1) && e1 - at <= MAX_SEGMENT) {
      const e2 = runEnd(text, e1 + 1);
      next = e2 + 1;
      if (text[e2] === "." && e2 - e1 - 1 <= MAX_SEGMENT) {
        const e3 = runEnd(text, e2 + 1);
        next = e3;
        // A token preceded by a base64url character is the tail of something longer.
        if (!(at > 0 && isB64(text.charCodeAt(at - 1)))) {
          const payload = Buffer.from(text.slice(e1 + 1, e2), "base64url").toString("utf-8");
          // The claim, as text: a payload JSON.parse can't read still counts (row 18: the net runs first).
          if (SERVICE_ROLE_CLAIM.test(payload)) {
            let iss = null;
            try { iss = JSON.parse(payload)?.iss ?? null; } catch { /* the regex decided */ }
            out.push({ index: at, end: e3, kind: "jwt", demo: iss === "supabase-demo" });
          }
        }
      }
    }
    at = text.indexOf("eyJ", Math.max(next, at + 1));
  }
  const SB = /sb_secret_([A-Za-z0-9_-]{16,128})(?![A-Za-z0-9_-])/g;
  for (let m; (m = SB.exec(text));) {
    if (m.index > 0 && /[A-Za-z0-9_]/.test(text[m.index - 1])) continue;
    if (/x{4}|\.\.\.|your|example|placeholder|replace|redacted|change_?me/i.test(m[1])) continue;
    out.push({ index: m.index, end: m.index + m[0].length, kind: "secret", demo: false });
  }
  return out.sort((a, b) => a.index - b.index);
}

/**
 * The variable a value at `index` is assigned to on its line (`NAME=`,
 * `NAME: "`, `"NAME": "`), or null. Read backwards a bounded number of
 * characters, so it costs the same for every hit.
 */
function assignedName(text, index) {
  let j = index - 1;
  const space = () => { while (j >= 0 && (text[j] === " " || text[j] === "\t")) j--; };
  space();
  if (text[j] === '"' || text[j] === "'" || text[j] === "`") j--;
  space();
  if (text[j] !== "=" && text[j] !== ":") return null;
  j--;
  space();
  if (text[j] === '"' || text[j] === "'") j--;
  const end = j + 1;
  while (j >= 0 && end - j <= 128 && /[A-Za-z0-9_]/.test(text[j])) j--;
  const name = text.slice(j + 1, end);
  return /^[A-Za-z_]/.test(name) ? name : null;
}

const PUBLIC_NAME = new RegExp(String.raw`(?<![A-Za-z0-9_])(?:${PUBLIC_PREFIXES.join("|")})[A-Z0-9_]{1,100}(?![A-Za-z0-9_])`, "g");
const ENV_READ = /(?:process\.env|import\.meta\.env)(?:\.|\[\s*["'`])([A-Za-z_][A-Za-z0-9_]{0,100})/g;
const IMPORT_SPEC = /\b(?:from|import|require)\s*(?:\(\s*)?(["'])([^"'\n]{1,300})\1/g;

/** Relative and alias import specifiers in a code file. */
function importsOf(text) {
  const out = [];
  for (let m; (m = IMPORT_SPEC.exec(text));) {
    const s = m[2];
    if (s.startsWith(".") || s.startsWith("@/") || s.startsWith("~/") || s.startsWith("/")) out.push(s);
  }
  return out;
}

// ── Build configs ────────────────────────────────────────────────────────

/**
 * The text of the `{ … }` that opens at `open`, matched with quotes skipped.
 * One pass, at most MAX_BLOCK characters: an unclosed or longer block is cut
 * there, so repeated `env: {` can't make the scan quadratic.
 */
const MAX_BLOCK = 64 * 1024;
function blockAt(text, open) {
  let depth = 0;
  const stop = Math.min(text.length, open + MAX_BLOCK);
  for (let i = open; i < stop; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      const close = text.indexOf(c, i + 1);
      if (close === -1 || close >= stop) return text.slice(open, stop);
      i = close;
    } else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return text.slice(open, i + 1);
  }
  return text.slice(open, stop);
}

/** Next's `env` / `publicRuntimeConfig` and Vite's `define` / `envPrefix`: what they put in the bundle. */
function buildConfigExposures(text, kind) {
  const hits = [];
  const keys = kind === "next" ? /\b(env|publicRuntimeConfig)\s*:\s*\{/g : /\b(define)\s*:\s*\{/g;
  for (let m; (m = keys.exec(text));) {
    const block = blockAt(text, m.index + m[0].length - 1);
    const name = /[A-Za-z_][A-Za-z0-9_]{0,100}/g;
    for (let n; (n = name.exec(block));) {
      if (isServiceRoleName(n[0])) { hits.push({ index: m.index, what: `\`${m[1]}\` puts \`${n[0]}\` in the client bundle` }); break; }
    }
  }
  if (kind === "vite") {
    const p = /\benvPrefix\s*:\s*(\[[^\]]{0,1000}\]|["'`][^"'`\n]{0,200}["'`])/g;
    for (let m; (m = p.exec(text));) {
      const prefixes = [...m[1].matchAll(/["'`]([^"'`\n]{0,200})["'`]/g)].map((x) => x[1]);
      const bad = prefixes.find((x) => x === "" || ["SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY", "SERVICE_ROLE_KEY"].some((n) => n.startsWith(x)));
      if (bad !== undefined) hits.push({ index: m.index, what: `\`envPrefix\` ${bad === "" ? "is empty, so every env var" : `\`${bad}\` lets the service-role key`} reach the client bundle` });
    }
  }
  return hits;
}

// ── SQL ──────────────────────────────────────────────────────────────────

/**
 * PostgreSQL text as tokens, in one pass: words (lowercased), "quoted"
 * identifiers (as written), 'strings', $tag$ bodies, numbers and single-character
 * operators. Comments (nested /* *\/ included) are dropped. `open` says the text
 * ends inside a string, identifier, body or comment; the tokens up to there are kept.
 */
export function sqlTokens(text) {
  const tokens = [];
  let open = null;
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") { i++; continue; }
    if (c === "-" && text[i + 1] === "-") { const nl = text.indexOf("\n", i); i = nl === -1 ? n : nl + 1; continue; }
    if (c === "/" && text[i + 1] === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (text[j] === "/" && text[j + 1] === "*") { depth++; j += 2; } else if (text[j] === "*" && text[j + 1] === "/") { depth--; j += 2; } else j++;
      }
      if (depth > 0) { open = "comment"; break; }
      i = j;
      continue;
    }
    if (c === "'" || ((c === "e" || c === "E") && text[i + 1] === "'")) {
      const escapes = c !== "'";
      let j = escapes ? i + 2 : i + 1;
      let done = false;
      while (j < n) {
        if (escapes && text[j] === "\\") { j += 2; continue; }
        if (text[j] === "'") { if (text[j + 1] === "'") { j += 2; continue; } done = true; break; }
        j++;
      }
      if (!done) { open = "string"; break; }
      tokens.push({ t: "str", v: text.slice(escapes ? i + 2 : i + 1, j), at: i });
      i = j + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let v = "";
      let done = false;
      while (j < n) {
        const k = text.indexOf('"', j);
        if (k === -1) break;
        v += text.slice(j, k);
        if (text[k + 1] === '"') { v += '"'; j = k + 2; continue; }
        j = k;
        done = true;
        break;
      }
      if (!done) { open = "identifier"; break; }
      tokens.push({ t: "word", v, quoted: true, at: i });
      i = j + 1;
      continue;
    }
    if (c === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]{0,62})?\$/.exec(text.slice(i, i + 65));
      if (m && !(i > 0 && /[A-Za-z0-9_]/.test(text[i - 1]))) {
        const close = text.indexOf(m[0], i + m[0].length);
        if (close === -1) { open = "body"; tokens.push({ t: "body", v: text.slice(i + m[0].length), at: i }); break; }
        tokens.push({ t: "body", v: text.slice(i + m[0].length, close), at: i });
        i = close + m[0].length;
        continue;
      }
      tokens.push({ t: "op", v: "$", at: i });
      i++;
      continue;
    }
    if (/[A-Za-z_\u0080-￿]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$\u0080-￿]/.test(text[j])) j++;
      tokens.push({ t: "word", v: text.slice(i, j).toLowerCase(), at: i });
      i = j;
      continue;
    }
    if (c >= "0" && c <= "9") {
      let j = i + 1;
      while (j < n && /[0-9.eE]/.test(text[j])) j++;
      tokens.push({ t: "num", v: text.slice(i, j), at: i });
      i = j;
      continue;
    }
    tokens.push({ t: "op", v: c, at: i });
    i++;
  }
  return { tokens, open };
}

/** Statements: token runs between top-level semicolons. */
function statements(tokens) {
  const out = [];
  let cur = [];
  for (const t of tokens) {
    if (t.t === "op" && t.v === ";") { if (cur.length) out.push(cur); cur = []; } else cur.push(t);
  }
  if (cur.length) out.push(cur);
  return out;
}

const isWord = (t, ...v) => t && t.t === "word" && !t.quoted && (v.length === 0 || v.includes(t.v));
const isOp = (t, v) => t && t.t === "op" && t.v === v;

/** A qualified name at s[i]: { parts, next } or null. */
function nameAt(s, i) {
  if (!s[i] || s[i].t !== "word") return null;
  const parts = [s[i].v];
  let j = i + 1;
  while (isOp(s[j], ".") && s[j + 1] && s[j + 1].t === "word") { parts.push(s[j + 1].v); j += 2; }
  return { parts, next: j };
}

/** The tokens inside the parentheses that open at s[i], and the index after the close. */
function parenAt(s, i) {
  if (!isOp(s[i], "(")) return null;
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    if (isOp(s[j], "(")) depth++;
    else if (isOp(s[j], ")") && --depth === 0) return { inner: s.slice(i + 1, j), next: j + 1 };
  }
  return { inner: s.slice(i + 1), next: s.length };
}

/**
 * Is this expression always true: `true`, `(true)`, `1 = 1`, `'t'::boolean`?
 * Brackets are dropped (none of these forms needs them), so it is one pass
 * however deep they nest; anything longer than a few tokens is not one of them.
 */
export function alwaysTrue(expr) {
  const e = expr.filter((t) => !isOp(t, "(") && !isOp(t, ")"));
  if (e.length === 0 || e.length > 6) return false;
  const text = e.map((t) => (t.t === "str" ? `'${t.v}'` : t.v)).join(" ");
  return /^(?:true|1 = 1|'t' : : bool(?:ean)?|'true' : : bool(?:ean)?|true : : bool(?:ean)?)$/.test(text);
}

const SENSITIVE_COLUMN = /e_?mail|phone|password|passwd|secret|token|ssn|address|birth|\bdob\b|stripe|iban|card|salary|api_?key|private|national_id|passport/i;
const POLICY_ROLES = new Set(["public", "anon", "authenticated"]);

/** The `[api] schemas = [...]` list of a supabase/config.toml, or null. */
export function exposedSchemas(toml) {
  const api = /^\s*\[api\]\s*$/m.exec(toml);
  if (!api) return null;
  const rest = toml.slice(api.index + api[0].length);
  const end = /^\s*\[[^\]\n]+\]\s*$/m.exec(rest);
  const section = end ? rest.slice(0, end.index) : rest;
  const m = /^\s*schemas\s*=\s*\[([^\]]{0,4000})\]/m.exec(section);
  return m ? [...m[1].matchAll(/["']([^"'\n]{1,63})["']/g)].map((x) => x[1]) : null;
}

/**
 * Read one Supabase project's migrations, in order, and report tables with no
 * row-level security and open policies. `files` is [{ rel, text }], sorted as
 * the CLI applies them. `budget` counts work across the files; past it the
 * result says `overBudget` and the caller marks the scan incomplete.
 */
export function checkMigrations(files, { schemas = ["public"], budget = null } = {}) {
  const exposed = new Set(schemas);
  const tables = new Map(); // "schema.name" → { schema, name, file, line, rls, revoked, columns }
  const policies = new Map(); // "schema.name|policy" → { … }
  const unchecked = [];
  const defaultRevoked = new Set(); // schemas whose future tables anon and authenticated can't reach
  let steps = 0;
  const limit = budget ?? files.reduce((a, f) => a + f.text.length, 0) * 20 + 1_000_000;
  let overBudget = false;
  const charge = (k) => { steps += k; if (steps > limit) overBudget = true; return overBudget; };

  for (const { rel, text } of files) {
    const starts = lineStarts(text);
    const line = (t) => lineAt(starts, t.at);
    // The tokenizer is one pass by construction; the budget counts the statement work after it.
    const { tokens, open } = sqlTokens(text);
    if (open) unchecked.push({ file: rel, line: tokens.length ? line(tokens.at(-1)) : 1, why: `ends inside a ${open}, so Penthera read it only up to there` });
    let searchPath = "public";
    const qualify = (parts) => (parts.length >= 2 ? { schema: parts.at(-2), name: parts.at(-1) } : { schema: searchPath, name: parts[0] });
    const key = (q) => `${q.schema}.${q.name}`;

    for (const s of statements(tokens)) {
      if (charge(s.length)) break;
      // Dynamic SQL: a DO block or function body that builds a table or turns RLS off.
      for (const t of s) {
        if (t.t === "body" && /\b(?:create\s+(?:(?:unlogged|temp|temporary)\s+)?table|disable\s+row\s+level\s+security)\b/i.test(t.v)) {
          unchecked.push({ file: rel, line: line(t), why: "creates a table or changes row-level security inside a function or DO block, which Penthera doesn't read" });
          break;
        }
      }
      const w0 = s[0];
      if (!isWord(w0)) continue;

      if (w0.v === "set" || (w0.v === "select" && s.some((t) => t.t === "str" && t.v === "search_path"))) {
        let i = 1;
        if (isWord(s[i], "session", "local")) i++;
        if (w0.v === "set" && isWord(s[i], "search_path")) {
          i++;
          if (isWord(s[i], "to") || isOp(s[i], "=")) i++;
          const first = s.slice(i).find((t) => (t.t === "word" || t.t === "str") && t.v !== "$user" && !isOp(t, ","));
          searchPath = first && first.v !== "" ? first.v : "public";
        } else if (w0.v === "select") {
          const idx = s.findIndex((t) => t.t === "str" && t.v === "search_path");
          const val = s.slice(idx + 1).find((t) => t.t === "str");
          const first = val ? val.v.split(",").map((x) => x.trim().replace(/^"|"$/g, "")).find((x) => x && x !== "$user") : null;
          searchPath = first || "public";
        }
        continue;
      }

      if (w0.v === "create") {
        let i = 1;
        if (isWord(s[i], "or") && isWord(s[i + 1], "replace")) i += 2;
        if (isWord(s[i], "global", "local")) i++;
        let temp = false;
        if (isWord(s[i], "temp", "temporary")) { temp = true; i++; }
        if (isWord(s[i], "unlogged")) i++;
        if (isWord(s[i], "table")) {
          i++;
          if (isWord(s[i], "if") && isWord(s[i + 1], "not") && isWord(s[i + 2], "exists")) i += 3;
          const nm = nameAt(s, i);
          if (!nm || temp) continue;
          const q = qualify(nm.parts);
          const columns = [];
          const body = parenAt(s, nm.next);
          if (body) {
            let depth = 0;
            let expect = true;
            for (const t of body.inner) {
              if (isOp(t, "(")) depth++;
              else if (isOp(t, ")")) depth--;
              else if (depth === 0 && isOp(t, ",")) { expect = true; continue; }
              if (expect && depth === 0 && t.t === "word") {
                if (!isWord(t, "constraint", "primary", "foreign", "unique", "check", "exclude", "like")) columns.push(t.v);
                expect = false;
              }
            }
          }
          tables.set(key(q), { ...q, file: rel, line: line(s[0]), rls: false, revoked: defaultRevoked.has(q.schema), columns });
          continue;
        }
        if (isWord(s[i], "policy")) {
          const name = s[i + 1];
          if (!name || name.t !== "word" || !isWord(s[i + 2], "on")) continue;
          const nm = nameAt(s, i + 3);
          if (!nm) continue;
          const q = qualify(nm.parts);
          const p = { table: key(q), name: name.v, file: rel, line: line(s[0]), permissive: true, command: "all", roles: ["public"], using: null, check: null };
          readPolicyClauses(s, nm.next, p);
          policies.set(`${p.table}|${p.name}`, p);
        }
        continue;
      }

      if (w0.v === "alter" && isWord(s[1], "table")) {
        let i = 2;
        if (isWord(s[i], "if") && isWord(s[i + 1], "exists")) i += 2;
        if (isWord(s[i], "only")) i++;
        const nm = nameAt(s, i);
        if (!nm) continue;
        const q = qualify(nm.parts);
        let t = tables.get(key(q));
        for (let j = nm.next; j < s.length; j++) {
          if (isWord(s[j], "enable", "disable") && isWord(s[j + 1], "row") && isWord(s[j + 2], "level") && isWord(s[j + 3], "security")) {
            if (!t) { t = { ...q, file: rel, line: line(s[0]), rls: false, revoked: false, columns: [], external: true }; tables.set(key(q), t); }
            t.rls = s[j].v === "enable";
            if (!t.rls) { t.file = rel; t.line = line(s[j]); t.disabledHere = true; }
          } else if (t && isWord(s[j], "rename") && isWord(s[j + 1], "to") && s[j + 2]?.t === "word") {
            tables.delete(key(t));
            t.name = s[j + 2].v;
            tables.set(key(t), t);
          } else if (t && isWord(s[j], "set") && isWord(s[j + 1], "schema") && s[j + 2]?.t === "word") {
            tables.delete(key(t));
            t.schema = s[j + 2].v;
            tables.set(key(t), t);
          }
        }
        continue;
      }

      if (w0.v === "alter" && isWord(s[1], "policy")) {
        const name = s[2];
        if (!name || name.t !== "word" || !isWord(s[3], "on")) continue;
        const nm = nameAt(s, 4);
        if (!nm) continue;
        const q = qualify(nm.parts);
        const p = policies.get(`${key(q)}|${name.v}`);
        if (!p) continue;
        if (isWord(s[nm.next], "rename") && isWord(s[nm.next + 1], "to") && s[nm.next + 2]?.t === "word") {
          policies.delete(`${p.table}|${p.name}`);
          p.name = s[nm.next + 2].v;
          policies.set(`${p.table}|${p.name}`, p);
        } else {
          readPolicyClauses(s, nm.next, p);
          p.file = rel;
          p.line = line(s[0]);
        }
        continue;
      }

      if (w0.v === "drop" && isWord(s[1], "table")) {
        let i = 2;
        if (isWord(s[i], "if") && isWord(s[i + 1], "exists")) i += 2;
        while (i < s.length) {
          const nm = nameAt(s, i);
          if (!nm) break;
          tables.delete(key(qualify(nm.parts)));
          i = nm.next;
          if (!isOp(s[i], ",")) break;
          i++;
        }
        continue;
      }

      if (w0.v === "drop" && isWord(s[1], "policy")) {
        let i = 2;
        if (isWord(s[i], "if") && isWord(s[i + 1], "exists")) i += 2;
        const name = s[i];
        if (!name || name.t !== "word" || !isWord(s[i + 1], "on")) continue;
        const nm = nameAt(s, i + 2);
        if (nm) policies.delete(`${key(qualify(nm.parts))}|${name.v}`);
        continue;
      }

      // Grants: a table anon and authenticated can't reach isn't exposed by the API.
      const isDefault = w0.v === "alter" && isWord(s[1], "default") && isWord(s[2], "privileges");
      const g = isDefault ? s.findIndex((t) => isWord(t, "grant", "revoke")) : 0;
      if (g !== -1 && isWord(s[g], "grant", "revoke")) {
        const revoke = s[g].v === "revoke";
        const on = s.findIndex((t, k) => k > g && isWord(t, "on"));
        const toFrom = s.findIndex((t, k) => k > on && on !== -1 && isWord(t, revoke ? "from" : "to"));
        if (on === -1 || toFrom === -1) continue;
        const privs = s.slice(g + 1, on).filter((t) => t.t === "word").map((t) => t.v);
        const roles = new Set(s.slice(toFrom + 1).filter((t) => t.t === "word").map((t) => t.v));
        const reaches = roles.has("anon") || roles.has("authenticated") || roles.has("public");
        const both = roles.has("anon") && roles.has("authenticated");
        if (revoke ? !(both && privs.includes("all")) : !reaches) continue;
        let names = [];
        let schemaWide = null;
        if (isDefault) {
          const inSchema = s.findIndex((t) => isWord(t, "schema"));
          schemaWide = inSchema !== -1 && s[inSchema + 1]?.t === "word" ? s[inSchema + 1].v : "public";
          if (revoke) defaultRevoked.add(schemaWide); else defaultRevoked.delete(schemaWide);
          continue;
        }
        if (isWord(s[on + 1], "all") && isWord(s[on + 2], "tables") && isWord(s[on + 3], "in") && isWord(s[on + 4], "schema")) {
          schemaWide = s[on + 5]?.v;
        } else {
          let i = on + 1;
          if (isWord(s[i], "table")) i++;
          while (i < toFrom) {
            const nm = nameAt(s, i);
            if (!nm) break;
            names.push(key(qualify(nm.parts)));
            i = nm.next;
            if (!isOp(s[i], ",")) break;
            i++;
          }
        }
        if (schemaWide) {
          if (charge(tables.size)) break;
          for (const t of tables.values()) if (t.schema === schemaWide) t.revoked = revoke;
        } else {
          for (const k of names) { const t = tables.get(k); if (t) t.revoked = revoke; }
        }
      }
    }
    if (overBudget) break;
  }

  const findings = [];
  for (const t of tables.values()) {
    if (t.rls || t.revoked || !exposed.has(t.schema)) continue;
    if (t.external && !t.disabledHere) continue;
    findings.push({ kind: "rls", table: t });
  }
  for (const p of policies.values()) {
    if (!p.permissive) continue;
    const roles = p.roles.filter((r) => POLICY_ROLES.has(r));
    if (!roles.length) continue;
    const openUsing = p.using && alwaysTrue(p.using);
    const openCheck = p.check && alwaysTrue(p.check);
    if (!openUsing && !openCheck) continue;
    const [schema, name] = p.table.split(/\.(?=[^.]*$)/);
    if (!exposed.has(schema)) continue;
    const t = tables.get(p.table);
    if (t && t.revoked) continue;
    findings.push({ kind: "policy", policy: p, roles, openUsing, openCheck, table: t || { schema, name, columns: [] } });
  }
  return { findings, unchecked, overBudget };
}

/** FOR, TO, AS, USING and WITH CHECK of a CREATE or ALTER POLICY, from s[i] on. */
function readPolicyClauses(s, i, p) {
  for (let j = i; j < s.length; j++) {
    if (isWord(s[j], "as") && isWord(s[j + 1], "permissive", "restrictive")) { p.permissive = s[j + 1].v === "permissive"; j++; } else if (isWord(s[j], "for") && isWord(s[j + 1], "all", "select", "insert", "update", "delete")) { p.command = s[j + 1].v; j++; } else if (isWord(s[j], "to")) {
      const roles = [];
      let k = j + 1;
      while (k < s.length && !isWord(s[k], "using", "with")) {
        if (s[k].t === "word") roles.push(s[k].v);
        k++;
      }
      p.roles = roles;
      j = k - 1;
    } else if (isWord(s[j], "using")) {
      const par = parenAt(s, j + 1);
      if (par) { p.using = par.inner; j = par.next - 1; }
    } else if (isWord(s[j], "with") && isWord(s[j + 1], "check")) {
      const par = parenAt(s, j + 2);
      if (par) { p.check = par.inner; j = par.next - 1; }
    }
  }
}

// ── Findings ─────────────────────────────────────────────────────────────

function finding(rule, severity, file, line, title, description, remediation, confidence = "likely") {
  return {
    severity, title, description, remediation,
    url: file, file, line,
    templateId: rule,
    category: SUPABASE_RULES[rule],
    source: "supabase-scan",
    confidence,
  };
}

const KEY_FIX = "Rotate the key now in the Supabase dashboard (Project Settings, API keys), since anyone who loaded the app has it. Then use only the anon or publishable key in browser code, keep the service-role key in a server-only variable (no NEXT_PUBLIC_ or VITE_ prefix), and call it from a route handler, server action or Edge Function.";
const COMMITTED_FIX = "Rotate the key in the Supabase dashboard (Project Settings, API keys): git history keeps it. Load it from an environment variable that only the server reads, and keep .env files out of git.";

function describeKey(hit) {
  return hit.kind === "jwt" ? "a JWT whose payload claims `\"role\": \"service_role\"`" : "an `sb_secret_` key";
}

/**
 * Run the Supabase checks on a repo. `ignored` is gitIgnored()'s result.
 * Returns { findings, incomplete, migrations } where incomplete lists
 * { file, reason } for what was not read whole.
 */
export function scanSupabase(repoPath, { ignored = null, maxSqlBytes = MAX_SQL_BYTES } = {}) {
  const root = repoPath;
  const ignoredDirs = new Set(ignored?.dirs || []);
  const ignoredFiles = ignored?.files || new Set();
  const { files, packages, projects } = walk(root, ignoredDirs);
  const apps = appsOf(root, packages);
  const findings = [];
  const incomplete = [];

  // ── Keys and env names ──
  const byKey = new Map();
  const add = (f) => {
    const k = `${f.templateId}|${f.file}|${f.title}`;
    const seen = byKey.get(k);
    if (!seen) { f.lines = [f.line]; byKey.set(k, f); findings.push(f); return; }
    if (!seen.lines.includes(f.line) && seen.lines.length < MAX_LINES_PER_FINDING) seen.lines.push(f.line);
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    if (rank[f.severity] > rank[seen.severity]) Object.assign(seen, { severity: f.severity, description: f.description, confidence: f.confidence });
  };

  // Per-file facts for reachability: which files are client code, and their import edges.
  const info = new Map();
  const keyHits = [];
  const envReads = [];
  for (const file of files) {
    const fd = openRegular(file.full);
    if (!fd) continue;
    const name = file.rel.split("/").pop();
    const ext = extOf(name);
    const code = CODE_EXT.has(ext);
    const env = isEnvFile(name);
    const local = ignoredFiles.has(file.full);
    const test = isTestPath(file.rel);
    const fi = { rel: file.rel, code, html: HTML_EXT.has(ext), directive: null, serverOnly: false, imports: [] };
    info.set(file.rel, fi);
    try {
      for (const { text, linesBefore, first } of chunksOf(fd.fd, fd.size)) {
        let starts = null;
        const at = (index) => linesBefore + lineAt((starts ??= lineStarts(text)), index);
        if (first && code) {
          fi.directive = directiveOf(text.slice(0, 4096));
          fi.serverOnly = SERVER_ONLY_IMPORT.test(text.slice(0, 64 * 1024)) || fi.directive === "server";
          if (fd.size <= MAX_IMPORT_PARSE_BYTES) fi.imports = importsOf(text);
        }
        if (first && fi.html && fd.size <= MAX_IMPORT_PARSE_BYTES) fi.imports = [...text.matchAll(/<script\b[^>]{0,500}?\bsrc\s*=\s*["']([^"'\s>]{1,300})["']/gi)].map((m) => m[1]);
        if (text.includes("eyJ") || text.includes("sb_secret_")) {
          for (const hit of findServiceKeys(text)) keyHits.push({ file: file.rel, line: at(hit.index), hit, name: assignedName(text, hit.index), local, test, env });
        }
        if (code || env || fi.html || ext === ".json" || ext === ".toml" || ext === ".yml" || ext === ".yaml") {
          PUBLIC_NAME.lastIndex = 0;
          for (let m; (m = PUBLIC_NAME.exec(text));) {
            if (!isServiceRoleName(m[0])) continue;
            add(finding("supabase-service-role-exposed", local ? "medium" : "high", file.rel, at(m.index),
              `Service-role key under a public env name: \`${m[0]}\``,
              `\`${file.rel}\` uses \`${m[0]}\`. The \`${publicPrefixOf(m[0])}\` prefix tells the build to inline the value into the browser bundle, so whatever key this holds ships to every visitor. A service-role key bypasses row-level security: with it, anyone can read and change every table.${local ? " The file is ignored by git, so it isn't committed, but any build that loads it inlines the key." : ""}`,
              `Rename it without the public prefix (for example SUPABASE_SERVICE_ROLE_KEY) and read it only in server code. If a build ever ran with it set, ${KEY_FIX.charAt(0).toLowerCase()}${KEY_FIX.slice(1)}`,
              test ? "potential" : "likely"));
          }
        }
        if (code) {
          ENV_READ.lastIndex = 0;
          for (let m; (m = ENV_READ.exec(text));) {
            if (isServiceRoleName(m[1]) && !publicPrefixOf(m[1])) envReads.push({ file: file.rel, line: at(m.index), name: m[1], test });
          }
          const base = name.replace(/\.[^.]+$/, "");
          const kind = base === "next.config" ? "next" : base === "vite.config" ? "vite" : null;
          if (kind && first) {
            for (const x of buildConfigExposures(text, kind)) {
              add(finding("supabase-service-role-exposed", "high", file.rel, at(x.index),
                "A build config puts the service-role key in the browser bundle",
                `\`${file.rel}\`: ${x.what}. A service-role key bypasses row-level security, and everything in the bundle ships to every visitor.`,
                `Remove the key from the build config and read it with process.env only in server code. ${KEY_FIX}`));
            }
          }
        }
      }
    } finally {
      closeSync(fd.fd);
    }
  }

  // Reachability: client seeds, then their imports, breadth first; each file once.
  const client = new Set();
  const queue = [];
  const seed = (rel) => {
    const fi = info.get(rel);
    if (!fi || client.has(rel) || fi.serverOnly) return;
    client.add(rel);
    queue.push(rel);
  };
  for (const fi of info.values()) {
    const app = appOf(apps, fi.rel);
    const own = inApp(app, fi.rel);
    if (/(?:^|\/)(?:public|static)\//.test(own) && !/(?:^|\/)supabase\//.test(own)) { seed(fi.rel); continue; }
    if (fi.html) { seed(fi.rel); continue; }
    if (!fi.code || fi.serverOnly || isServerPath(own)) continue;
    if (fi.directive === "client") { seed(fi.rel); continue; }
    if (app?.next && /^(?:src\/)?pages\//.test(own)) { seed(fi.rel); continue; }
    // A single-page or mobile app ships its source folders; other files count once client code imports them.
    if (app?.spa && !isTestPath(own) && (/^(?:src|app|components|screens|hooks|pages)\//.test(own) || /^(?:App|index|main)\.[cm]?[jt]sx?$/.test(own))) seed(fi.rel);
  }
  const resolveSpec = (from, spec) => {
    const app = appOf(apps, from);
    const appDir = app?.dir || "";
    let base;
    if (spec.startsWith(".")) base = posix.join(posix.dirname(from), spec);
    else if (spec.startsWith("/")) base = posix.join(appDir, spec);
    else base = null;
    const candidates = base ? [base] : [posix.join(appDir, "src", spec.slice(2)), posix.join(appDir, spec.slice(2))];
    for (const c of candidates) {
      const clean = c.replace(/\?.*$/, "");
      if (info.has(clean)) return clean;
      for (const e of RESOLVE_EXT) { if (info.has(clean + e)) return clean + e; }
      for (const e of RESOLVE_EXT) { if (info.has(`${clean}/index${e}`)) return `${clean}/index${e}`; }
      // A .js specifier that names a .ts file (TypeScript's NodeNext style).
      const js = /\.[cm]?jsx?$/.exec(clean);
      if (js) for (const e of [".ts", ".tsx", ".mts", ".cts"]) { const t = clean.slice(0, -js[0].length) + e; if (info.has(t)) return t; }
    }
    return null;
  };
  for (let q = 0; q < queue.length; q++) {
    const rel = queue[q];
    const fi = info.get(rel);
    for (const spec of fi.imports) {
      const to = resolveSpec(rel, spec);
      if (!to) continue;
      const target = info.get(to);
      // A "use server" module imported by a client file becomes a server action; its code stays on the server.
      if (target.serverOnly) continue;
      seed(to);
    }
  }

  for (const k of keyHits) {
    const what = describeKey(k.hit);
    const publicName = k.name && publicPrefixOf(k.name);
    const inClient = client.has(k.file);
    if (k.hit.demo) {
      add(finding("supabase-service-role-committed", "low", k.file, k.line,
        "Supabase's default local service-role key",
        `\`${k.file}\` holds ${what} issued by \`supabase-demo\`: the well-known key every local Supabase stack uses. It opens nothing on Supabase's hosted platform, but it is full access to any self-hosted Supabase still running with the default keys.`,
        "Fine for a local stack. If you self-host Supabase, generate your own JWT secret and keys, and keep them out of the repo.",
        "potential"));
      continue;
    }
    if (publicName || inClient) {
      if (k.local && !publicName) continue;
      const how = publicName
        ? `It is assigned to \`${k.name}\`: the \`${publicName}\` prefix makes the build inline it into the browser bundle.`
        : "This file is client code (it ships to the browser), so the key is in every visitor's copy of the app.";
      add(finding("supabase-service-role-exposed", k.local ? "high" : "critical", k.file, k.line,
        "Supabase service-role key in browser code",
        `\`${k.file}\` line ${k.line} holds ${what}. ${how} The service-role key bypasses row-level security: with it, anyone can read, change and delete every row of every table.${k.local ? " The file is ignored by git, so it isn't committed, but any build that loads it ships the key." : ""}`,
        KEY_FIX, k.test ? "potential" : "likely"));
      continue;
    }
    if (k.local) continue; // a server-only key in an ignored .env is the right setup
    add(finding("supabase-service-role-committed", "high", k.file, k.line,
      "Supabase service-role key committed to the repo",
      `\`${k.file}\` line ${k.line} holds ${what}. Penthera didn't find this file in browser code, but the key is in git, and it bypasses row-level security for every table.`,
      COMMITTED_FIX, k.test ? "potential" : "likely"));
  }

  for (const r of envReads) {
    if (!client.has(r.file)) continue;
    add(finding("supabase-service-role-exposed", "medium", r.file, r.line,
      `Client code reads \`${r.name}\``,
      `\`${r.file}\` is client code and reads \`${r.name}\`. Under a server-only name the value is undefined in the browser, unless a build config inlines it, and then the service-role key ships to every visitor. Either way this code expects admin access in the browser.`,
      "Move the call that needs the service-role key into a route handler, server action or Edge Function, and use the anon or publishable key in the browser.",
      "potential"));
  }

  // ── Migrations ──
  let migrations = 0;
  for (const project of projects) {
    const dirs = ["migrations", "schemas"].map((d) => `${project}/${d}`).filter((d) => {
      let st;
      try { st = lstatSync(join(root, d)); } catch { return false; }
      // A link or other non-folder where migrations belong is reported, not passed over.
      if (!st.isDirectory()) incomplete.push({ file: d, reason: st.isSymbolicLink() ? "it is a symbolic link" : "it is not a folder" });
      return st.isDirectory();
    });
    if (!dirs.length) continue;
    let schemas = ["public"];
    try {
      const toml = readRepoFile(join(root, project, "config.toml"), { root, maxBytes: 1024 * 1024, label: `${project}/config.toml` });
      schemas = exposedSchemas(toml) || schemas;
    } catch (e) {
      if (isRefused(e)) incomplete.push({ file: `${project}/config.toml`, reason: e.reason || e.message });
    }
    const sql = [];
    for (const d of dirs) {
      const list = [];
      const collect = (dir) => {
        let entries;
        try { entries = readdirSync(join(root, dir), { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
          const rel = `${dir}/${e.name}`;
          if (e.isDirectory()) collect(rel);
          else if (extOf(e.name) === ".sql") list.push(rel);
        }
      };
      collect(d);
      // The CLI applies migrations in filename order; declarative schemas come after.
      list.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      sql.push(...list);
    }
    const read = [];
    for (const rel of sql) {
      if (read.length >= MAX_SQL_FILES) {
        incomplete.push({ file: rel, reason: `more than ${MAX_SQL_FILES} SQL files in ${project}; the rest were not read` });
        break;
      }
      try {
        read.push({ rel, text: readRepoFile(join(root, rel), { root, maxBytes: maxSqlBytes, label: rel }) });
      } catch (e) {
        if (isRefused(e)) incomplete.push({ file: rel, reason: e.reason || e.message });
        else if (e.code !== "ENOENT") incomplete.push({ file: rel, reason: e.message });
      }
    }
    migrations += read.length;
    const res = checkMigrations(read, { schemas });
    if (res.overBudget) incomplete.push({ file: project, reason: "the migrations took more work than their size allows, so Penthera stopped reading them" });
    for (const u of res.unchecked) {
      findings.push(finding("supabase-sql-unchecked", "medium", u.file, u.line,
        "A migration Penthera couldn't fully read",
        `\`${u.file}\` ${u.why}. Tables made there aren't checked for row-level security.`,
        "Check by hand that every table it creates has row-level security enabled, or write it as plain CREATE TABLE and ALTER TABLE … ENABLE ROW LEVEL SECURITY statements.",
        "potential"));
    }
    for (const f of res.findings) {
      const t = f.table;
      const full = `${t.schema}.${t.name}`;
      const sensitive = (t.columns || []).filter((c) => SENSITIVE_COLUMN.test(c));
      const cols = sensitive.length ? ` Its columns include ${sensitive.slice(0, 5).map((c) => `\`${c}\``).join(", ")}.` : "";
      if (f.kind === "rls") {
        findings.push(finding("supabase-rls-disabled", "high", t.file, t.line,
          `Table \`${full}\` has no row-level security`,
          t.disabledHere
            ? `\`${t.file}\` line ${t.line} disables row-level security on \`${full}\`, and no later migration turns it back on. Supabase's API serves the \`${t.schema}\` schema to anyone with the anon key, which ships in your app, so anyone can read and change every row.${cols}`
            : `\`${t.file}\` line ${t.line} creates \`${full}\`, and no migration enables row-level security on it. Supabase's API serves the \`${t.schema}\` schema to anyone with the anon key, which ships in your app, so anyone can read and change every row.${cols}`,
          `Add a migration with \`alter table ${full} enable row level security;\` and policies for who may read and write. If row-level security is already on in the dashboard, put it in a migration too, so the repo says what the database does.`));
        continue;
      }
      const p = f.policy;
      const who = f.roles.includes("public") ? "everyone (no TO clause, or TO public)" : f.roles.join(" and ");
      const writes = p.command !== "select";
      const anyone = f.roles.includes("public") || f.roles.includes("anon");
      let severity;
      let confidence = "likely";
      if (!writes) { severity = sensitive.length && anyone ? "medium" : "low"; confidence = "potential"; } else if (p.command === "insert") { severity = anyone ? "medium" : "low"; confidence = "potential"; } else severity = anyone ? "high" : "medium";
      const what = p.command === "select" ? "read every row" : p.command === "insert" ? "insert any row" : p.command === "all" ? "read, change and delete every row" : `${p.command} every row`;
      findings.push(finding("supabase-policy-open", severity, p.file, p.line,
        `Policy "${p.name}" lets ${anyone ? "anyone" : "any signed-in user"} ${what} of \`${full}\``,
        `\`${p.file}\` line ${p.line}: the policy "${p.name}" on \`${full}\` applies to ${who}${p.command === "all" ? " for every command" : ` for ${p.command.toUpperCase()}`} with ${f.openUsing ? "USING (true)" : ""}${f.openUsing && f.openCheck ? " and " : ""}${f.openCheck ? "WITH CHECK (true)" : ""}, so it checks nothing.${anyone ? " The anon key ships in your app." : " Supabase lets anyone sign up unless you turn it off."}${cols}${writes ? "" : " Fine for data meant to be public."}`,
        `Replace \`true\` with a condition on the row, for example \`(select auth.uid()) = user_id\`, and give each command its own policy.${writes ? "" : " If this table is meant to be public, keep it and make sure it holds nothing private."}`,
        confidence));
    }
  }

  // A key finding on a line says more than the public-name finding on the same line.
  const keyAt = new Set(findings.filter((f) => f.title === "Supabase service-role key in browser code").map((f) => `${f.file}|${f.line}`));
  const out = findings.filter((f) => !(f.title.startsWith("Service-role key under a public env name") && f.lines && f.lines.every((l) => keyAt.has(`${f.file}|${l}`))));
  for (const f of out) {
    if (f.lines && f.lines.length < 2) delete f.lines;
    else if (f.lines) f.lines.sort((a, b) => a - b);
  }
  return { findings: out, incomplete, migrations };
}
