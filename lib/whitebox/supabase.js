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
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, realpathSync, statSync } from "node:fs";
import { createHash, createHmac } from "node:crypto";
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
/** Distinct service-role env names kept per file and per repo; past either the file is not fully checked. */
export const MAX_NAMES_PER_FILE = 1000;
export const MAX_NAMES_TOTAL = 20_000;
/** Files per kind of env-name finding that get a finding of their own; the rest are counted. */
export const MAX_NAME_GROUPS = 1000;

// ── Names ────────────────────────────────────────────────────────────────

// Env prefixes a framework inlines into the client bundle.
const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "NUXT_PUBLIC_", "PUBLIC_", "GATSBY_", "VUE_APP_"];
const publicPrefixOf = (name) => PUBLIC_PREFIXES.find((p) => name.startsWith(p)) || null;
/** A variable name for the service-role key, the new secret key or the JWT secret. */
export function isServiceRoleName(name) {
  const n = name.toUpperCase();
  return /SERVICE_?ROLE/.test(n) || (n.includes("SUPABASE") && (n.includes("SECRET") || /SERVICE_?KEY/.test(n)));
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
  const skipped = [];
  const aliases = []; // links inside the project: { rel, target, dir }
  let realRoot;
  try { realRoot = realpathSync(root); } catch { realRoot = root; }
  const wanted = (rel, name) => isSecretScanTarget(rel) || CODE_EXT.has(extOf(name)) || HTML_EXT.has(extOf(name)) || extOf(name) === ".sql" || isEnvFile(name);
  const visit = (dir) => {
    if (isNestedRepo(dir, root) || (dir !== root && (isVirtualenv(dir) || ignoredDirs.has(dir)))) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch (e) {
      skipped.push({ file: relative(root, dir).split(sep).join("/") || ".", reason: `the folder can't be read (${e.code || e.message})` });
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (isSecretSkipDir(e.name)) continue;
      const full = join(dir, e.name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      const rel = relative(root, full).split(sep).join("/");
      if (st.isSymbolicLink()) {
        // A link inside the project is read at its target. One that leaves the project or is broken
        // is reported, when it names something this check reads (row 2).
        let real = null;
        try { real = realpathSync(full); } catch { /* broken */ }
        const inside = real !== null && (real === realRoot || real.startsWith(realRoot + sep));
        let dir = false;
        try { dir = statSync(full).isDirectory(); } catch { /* broken */ }
        if (!inside) {
          // Any folder, or a file this check reads: what it holds was not checked.
          if (dir || wanted(rel, e.name)) skipped.push({ file: rel, reason: real === null ? "it is a broken link" : "it is a link out of the project folder" });
        } else if (real !== realRoot) {
          // Read at its target; the link's own path still decides whether it ships (public/keys.js -> ../server/keys.js).
          aliases.push({ rel, target: relative(realRoot, real).split(sep).join("/"), dir });
        }
        continue;
      }
      if (st.isDirectory()) {
        if (e.name === "supabase") projects.push(rel);
        visit(full);
      } else if (st.isFile()) {
        if (e.name === "package.json") packages.push(rel);
        if (wanted(rel, e.name)) files.push({ rel, full, size: st.size });
      } else if (wanted(rel, e.name)) {
        skipped.push({ file: rel, reason: "it is not a regular file (a device, FIFO or socket)" });
      }
    }
  };
  visit(root);
  return { files, packages, projects, skipped, aliases };
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
    apps.push({ dir, next: has("next"), spa, supabase: Object.keys(deps).some((n) => n.startsWith("@supabase/")) });
  }
  // The deepest folder first, so a file belongs to its nearest package.json.
  return apps.sort((a, b) => b.dir.length - a.dir.length);
}
/**
 * The app a file belongs to: its nearest package.json folder. Looked up by folder prefix in a map,
 * O(path depth), not by scanning every app: a crafted repo can hold thousands (review of PR 312).
 */
const appIndex = new WeakMap();
const appOf = (apps, rel) => {
  let byDir = appIndex.get(apps);
  if (!byDir) { byDir = new Map(apps.map((a) => [a.dir, a])); appIndex.set(apps, byDir); }
  for (let at = rel.lastIndexOf("/"); at > 0; at = rel.lastIndexOf("/", at - 1)) {
    const app = byDir.get(rel.slice(0, at));
    if (app) return app;
  }
  return byDir.get("") || null;
};
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
// The JWT secret every local Supabase stack (`supabase start`) signs with, published in
// Supabase's docs. A key it signs opens only a stack that still uses it. The claim alone
// proves nothing (row 6): a key counts as the demo key only if this secret signed it.
const LOCAL_DEMO_SECRET = ["super", "secret", "jwt", "token", "with", "at", "least", "32", "characters", "long"].join("-");
const signedWithDemoSecret = (signingInput, sig) => createHmac("sha256", LOCAL_DEMO_SECRET).update(signingInput).digest("base64url") === sig;

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
            const demo = iss === "supabase-demo" && signedWithDemoSecret(text.slice(at, e2), text.slice(e2 + 1, e3));
            out.push({ index: at, end: e3, kind: "jwt", demo });
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

// The start of a public name; the caller reads it to the end of the identifier (identEnd), so a name
// longer than any bound is still seen (review of PR 312: one over 100 characters was dropped).
const PUBLIC_NAME = new RegExp(String.raw`(?<![A-Za-z0-9_])(?:${PUBLIC_PREFIXES.join("|")})[A-Z0-9_]`, "g");
/** Where the identifier that starts at `i` ends: one forward pass, and the caller skips past it. */
function identEnd(text, i) {
  let j = i;
  while (j < text.length && /[A-Za-z0-9_]/.test(text[j])) j++;
  return j;
}
/** A name as kept: at most 200 characters (enough for any real env name). */
const MAX_ENV_NAME = 200;
const ENV_READ = /(?:process\.env|import\.meta\.env)(?:\.|\[\s*["'`])(?=[A-Za-z_])/g;
const IMPORT_SPEC = /\b(?:from|import|require)\s*(?:\(\s*)?(["'])([^"'\n]{1,300})\1/g;

/** Distinct import specifiers kept per file; past it the file's imports are not all followed. */
export const MAX_IMPORTS_PER_FILE = 5000;

/**
 * Relative and alias import specifiers in a code file, each once (the same import 100k times is
 * resolved once: review of PR 312). `cut` is set when a file has more than MAX_IMPORTS_PER_FILE.
 */
function importsOf(text) {
  const out = new Set();
  let cut = false;
  IMPORT_SPEC.lastIndex = 0;
  for (let m; (m = IMPORT_SPEC.exec(text));) {
    const s = m[2];
    if (!(s.startsWith(".") || s.startsWith("@/") || s.startsWith("~/") || s.startsWith("/")) || out.has(s)) continue;
    if (out.size >= MAX_IMPORTS_PER_FILE) { cut = true; continue; }
    // Copied (own): a kept specifier must not hold its whole source file in memory.
    out.add(own(s));
  }
  const list = [...out];
  if (cut) list.cut = true;
  return list;
}

// ── Build configs ────────────────────────────────────────────────────────

/**
 * Spans of the `{ … }` objects that a build config inlines into the bundle:
 * Next's `env` and `publicRuntimeConfig`, Vite's `define`. One pass over the
 * file with a stack of open braces (quoted text skipped), keeping only the
 * outermost such span, so nesting and padding can't hide a name or make the
 * scan quadratic. An object still open at the end runs to the end.
 */
function inlinedSpans(text, keys) {
  const spans = [];
  const stack = [];
  let openKeyed = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < text.length && text[j] !== c) j += text[j] === "\\" ? 2 : 1;
      i = j;
    } else if (c === "/" && text[i + 1] === "/") {
      const nl = text.indexOf("\n", i);
      i = nl === -1 ? text.length : nl;
    } else if (c === "/" && text[i + 1] === "*") {
      const e = text.indexOf("*/", i + 2);
      i = e === -1 ? text.length : e + 1;
    } else if (c === "{") {
      const key = keyBefore(text, i);
      const keyed = key !== null && keys.has(key);
      stack.push({ at: i, keyed, key, outer: keyed && openKeyed === 0 });
      if (keyed) openKeyed++;
    } else if (c === "}" && stack.length) {
      const o = stack.pop();
      if (o.keyed) openKeyed--;
      if (o.outer) spans.push({ start: o.at, end: i, key: o.key });
    }
  }
  for (const o of stack) if (o.outer) spans.push({ start: o.at, end: text.length, key: o.key });
  return spans.sort((a, b) => a.start - b.start);
}

/** The `name` of a `name: {` before position `i`, read backwards a bounded way, or null. */
function keyBefore(text, i) {
  let j = i - 1;
  while (j >= 0 && /\s/.test(text[j]) && i - j < 200) j--;
  if (text[j] !== ":") return null;
  j--;
  while (j >= 0 && /\s/.test(text[j]) && i - j < 400) j--;
  if (text[j] === '"' || text[j] === "'") j--;
  const end = j + 1;
  while (j >= 0 && end - j <= 32 && /[A-Za-z0-9_]/.test(text[j])) j--;
  return end > j + 1 ? text.slice(j + 1, end) : null;
}

/** Next's `env` / `publicRuntimeConfig` and Vite's `define` / `envPrefix`: what they put in the bundle. */
function buildConfigExposures(text, kind, { usesSupabase = false } = {}) {
  const hits = [];
  const spans = inlinedSpans(text, new Set(kind === "next" ? ["env", "publicRuntimeConfig"] : ["define"]));
  // The whole environment inlined: `...process.env` in Next's env, or a `process.env` /
  // `import.meta.env` key in Vite's define. Then the service-role key ships if it is set.
  if (usesSupabase) {
    // Names that hold the whole environment: process.env, import.meta.env, and any variable set from them or from loadEnv.
    const envVars = new Set(["process.env", "import.meta.env"]);
    for (const m of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*(?:await\s+)?(?:process\.env\b|import\.meta\.env\b|loadEnv\s*\()/g)) envVars.add(m[1]);
    // Escape every regex metacharacter, backslash included (CodeQL js/incomplete-sanitization).
    const ident = [...envVars].map((v) => v.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")).join("|");
    const whole = new RegExp(String.raw`\.\.\.\s*(?:${ident})\b|["'\x60]?(?:process\.env|import\.meta\.env)["'\x60]?\s*:|JSON\.stringify\(\s*(?:${ident})\s*\)`);
    for (const sp of spans) {
      const m = whole.exec(text.slice(sp.start, sp.end + 1));
      if (m) hits.push({ index: sp.start, whole: true, what: `\`${sp.key}\` puts the whole environment (\`${m[0].replace(/\s+/g, " ").trim()}\`) in the client bundle, the service-role key included when it is set` });
    }
    // Vite: loadEnv with an empty prefix loads every variable. A define built by code rather than
    // written as an object (Object.fromEntries over it) can't be read here, so it counts as inlining it.
    // A plain-object define was read above: one that picks single values (env.npm_package_version) is fine.
    const empty = kind === "vite" ? /\bloadEnv\s*\([^;\n]{0,300}?,\s*(["'`])\1\s*\)/.exec(text) : null;
    if (empty && /\bdefine\s*:(?!\s*\{)/.test(text) && !hits.some((h) => h.whole)) {
      hits.push({ index: empty.index, whole: true, what: "`loadEnv` with an empty prefix loads every env var, and `define` builds client constants from them, so the service-role key can reach the bundle" });
    }
  }
  if (spans.length) {
    // Every service-role name in the file, then: is it inside an outermost span? Spans don't overlap.
    const name = /[A-Za-z_][A-Za-z0-9_]{0,100}/g;
    let k = 0;
    const reported = new Set();
    for (let n; (n = name.exec(text));) {
      while (k < spans.length && spans[k].end < n.index) k++;
      if (k === spans.length) break;
      const sp = spans[k];
      if (n.index > sp.start && isServiceRoleName(n[0]) && !reported.has(sp.start)) {
        reported.add(sp.start);
        hits.push({ index: sp.start, what: `\`${sp.key}\` puts \`${n[0]}\` in the client bundle` });
      }
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
  const state = { open: null };
  const tokens = [...tokenStream(text, state)];
  return { tokens, open: state.open };
}

/**
 * PostgreSQL keeps the first 63 bytes of an identifier (NAMEDATALEN - 1) and drops the rest, so two
 * names that share those bytes are one table. Penthera does the same, cut on a character boundary:
 * then every key, policy key and digest entry built from names is bounded (Vercel, PR 312: a
 * multi-MiB quoted name renamed into thousands of policy keys exhausted the heap).
 */
export const PG_IDENT_BYTES = 63;
/** Characters read into a name before it is cut; enough for 63 bytes of any UTF-8. */
const IDENT_KEEP = 256;
/** A name longer than this in the source is no real name: the file is marked not fully checked. */
export const MAX_IDENT_CHARS = 1024;
/**
 * A copy of a string that doesn't point into a larger one. V8 keeps a slice of 13 or more
 * characters as a view of its source, so a kept table name would hold a whole migration in memory
 * (review of PR 312: 80 migrations of 15 MB peaked at 1.4 GB). The concatenation flattens it.
 */
export const own = (x) => (" " + x).slice(1);
export function pgIdent(v) {
  if (v.length <= PG_IDENT_BYTES / 4 || Buffer.byteLength(v) <= PG_IDENT_BYTES) return own(v);
  let bytes = 0;
  let out = "";
  for (const ch of v) {
    const b = Buffer.byteLength(ch);
    if (bytes + b > PG_IDENT_BYTES) break;
    bytes += b;
    out += ch;
  }
  return own(out);
}

/** The tokens of sqlTokens, one at a time; `state.open` is set when the text ends inside something. */
function* tokenStream(text, state) {
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
      yield ({ t: "str", v: text.slice(escapes ? i + 2 : i + 1, j), at: i });
      i = j + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let v = "";
      let done = false;
      let length = 0;
      while (j < n) {
        const k = text.indexOf('"', j);
        if (k === -1) break;
        // Only the start is kept (PostgreSQL keeps 63 bytes); the length is still counted.
        length += k - j;
        if (v.length < IDENT_KEEP) v += text.slice(j, Math.min(k, j + IDENT_KEEP));
        if (text[k + 1] === '"') { length++; if (v.length < IDENT_KEEP) v += '"'; j = k + 2; continue; }
        j = k;
        done = true;
        break;
      }
      if (!done) { open = "identifier"; break; }
      if (length > MAX_IDENT_CHARS) state.longIdent ??= i;
      // PostgreSQL rejects NUL in an identifier; here it would split the NUL-joined keys, so it becomes U+FFFD.
      yield ({ t: "word", v: pgIdent(v.replaceAll("\u0000", "\uFFFD")), quoted: true, at: i });
      i = j + 1;
      continue;
    }
    if (c === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]{0,62})?\$/.exec(text.slice(i, i + 65));
      if (m && !(i > 0 && /[A-Za-z0-9_]/.test(text[i - 1]))) {
        const close = text.indexOf(m[0], i + m[0].length);
        if (close === -1) { open = "body"; yield ({ t: "body", v: text.slice(i + m[0].length), at: i }); break; }
        yield ({ t: "body", v: text.slice(i + m[0].length, close), at: i });
        i = close + m[0].length;
        continue;
      }
      yield ({ t: "op", v: "$", at: i });
      i++;
      continue;
    }
    if (/[A-Za-z_\u0080-￿]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$\u0080-￿]/.test(text[j])) j++;
      if (j - i > MAX_IDENT_CHARS) state.longIdent ??= i;
      // PostgreSQL folds only ASCII A-Z in an unquoted name (in UTF-8): ÄRGER stays ÄRGER.
      yield ({ t: "word", v: pgIdent(text.slice(i, Math.min(j, i + IDENT_KEEP)).replace(/[A-Z]+/g, (x) => x.toLowerCase())), at: i });
      i = j;
      continue;
    }
    if (c >= "0" && c <= "9") {
      let j = i + 1;
      while (j < n && /[0-9.eE]/.test(text[j])) j++;
      yield ({ t: "num", v: text.slice(i, j), at: i });
      i = j;
      continue;
    }
    yield ({ t: "op", v: c, at: i });
    i++;
  }
  state.open = open;
}

/**
 * Tables and policies tracked across one project's migrations. A real project has a few hundred;
 * past this the reader stops, keeps what it found and says the scan is incomplete, so a crafted
 * migration of short CREATE TABLEs can't grow memory or findings without bound (Vercel, PR 312).
 */
export const MAX_TRACKED_OBJECTS = 50_000;
/** Tables or policies named one by one in a grouped finding; the rest are counted. */
const GROUP_NAMES = 20;

/** A statement longer than this keeps its first tokens (its kind and name) and is marked: memory stays bounded. */
export const MAX_STATEMENT_TOKENS = 20_000;

/**
 * Statements, one at a time: token runs between top-level semicolons. Only
 * one statement is held in memory. A longer one keeps its first
 * MAX_STATEMENT_TOKENS tokens and comes with `cut: true`.
 */
function* statementStream(text, state) {
  let cur = [];
  let cut = false;
  for (const t of tokenStream(text, state)) {
    state.last = t;
    if (t.t === "op" && t.v === ";") {
      if (cur.length) yield { s: cur, cut };
      cur = [];
      cut = false;
    } else if (cur.length < MAX_STATEMENT_TOKENS) cur.push(t);
    else cut = true;
  }
  if (cur.length) yield { s: cur, cut };
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

/**
 * The `[api] schemas = [...]` list of a supabase/config.toml, or null. Read
 * line by line in one pass: a regex with ^ and /m over the whole file was
 * quadratic on blank lines (blind review, row 15).
 */
export function exposedSchemas(toml) {
  let inApi = false;
  let collecting = null;
  for (const raw of toml.split("\n")) {
    const line = raw.trim();
    if (collecting !== null) {
      collecting += " " + line;
      if (line.includes("]")) break;
      if (collecting.length > 4000) return null;
      continue;
    }
    if (/^\[[^\]]*\]$/.test(line)) { inApi = line === "[api]"; continue; }
    if (inApi && /^schemas\s*=/.test(line)) {
      collecting = line.slice(line.indexOf("=") + 1);
      if (line.includes("]")) break;
    }
  }
  if (collecting === null) return null;
  const list = collecting.slice(collecting.indexOf("[") + 1, collecting.indexOf("]") === -1 ? undefined : collecting.indexOf("]"));
  // Cut like names in SQL (63 bytes), so a long schema here still matches its tables there.
  // Any length (the list is at most 4,000 characters): a long name is cut, never dropped.
  return [...list.matchAll(/["']([^"'\n]+)["']/g)].map((x) => pgIdent(x[1].slice(0, IDENT_KEEP)));
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
  // One entry per file and reason, with a count: 200k DO blocks are one line in the report.
  const uncheckedBy = new Map();
  const unchecked = { push: (u) => {
    const k = `${u.file}|${u.why}`;
    const seen = uncheckedBy.get(k);
    if (seen) seen.count++;
    else uncheckedBy.set(k, { ...u, count: 1 });
  } };
  let overTracked = false;
  let stoppedAt = null; // the file where the cap or the budget stopped full reading
  // Past the cap, a cheap pass still collects new tables in exposed schemas (bounded), so the cap
  // can't hide a real unprotected table behind 50,000 harmless ones (review of PR 312).
  // Names are hashed as they come (in migration order), and up to MAX_OVERFLOW are kept by name,
  // those with private-looking columns in a list of their own so they are named first.
  const overflow = { sensitive: [], names: [], count: 0, file: null, line: 0, hash: createHash("sha256") };
  const MAX_OVERFLOW = 1000;
  // kind "table" names one table; "all" and "future" stand for every (future) table of a schema,
  // shown as a fixed label, and hashed with their kind so a table literally named "*" is distinct.
  const noteOverflow = (q, rel, at, sensitive = false, kind = "table") => {
    const k = kind === "table" ? `${shown(q.schema)}.${shown(q.name)}` : `${shown(q.schema)}.* (${kind === "future" ? "future tables" : "all tables"})`;
    overflow.count++;
    overflow.hash.update(JSON.stringify([kind, q.schema, q.name]) + "\n");
    const list = sensitive ? overflow.sensitive : overflow.names;
    if (list.length < MAX_OVERFLOW) list.push(k);
    if (!overflow.file) { overflow.file = rel; overflow.line = at; }
  };
  const defaultRevoked = new Set(); // schemas whose future tables anon and authenticated can't reach
  let steps = 0;
  // A file is { rel, text } or { rel, size, read() }: read() returns its text, or null when it can't
  // be read (the caller marks that incomplete). Then only one migration is in memory at a time (row 4).
  const limit = budget ?? files.reduce((a, f) => a + (f.size ?? f.text.length), 0) * 20 + 1_000_000;
  let overBudget = false;
  let dynamicRls = false;
  const charge = (k) => { steps += k; if (steps > limit) overBudget = true; return overBudget; };

  for (const f of files) {
    const rel = f.rel;
    const text = f.read ? f.read() : f.text;
    if (text == null) continue;
    const starts = lineStarts(text);
    const line = (t) => lineAt(starts, t.at);
    // The tokenizer is one pass by construction; the budget counts the statement work after it.
    const state = { open: null, last: null };
    let searchPath = "public";
    let localPath = null; // SET LOCAL lasts until the transaction ends
    const qualify = (parts) => (parts.length >= 2 ? { schema: parts.at(-2), name: parts.at(-1) } : { schema: localPath ?? searchPath, name: parts[0] });
    // NUL can't occur in a PostgreSQL identifier, so it joins schema and name unambiguously:
    // public."x.y" and "public.x".y are different tables (review of PR 312).
    const key = (q) => `${q.schema}\u0000${q.name}`;

    for (const { s, cut } of statementStream(text, state)) {
      if (charge(s.length)) { stoppedAt ??= rel; break; }
      if (!overTracked && tables.size + policies.size > MAX_TRACKED_OBJECTS) { overTracked = true; stoppedAt ??= rel; }
      if (overTracked) {
        // Past the cap, nothing new is tracked. Instead, on purpose broadly, every statement that
        // can leave a table in an exposed schema reachable is noted: CREATE TABLE (a known name
        // too: it may have been dropped), DISABLE RLS, SET SCHEMA or RENAME into an exposed
        // schema, a policy with `true` in it, and GRANT (also default privileges) to anon,
        // authenticated or public. Noted tables are reported at potential on an incomplete scan;
        // search_path and transactions are still followed (below).
        if (isWord(s[0], "create", "alter") && isWord(s[1], "policy")) {
          const onAt = s.findIndex((t, k) => k > 1 && isWord(t, "on"));
          const nm = onAt !== -1 && nameAt(s, onAt + 1);
          const q = nm && qualify(nm.parts);
          // The full parser's reading of USING and WITH CHECK (so `1 = 1` counts), and any `true` besides.
          const p = { using: null, check: null, roles: [], permissive: true, command: "all" };
          if (nm) readPolicyClauses(s, nm.next, p);
          const open = !!p.using?.open || !!p.check?.open || s.some((t) => isWord(t, "true"));
          if (q && exposed.has(q.schema) && open) noteOverflow(q, rel, line(s[0]));
          continue;
        }
        if (isWord(s[0], "create")) {
          let i = 1;
          while (isWord(s[i], "or", "replace", "global", "local", "unlogged")) i++;
          if (isWord(s[i], "table")) {
            i++;
            if (isWord(s[i], "if") && isWord(s[i + 1], "not") && isWord(s[i + 2], "exists")) i += 3;
            const nm = nameAt(s, i);
            const q = nm && qualify(nm.parts);
            if (q && exposed.has(q.schema)) {
              const body = parenAt(s, nm.next);
              noteOverflow(q, rel, line(s[0]), !!body && body.inner.some((t) => t.t === "word" && SENSITIVE_COLUMN.test(t.v)));
            }
          }
          continue;
        }
        if (isWord(s[0], "alter") && isWord(s[1], "table")) {
          let i = 2;
          if (isWord(s[i], "if") && isWord(s[i + 1], "exists")) i += 2;
          if (isWord(s[i], "only")) i++;
          const nm = nameAt(s, i);
          if (!nm) continue;
          const q = qualify(nm.parts);
          const known = tables.get(key(q));
          for (let j = nm.next; j < s.length; j++) {
            if (isWord(s[j], "disable") && isWord(s[j + 1], "row") && isWord(s[j + 2], "level") && isWord(s[j + 3], "security") && exposed.has(q.schema)) {
              noteOverflow(q, rel, line(s[0]));
              break;
            }
            const moved = isWord(s[j], "set") && isWord(s[j + 1], "schema") && s[j + 2]?.t === "word" ? { schema: s[j + 2].v, name: q.name }
              : isWord(s[j], "rename") && isWord(s[j + 1], "to") && s[j + 2]?.t === "word" ? { schema: q.schema, name: s[j + 2].v } : null;
            // A table known to have RLS keeps it when moved; one without it, or unknown, is noted.
            if (moved && exposed.has(moved.schema) && !(known && known.rls)) { noteOverflow(moved, rel, line(s[0])); break; }
          }
          continue;
        }
        const def = isWord(s[0], "alter") && isWord(s[1], "default") && isWord(s[2], "privileges");
        const g = def ? s.findIndex((t) => isWord(t, "grant")) : isWord(s[0], "grant") ? 0 : -1;
        if (g !== -1) {
          const on = s.findIndex((t, k) => k > g && isWord(t, "on"));
          const to = s.findIndex((t, k) => k > on && on !== -1 && isWord(t, "to"));
          if (on === -1 || to === -1) continue;
          // Roles as the full parser reads them: a quoted "anon" is anon.
          if (!s.slice(to + 1).some((t) => t.t === "word" && POLICY_ROLES.has(t.v))) continue;
          const inSchema = s.findIndex((t) => isWord(t, "schema"));
          if (def || (isWord(s[on + 1], "all") && isWord(s[on + 2], "tables"))) {
            const sch = inSchema !== -1 && s[inSchema + 1]?.t === "word" ? s[inSchema + 1].v : "public";
            if (exposed.has(sch)) noteOverflow({ schema: sch, name: null }, rel, line(s[0]), false, def ? "future" : "all");
            continue;
          }
          let i = on + 1;
          if (isWord(s[i], "table")) i++;
          while (i < to) {
            const nm = nameAt(s, i);
            if (!nm) break;
            const q = qualify(nm.parts);
            if (exposed.has(q.schema)) noteOverflow(q, rel, line(s[0]));
            i = nm.next;
            if (!isOp(s[i], ",")) break;
            i++;
          }
          continue;
        }
        if (!isWord(s[0], "set", "reset", "select", "commit", "end", "rollback", "abort")) continue;
      }
      // A cut statement may hide what matters (a DISABLE at its end): the scan is incomplete too (row 1).
      if (cut) unchecked.push({ file: rel, line: line(s[0]), why: `has a statement over ${MAX_STATEMENT_TOKENS} tokens, and Penthera read only its start`, incomplete: true });
      // Dynamic SQL: a DO block or function body that builds a table or changes RLS.
      const isDo = isWord(s[0], "do");
      for (const t of s) {
        // A function or DO body: $tag$ … $tag$, or a plain string after DO.
        if (t.t !== "body" && !(isDo && t.t === "str")) continue;
        const enables = /\benable\s+row\s+level\s+security\b/i.test(t.v);
        if (enables || /\b(?:create\s+(?:(?:unlogged|temp|temporary)\s+)?table|disable\s+row\s+level\s+security)\b/i.test(t.v) ||
          (/\bexecute\b/i.test(t.v) && /\bcreate\b/i.test(t.v))) {
          // Turning RLS on in a loop is common; then a table here may be covered, so its finding drops to potential.
          if (enables) dynamicRls = true;
          unchecked.push({ file: rel, line: line(t), why: "creates a table or changes row-level security inside a function or DO block, which Penthera doesn't read" });
          break;
        }
      }
      const w0 = s[0];
      if (!isWord(w0)) continue;

      if (isWord(w0, "commit", "end", "rollback", "abort")) { localPath = null; continue; }
      if (w0.v === "reset" && isWord(s[1], "search_path", "all")) { searchPath = "public"; localPath = null; continue; }
      if (w0.v === "set" || (w0.v === "select" && s.some((t) => t.t === "str" && t.v === "search_path"))) {
        let i = 1;
        const local = isWord(s[i], "local");
        if (isWord(s[i], "session", "local")) i++;
        if (w0.v === "set" && isWord(s[i], "search_path")) {
          i++;
          if (isWord(s[i], "to") || isOp(s[i], "=")) i++;
          const first = s.slice(i).find((t) => (t.t === "word" || t.t === "str") && t.v !== "$user" && !isOp(t, ","));
          // DEFAULT (and an empty path) is the server default: public.
          const path = first && first.v !== "" && !(first.t === "word" && !first.quoted && first.v === "default") ? pgIdent(first.v.slice(0, IDENT_KEEP)) : "public";
          if (local) localPath = path; else searchPath = path;
        } else if (w0.v === "select") {
          const idx = s.findIndex((t) => t.t === "str" && t.v === "search_path");
          const val = s.slice(idx + 1).find((t) => t.t === "str");
          const first = val ? val.v.split(",").map((x) => x.trim().replace(/^"|"$/g, "")).find((x) => x && x !== "$user") : null;
          // set_config(name, value, is_local): true lasts until the transaction ends, like SET LOCAL.
          const isLocal = isWord(s.slice(s.indexOf(val) + 1).find((t) => t.t === "word"), "true");
          const sp = first ? pgIdent(first.slice(0, IDENT_KEEP)) : "public";
          if (isLocal) localPath = sp; else searchPath = sp;
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
                // Only the names the report mentions are kept, at most 8: memory per table stays small.
                if (!isWord(t, "constraint", "primary", "foreign", "unique", "check", "exclude", "like") && columns.length < 8 && SENSITIVE_COLUMN.test(t.v)) columns.push(t.v);
                expect = false;
              }
            }
          }
          // A table that exists already keeps its state: IF NOT EXISTS does nothing, and a second CREATE fails.
          if (!tables.has(key(q))) tables.set(key(q), { ...q, file: rel, line: line(s[0]), rls: false, revoked: defaultRevoked.has(q.schema), columns });
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
          policies.set(`${p.table}\u0000${p.name}`, p);
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
          } else if ((isWord(s[j], "rename") && isWord(s[j + 1], "to") && s[j + 2]?.t === "word") || (isWord(s[j], "set") && isWord(s[j + 1], "schema") && s[j + 2]?.t === "word")) {
            const from = t ? { schema: t.schema, name: t.name } : q;
            const to = s[j].v === "rename" ? { schema: from.schema, name: s[j + 2].v } : { schema: s[j + 2].v, name: from.name };
            if (t) { tables.delete(key(from)); Object.assign(t, to); tables.set(key(t), t); }
            // Policies go with their table.
            if (charge(policies.size)) break;
            for (const [pk, p] of [...policies]) {
              if (p.table !== key(from)) continue;
              policies.delete(pk);
              p.table = key(to);
              policies.set(`${p.table}\u0000${p.name}`, p);
            }
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
        const p = policies.get(`${key(q)}\u0000${name.v}`);
        if (!p) continue;
        if (isWord(s[nm.next], "rename") && isWord(s[nm.next + 1], "to") && s[nm.next + 2]?.t === "word") {
          policies.delete(`${p.table}\u0000${p.name}`);
          p.name = s[nm.next + 2].v;
          policies.set(`${p.table}\u0000${p.name}`, p);
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
        if (nm) policies.delete(`${key(qualify(nm.parts))}\u0000${name.v}`);
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
          // Only defaults for tables, and only for the role that runs migrations (postgres), touch the tables made here.
          if (!isWord(s[on + 1], "tables")) continue;
          const fr = s.findIndex((t, k) => k < g && isWord(t, "for") && isWord(s[k + 1], "role", "user"));
          if (fr !== -1) {
            const owners = [];
            for (let k = fr + 2; k < g && !isWord(s[k], "in"); k++) if (s[k].t === "word") owners.push(s[k].v);
            if (!owners.every((r) => r === "postgres")) continue;
          }
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
    if (state.open) unchecked.push({ file: rel, line: state.last ? line(state.last) : 1, why: `ends inside a ${state.open}, so Penthera read it only up to there` });
    if (state.longIdent != null) unchecked.push({ file: rel, line: lineAt(starts, state.longIdent), why: `has a name over ${MAX_IDENT_CHARS} characters; PostgreSQL keeps its first ${PG_IDENT_BYTES} bytes, and so does Penthera`, incomplete: true });
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
    const openUsing = !!p.using?.open;
    // Without WITH CHECK, an ALL or UPDATE policy checks new rows with its USING (PostgreSQL docs):
    // dropping WITH CHECK can open it, so the effective check is what counts (review of PR 312).
    const check = p.check ?? (p.command === "all" || p.command === "update" ? p.using : null);
    const openCheck = !!check?.open;
    if (!openUsing && !openCheck) continue;
    const [schema, name] = p.table.split("\u0000");
    if (!exposed.has(schema)) continue;
    const t = tables.get(p.table);
    if (t && t.revoked) continue;
    findings.push({ kind: "policy", policy: p, roles, openUsing, openCheck, checkImplied: p.check == null, table: t || { schema, name, columns: [] } });
  }
  return { findings, unchecked: [...uncheckedBy.values()], overBudget, overTracked, overflow, stoppedAt, dynamicRls };
}

/**
 * FOR, TO, AS, USING and WITH CHECK of a CREATE or ALTER POLICY, from s[i] on. Only a summary is
 * kept, never the tokens (Vercel, PR 312: thousands of policies with ~20,000-token expressions held
 * millions of token objects): a clause is { open } (is it always true?), and roles are only the
 * ones that matter (public, anon, authenticated), each once. A stored
 * policy is then a few hundred bytes, and the 50,000-object cap bounds them all.
 */
function readPolicyClauses(s, i, p) {
  for (let j = i; j < s.length; j++) {
    if (isWord(s[j], "as") && isWord(s[j + 1], "permissive", "restrictive")) { p.permissive = s[j + 1].v === "permissive"; j++; } else if (isWord(s[j], "for") && isWord(s[j + 1], "all", "select", "insert", "update", "delete")) { p.command = s[j + 1].v; j++; } else if (isWord(s[j], "to")) {
      const roles = new Set();
      let k = j + 1;
      while (k < s.length && !isWord(s[k], "using", "with")) {
        if (s[k].t === "word" && POLICY_ROLES.has(s[k].v)) roles.add(s[k].v);
        k++;
      }
      p.roles = [...roles];
      j = k - 1;
    } else if (isWord(s[j], "using")) {
      const par = parenAt(s, j + 1);
      if (par) { p.using = { open: alwaysTrue(par.inner) }; j = par.next - 1; }
    } else if (isWord(s[j], "with") && isWord(s[j + 1], "check")) {
      const par = parenAt(s, j + 2);
      if (par) { p.check = { open: alwaysTrue(par.inner) }; j = par.next - 1; }
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
 * A short digest of a set of names, in the title of a grouped finding. The finding's id comes
 * from its title, so a suppression covers exactly this set: a new or swapped table gives a new
 * id and shows again (review of PR 312).
 */
function digestOf(names) {
  // 16 hex characters (64 bits): too many to search for a swapped set that keeps the same digest.
  // Each entry is JSON (newlines escaped), so joining sorted entries with "\n" is unambiguous.
  return createHash("sha256").update([...names].sort().join("\n")).digest("hex").slice(0, 16);
}

/**
 * What an open policy grants, in the words of its finding's title: command, roles (sorted) and the
 * clauses that are always true, e.g. "ALL to anon, authenticated; USING true, WITH CHECK true".
 * It is part of the finding's id, so broadening a policy (SELECT to ALL, adding a role, opening WITH
 * CHECK) changes the id and the finding is reported again, past a baseline or a suppression.
 */
function policyGrant(f) {
  const clauses = [f.openUsing && "USING true", f.openCheck && "WITH CHECK true"].filter(Boolean).join(", ");
  // Only the roles that matter (public, anon, authenticated), so the text is short and a quoted
  // role such as "authenticated, x" can't make two different lists read the same.
  return `${f.policy.command.toUpperCase()} to ${[...new Set(f.roles)].sort().join(", ")}; ${clauses}`;
}

/**
 * A name as a title shows it. The title is the finding's id (lib/audit-loop.js), so this must be
 * one-to-one: two different names never show alike (Vercel, PR 312: shortened names could
 * impersonate an accepted finding). A plain name (lowercase letters, digits, _ $ -, at most 80)
 * shows as it is. Any other name (longer, with an uppercase letter, a dot, quote, backtick, space,
 * newline or "…") shows a
 * cleaned 48-character prefix, "…", and 16 hex characters of the SHA-256 of the whole name. A plain
 * name has no "…", so it can't look like a shortened one, and two shortened names look alike only
 * if their 64-bit hashes match.
 */
export function shown(name) {
  // Lowercase only: finding ids lowercase the title, and a quoted "Users" is another table than users.
  if (/^[a-z0-9_$-]{1,80}$/.test(name)) return name;
  const prefix = name.slice(0, 48).replace(/[^\w$-]/g, "?");
  return `${prefix}…${createHash("sha256").update(name).digest("hex").slice(0, 16)}`;
}

/** The worst first: items with private-looking columns, then by line. */
function rankItems(items) {
  return items.slice().sort((a, b) => (b.sensitive.length > 0) - (a.sensitive.length > 0) || a.line - b.line);
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
  const { files, packages, projects, skipped, aliases } = walk(root, ignoredDirs);
  const apps = appsOf(root, packages);
  // The whole-env checks below are about Supabase only in a project that uses it: a supabase/
  // folder, an @supabase/ package, or code that names Supabase (a client loaded from a CDN).
  let usesSupabase = projects.length > 0 || apps.some((a) => a.supabase);
  const configs = [];
  const findings = [];
  const incomplete = [...skipped];

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
  // Hits per file and kind, with their lines (capped): a file with a million keys costs one entry (row 13).
  const keyHits = new Map();
  const envReads = new Map();
  const publicNames = new Map();
  // Env names are grouped per file as they come: a .env with 200k distinct names is one entry with
  // at most MAX_NAMES_PER_FILE names, and the repo keeps at most MAX_NAMES_TOTAL (Vercel, PR 312).
  // Each kind (public names, client reads) has its own budget, so names that are never reported
  // can't use up the budget of ones that are. At most MAX_NAME_GROUPS files per kind get a finding
  // of their own; the rest are counted into one overflow finding that names the first of them.
  const budgets = new Map();
  const rememberName = (map, file, name, line, extra) => {
    const b = budgets.get(map) || budgets.set(map, { total: 0, overflow: { count: 0, files: [], line: 0, cut: new Map() } }).get(map);
    let g = map.get(file);
    if (!g) {
      if (map.size >= MAX_NAME_GROUPS) {
        const o = b.overflow;
        // Distinct files are counted up to MAX_NAME_GROUPS more; past that the count reads "N+".
        if (o.cut.has(file)) return;
        if (o.cut.size >= MAX_NAME_GROUPS) { o.more = true; return; }
        o.cut.set(file, { file, line, ...extra });
        o.count++;
        if (!extra.test) o.nonTest = true;
        if (o.files.length < GROUP_NAMES) o.files.push({ file, line, ...extra });
        return;
      }
      g = { file, names: new Map(), lines: [], cut: false, ...extra };
      map.set(file, g);
    }
    // The line is kept whatever the name budget says, and a file's first name always is.
    if (g.lines.length < MAX_LINES_PER_FINDING && !g.lines.includes(line)) g.lines.push(line);
    if (g.names.has(name)) return;
    if (g.names.size > 0 && (g.names.size >= MAX_NAMES_PER_FILE || b.total >= MAX_NAMES_TOTAL)) { g.cut = true; return; }
    b.total++;
    g.names.set(name, line);
  };
  const remember = (map, k, entry) => {
    const seen = map.get(k);
    if (!seen) map.set(k, { ...entry, lines: [entry.line] });
    else if (seen.lines.length < MAX_LINES_PER_FINDING && !seen.lines.includes(entry.line)) seen.lines.push(entry.line);
  };
  for (const file of files) {
    const fd = openRegular(file.full);
    if (!fd) continue;
    const name = file.rel.split("/").pop();
    const ext = extOf(name);
    const code = CODE_EXT.has(ext);
    const env = isEnvFile(name);
    const local = ignoredFiles.has(file.full);
    const test = isTestPath(file.rel);
    const fi = { rel: file.rel, code, ext, html: HTML_EXT.has(ext), directive: null, serverOnly: false, imports: [], frontmatterEnd: -1 };
    // A route handler, an Edge Function or a "use server"/server-only module: its env reads never ship.
    const serverFile = () => fi.serverOnly || isServerPath(inApp(appOf(apps, file.rel), file.rel));
    info.set(file.rel, fi);
    try {
      for (const { text, linesBefore, first } of chunksOf(fd.fd, fd.size)) {
        let starts = null;
        const at = (index) => linesBefore + lineAt((starts ??= lineStarts(text)), index);
        if (code && !usesSupabase && /supabase/i.test(text)) usesSupabase = true;
        if (first && ext === ".astro") {
          // An Astro file's frontmatter (between the --- fences) runs on the server; the rest renders for the browser.
          const open = /^\s*---/.exec(text.slice(0, 1024));
          const close = open ? text.indexOf("\n---", open[0].length) : -1;
          fi.frontmatterEnd = open ? (close === -1 ? text.length : close + 4) : 0;
        }
        if (first && code) {
          fi.directive = directiveOf(text.slice(0, 4096));
          fi.serverOnly = SERVER_ONLY_IMPORT.test(text.slice(0, 64 * 1024)) || fi.directive === "server";
          if (fd.size <= MAX_IMPORT_PARSE_BYTES) fi.imports = importsOf(text);
        }
        if (first && fi.html && fd.size <= MAX_IMPORT_PARSE_BYTES) {
          // Script sources, each once and at most MAX_IMPORTS_PER_FILE, like imports.
          const srcs = new Set();
          for (const m of text.matchAll(/<script\b[^>]{0,500}?\bsrc\s*=\s*["']([^"'\s>]{1,300})["']/gi)) {
            if (srcs.size >= MAX_IMPORTS_PER_FILE) { srcs.cut = true; break; }
            srcs.add(own(m[1]));
          }
          fi.imports = [...srcs];
          if (srcs.cut) fi.imports.cut = true;
        }
        if (text.includes("eyJ") || text.includes("sb_secret_")) {
          for (const hit of findServiceKeys(text)) {
            const found = assignedName(text, hit.index);
            const name = found && own(found);
            const pub = name && publicPrefixOf(name);
            const astroClient = first && ext === ".astro" && fi.frontmatterEnd >= 0 && hit.index >= fi.frontmatterEnd;
            remember(keyHits, `${file.rel}|${hit.kind}|${hit.demo}|${pub || ""}|${astroClient}`, { file: file.rel, line: at(hit.index), hit, name, local, test, env, astroClient });
          }
        }
        if (code || env || fi.html || ext === ".json" || ext === ".toml" || ext === ".yml" || ext === ".yaml") {
          PUBLIC_NAME.lastIndex = 0;
          for (let m; (m = PUBLIC_NAME.exec(text));) {
            const end = identEnd(text, m.index);
            PUBLIC_NAME.lastIndex = end;
            const name = text.slice(m.index, Math.min(end, m.index + MAX_ENV_NAME));
            // A name past MAX_ENV_NAME is judged on the whole of it.
            if (isServiceRoleName(end - m.index > MAX_ENV_NAME ? text.slice(m.index, end) : name)) rememberName(publicNames, file.rel, own(name), at(m.index), { local, test, code });
          }
        }
        if (code) {
          ENV_READ.lastIndex = 0;
          for (let m; (m = ENV_READ.exec(text));) {
            const from = m.index + m[0].length;
            const end = identEnd(text, from);
            ENV_READ.lastIndex = end;
            const whole = end - from > MAX_ENV_NAME ? text.slice(from, end) : null;
            const name = text.slice(from, Math.min(end, from + MAX_ENV_NAME));
            if (isServiceRoleName(whole ?? name) && !publicPrefixOf(name)) {
              // A server-path file doesn't take a client-read slot (review of PR 312), but its first read
              // is kept on its own entry (one per file): if client code imports it, it is still reported.
              if (serverFile()) {
                if (!fi.firstRead) fi.firstRead = { name: own(name), line: at(m.index), test };
                else if (fi.firstRead.name !== name) fi.moreReads = true;
              } else rememberName(envReads, file.rel, own(name), at(m.index), { test });
            }
          }
        }
      }
    } finally {
      closeSync(fd.fd);
    }
    // A build config is read whole (row 14: an object can span any chunk edge), under the same cap as a migration.
    const base = name.replace(/\.[^.]+$/, "");
    const kind = !code ? null : base === "next.config" ? "next" : base === "vite.config" ? "vite" : null;
    if (kind) configs.push({ file, kind });
  }

  // Build configs, once every file has said whether the project uses Supabase.
  for (const { file, kind } of configs) {
    let whole;
    try {
      whole = readRepoFile(file.full, { root, maxBytes: maxSqlBytes, label: file.rel });
    } catch (e) {
      incomplete.push({ file: file.rel, reason: e.reason || e.message });
      continue;
    }
    const starts = lineStarts(whole);
    for (const x of buildConfigExposures(whole, kind, { usesSupabase })) {
      add(finding("supabase-service-role-exposed", "high", file.rel, lineAt(starts, x.index),
        "A build config puts the service-role key in the browser bundle",
        `\`${file.rel}\`: ${x.what}. A service-role key bypasses row-level security, and everything in the bundle ships to every visitor.`,
        `Remove the key from the build config and read it with process.env only in server code. ${KEY_FIX}`));
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
  /** Is the file at `rel` (with facts `fi`) client code by itself, before imports? */
  const shipsByItself = (rel, fi) => {
    const app = appOf(apps, rel);
    const own = inApp(app, rel);
    if (/(?:^|\/)(?:public|static)\//.test(own) && !/(?:^|\/)supabase\//.test(own)) return true;
    if (fi.html) return true;
    if (!fi.code || fi.serverOnly || isServerPath(own)) return false;
    if (fi.directive === "client") return true;
    // A Svelte or Vue component's script runs in the browser too (SvelteKit, Nuxt, a Vite app).
    if ((fi.ext === ".svelte" || fi.ext === ".vue") && !isTestPath(own)) return true;
    if (app?.next && /^(?:src\/)?pages\//.test(own)) return true;
    // A single-page or mobile app ships its source folders; other files count once client code imports them.
    return !!app?.spa && !isTestPath(own) && (/^(?:src|app|components|screens|hooks|pages)\//.test(own) || /^(?:App|index|main)\.[cm]?[jt]sx?$/.test(own));
  };
  for (const fi of info.values()) if (shipsByItself(fi.rel, fi)) seed(fi.rel);
  // A link inside the project ships its target when the link's own path ships.
  const fileAlias = new Map();
  const dirAliases = [];
  for (const a of aliases) {
    if (a.dir) { dirAliases.push(a); continue; }
    fileAlias.set(a.rel, a.target);
    const target = info.get(a.target);
    if (target && shipsByItself(a.rel, target)) seed(a.target);
  }
  // Folder links by their path, so a lookup walks the path's own prefixes (O(depth)), not every link.
  // The walk never enters a link, so links don't nest and at most one prefix matches.
  const dirAlias = new Map(dirAliases.map((a) => [a.rel, a.target]));
  const unalias = (rel) => {
    if (fileAlias.has(rel)) return fileAlias.get(rel);
    if (dirAlias.size) {
      for (let at = rel.indexOf("/"); at !== -1; at = rel.indexOf("/", at + 1)) {
        const target = dirAlias.get(rel.slice(0, at));
        if (target !== undefined) return target + rel.slice(at);
      }
    }
    return rel;
  };
  // Resolutions are cached by what they depend on (the joined path, or the app and the alias), and
  // all graph work is charged to a budget scaled to the input: past it, the walk stops, files not
  // yet reached count as server code (a key there is still reported, as committed), and the scan
  // is incomplete (Vercel, PR 312: directory links times imports multiplied the work).
  const resolved = new Map();
  const MAX_RESOLVED = 200_000;
  let graphWork = 0;
  // Each distinct import resolves once (the cache); the most one can cost is two candidates of
  // 32 plus their length, at most the importer's folder or app folder plus a 300-character
  // specifier. So the budget is that worst case for every import kept: a real repo never reaches
  // it, a crafted one is cut off before the work grows with links times imports.
  let graphBudget = 1_000_000;
  for (const x of info.values()) graphBudget += 1 + (x.imports ? x.imports.length : 0) * 2 * (32 + 300 + 8 + x.rel.length);
  const resolveSpec = (from, spec, appDir) => {
    let base;
    if (spec.startsWith(".")) base = posix.join(posix.dirname(from), spec);
    else if (spec.startsWith("/")) base = posix.join(appDir || ".", spec.slice(1)); // a root URL, as Vite serves it
    else base = null;
    const k = base ?? `${appDir}\u0000${spec}`;
    if (resolved.has(k)) { graphWork += 1; return resolved.get(k); }
    const candidates = base ? [base] : [posix.join(appDir, "src", spec.slice(2)), posix.join(appDir, spec.slice(2))];
    const r = resolveCandidates(candidates);
    if (resolved.size < MAX_RESOLVED) resolved.set(k, r);
    return r;
  };
  const resolveCandidates = (candidates) => {
    for (const c of candidates) {
      // Each candidate: one prefix walk (unalias) and a fixed number of lookups.
      graphWork += 32 + c.length;
      // Drop a ?query (Vite's ?raw, ?url): cut at the first "?", no regex (regexp/no-super-linear-move).
      const q = c.indexOf("?");
      const clean = unalias(q === -1 ? c : c.slice(0, q));
      if (info.has(clean)) return clean;
      for (const e of RESOLVE_EXT) { if (info.has(clean + e)) return clean + e; }
      for (const e of RESOLVE_EXT) { if (info.has(`${clean}/index${e}`)) return `${clean}/index${e}`; }
      // A .js specifier that names a .ts file (TypeScript's NodeNext style).
      const js = /\.[cm]?jsx?$/.exec(clean);
      if (js) for (const e of [".ts", ".tsx", ".mts", ".cts"]) { const t = clean.slice(0, -js[0].length) + e; if (info.has(t)) return t; }
    }
    return null;
  };
  let graphStopped = null;
  for (let q = 0; q < queue.length; q++) {
    const rel = queue[q];
    const fi = info.get(rel);
    if (fi.imports.cut) incomplete.push({ file: rel, partial: true, reason: `it has more than ${MAX_IMPORTS_PER_FILE} distinct imports, and only the first were followed to find client code` });
    const appDir = appOf(apps, rel)?.dir || "";
    if (graphWork > graphBudget) { graphStopped = rel; break; }
    for (const spec of fi.imports) {
      const to = resolveSpec(rel, spec, appDir);
      if (!to) continue;
      const target = info.get(to);
      // A "use server" module imported by a client file becomes a server action; its code stays on the server.
      if (target.serverOnly) continue;
      seed(to);
    }
  }

  if (graphStopped) incomplete.push({ file: graphStopped, partial: true, reason: "finding client code took more work than the project's size allows, so files reached from here on were not followed" });

  // Each remembered hit, once per line it was seen on: add() merges them into one finding.
  const each = (map) => [...map.values()].flatMap((e) => e.lines.map((line) => ({ ...e, line })));
  for (const k of each(keyHits)) {
    const what = describeKey(k.hit);
    const publicName = k.name && publicPrefixOf(k.name);
    const inClient = client.has(k.file) || k.astroClient;
    if (k.hit.demo) {
      add(finding("supabase-service-role-committed", "low", k.file, k.line,
        "Supabase's default local service-role key",
        `\`${k.file}\` holds ${what}, signed with the JWT secret every local Supabase stack uses (published in Supabase's docs). It opens nothing on Supabase's hosted platform, but it is full access to any self-hosted Supabase still running with that secret.`,
        "Fine for a local stack. If you self-host Supabase, generate your own JWT secret and keys, and keep them out of the repo.",
        "potential"));
      continue;
    }
    if (publicName || inClient) {
      // Client code git ignores still ships in any build made from this folder: high, not dropped.
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

  // One finding per file for env names: a file with one name reads as before; more are grouped,
  // with a count, the first GROUP_NAMES and a digest of every name kept (so the id follows the set).
  const nameGroup = (g, single, grouped) => {
    const names = [...g.names.keys()];
    const lines = g.lines.slice().sort((a, b) => a - b);
    const first = lines[0] ?? 1;
    if (g.cut) incomplete.push({ file: g.file, partial: true, reason: `it names more than ${g.names.size} distinct service-role env names, past the ${MAX_NAMES_PER_FILE}-per-file or ${MAX_NAMES_TOTAL}-per-repo limit, so the rest were not listed` });
    const f = names.length === 1 && !g.cut ? single(names[0], first) : grouped(names, first);
    f.lines = lines; // the same-line dedupe below reads it; a single line is dropped at the end
    findings.push(f);
  };
  const listNames = (names) => names.slice(0, GROUP_NAMES).map((n) => `\`${n}\``).join(", ") + (names.length > GROUP_NAMES ? ` and ${names.length - GROUP_NAMES} more` : "");
  for (const g of publicNames.values()) {
    // Inlined where client code reads it, or defined in an env or config file: high. Read only in
    // server code (a guard that refuses to start with it set, say), nothing is inlined: medium, potential.
    const ships = !g.code || client.has(g.file);
    const severity = !ships ? "medium" : g.local ? "medium" : "high";
    const confidence = g.test || !ships ? "potential" : "likely";
    const fix = `Rename it without the public prefix (for example SUPABASE_SERVICE_ROLE_KEY) and read it only in server code. If a build ever ran with it set, ${KEY_FIX.charAt(0).toLowerCase()}${KEY_FIX.slice(1)}`;
    const local = g.local ? " The file is ignored by git, so it isn't committed, but any build that loads it inlines the key." : "";
    nameGroup(g,
      (name, line) => finding("supabase-service-role-exposed", severity, g.file, line,
        `Service-role key under a public env name: \`${name}\``,
        ships
          ? `\`${g.file}\` uses \`${name}\`. The \`${publicPrefixOf(name)}\` prefix tells the build to inline the value into the browser bundle, so whatever key this holds ships to every visitor. A service-role key bypasses row-level security: with it, anyone can read and change every table.${local}`
          : `\`${g.file}\` reads \`${name}\` in code Penthera didn't find in the browser, so nothing is inlined from here. But the \`${publicPrefixOf(name)}\` prefix means any client file that reads it ships the key. If this is a check that refuses that name, it's fine.`,
        fix, confidence),
      (names, line) => finding("supabase-service-role-exposed", severity, g.file, line,
        `Service-role key under ${names.length}${g.cut ? "+" : ""} public env names in \`${g.file}\` (list ${digestOf(names)})`,
        `\`${g.file}\` uses ${g.cut ? "more than " : ""}${names.length} env names for the service-role key with a public prefix (NEXT_PUBLIC_, VITE_ and the like): ${listNames(names)}. ${ships ? "The build inlines each into the browser bundle, so whatever key they hold ships to every visitor." : "This is code Penthera didn't find in the browser, so nothing is inlined from here, but any client file that reads them ships the key."}${local}`,
        fix, confidence));
  }

  // Files past MAX_NAME_GROUPS for a kind: one finding at the worst severity that kind can have,
  // naming the first files, and the scan is incomplete (exit 2).
  const overflowOf = (map, kind) => {
    const o0 = budgets.get(map)?.overflow;
    if (!o0 || !o0.count) return;
    // Client reads only matter in client code: count the overflow files that are client code.
    const o = kind === "public env names" ? o0 : (() => {
      const kept = [...o0.cut.values()].filter((x) => client.has(x.file));
      return { ...o0, count: kept.length, files: kept.slice(0, GROUP_NAMES) };
    })();
    if (!o.count) {
      // None of the counted ones is client code; past the count Penthera can't tell.
      if (o0.more) incomplete.push({ file: o0.files[0].file, partial: true, reason: `more than ${MAX_NAME_GROUPS * 2} files read server-only service-role env names, so the rest were not checked one by one` });
      return;
    }
    const first = o.files[0];
    const n = `${o.count}${o.more ? "+" : ""}`;
    const files = o.files.map((x) => `\`${x.file}\``).join(", ") + (o.count > o.files.length ? ` and ${o.count - o.files.length}${o.more ? "+" : ""} more` : "");
    incomplete.push({ file: first.file, partial: true, reason: `${n} files past the ${MAX_NAME_GROUPS}-file limit for ${kind} were counted, not checked one by one` });
    findings.push(kind === "public env names"
      ? finding("supabase-service-role-exposed", "high", first.file, first.line,
        `${n} more files use public env names for the service-role key`,
        `Past ${MAX_NAME_GROUPS} files with public env names for the service-role key, ${n} more were counted, not checked one by one: ${files}. Each such name is inlined into the browser bundle wherever client code reads it.`,
        "Rename these without the public prefix and read them only in server code.", o.nonTest ? "likely" : "potential")
      : finding("supabase-service-role-exposed", "medium", first.file, first.line,
        `${n} more files read server-only service-role env names`,
        `Past ${MAX_NAME_GROUPS} files that read server-only service-role env names, ${n} more were counted, not checked one by one: ${files}. In client code such a read expects admin access in the browser.`,
        "Move calls that need the service-role key into server code.", "potential"));
  };
  overflowOf(publicNames, "public env names");
  overflowOf(envReads, "server-only env reads");

  // Server-path files that client code imports after all: their first read is reported.
  for (const fi of info.values()) {
    if (!fi.firstRead || !client.has(fi.rel) || envReads.has(fi.rel)) continue;
    const r = fi.firstRead;
    findings.push(finding("supabase-service-role-exposed", "medium", fi.rel, r.line,
      `Client code reads \`${r.name}\``,
      `\`${fi.rel}\` sits on a server path, but client code imports it, so it ships to the browser, and it reads \`${r.name}\`. Under a server-only name the value is undefined there unless a build config inlines it, and then the service-role key ships to every visitor.`,
      "Move the call that needs the service-role key into a route handler, server action or Edge Function, and don't import it from client code.", "potential"));
    if (fi.moreReads) incomplete.push({ file: fi.rel, partial: true, reason: "it reads more service-role env names than the first, which Penthera kept only for this one" });
  }

  for (const g of envReads.values()) {
    if (!client.has(g.file)) continue;
    const fix = "Move the call that needs the service-role key into a route handler, server action or Edge Function, and use the anon or publishable key in the browser.";
    nameGroup(g,
      (name, line) => finding("supabase-service-role-exposed", "medium", g.file, line,
        `Client code reads \`${name}\``,
        `\`${g.file}\` is client code and reads \`${name}\`. Under a server-only name the value is undefined in the browser, unless a build config inlines it, and then the service-role key ships to every visitor. Either way this code expects admin access in the browser.`,
        fix, "potential"),
      (names, line) => finding("supabase-service-role-exposed", "medium", g.file, line,
        `Client code reads ${names.length}${g.cut ? "+" : ""} service-role env names in \`${g.file}\` (list ${digestOf(names)})`,
        `\`${g.file}\` is client code and reads ${g.cut ? "more than " : ""}${names.length} server-only service-role env names: ${listNames(names)}. They are undefined in the browser unless a build config inlines them, and then the key ships to every visitor.`,
        fix, "potential"));
  }

  // ── Migrations ──
  let migrations = 0;
  const readSql = [];
  // Each SQL file belongs to one project, the nearest one (Vercel DoS 01M6ZKR6TN5K2H7AFAZ0SJR388):
  // nested supabase/ folders made every ancestor reparse the same migrations with a fresh
  // budget. Deepest projects claim their files first; an ancestor reads only what is left,
  // so a file in a nested folder without migrations/ is still read by its ancestor.
  const claimed = new Set();
  const depth = (p) => p.split("/").length;
  const ordered = projects.map((p, i) => [p, i]).sort((a, b) => depth(b[0]) - depth(a[0]) || a[1] - b[1]).map(([p]) => p);
  for (const project of ordered) {
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
        try { entries = readdirSync(join(root, dir), { withFileTypes: true }); } catch (e) {
          incomplete.push({ file: dir, reason: `the folder can't be read (${e.code || e.message})` });
          return;
        }
        for (const e of entries) {
          const rel = `${dir}/${e.name}`;
          if (e.isDirectory()) collect(rel);
          else if (extOf(e.name) === ".sql") { if (!claimed.has(rel)) { claimed.add(rel); list.push(rel); } }
          // A link here may be a folder of migrations: say so rather than pass it over (row 2).
          else if (e.isSymbolicLink()) incomplete.push({ file: rel, reason: "it is a symbolic link" });
        }
      };
      collect(d);
      // The CLI applies migrations in filename order; declarative schemas come after.
      list.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      for (const rel of list) sql.push(rel); // no spread: a folder can hold any number of files
    }
    // Read lazily, one file at a time, so memory holds one migration, not all of them (row 4).
    if (sql.length > MAX_SQL_FILES) incomplete.push({ file: sql[MAX_SQL_FILES], reason: `more than ${MAX_SQL_FILES} SQL files in ${project}; the rest were not read` });
    const lazy = sql.slice(0, MAX_SQL_FILES).map((rel) => {
      let size = 0;
      try { size = lstatSync(join(root, rel)).size; } catch { /* read() reports it */ }
      return {
        rel, size,
        read: () => {
          try {
            const text = readRepoFile(join(root, rel), { root, maxBytes: maxSqlBytes, label: rel });
            migrations++;
            readSql.push(rel);
            return text;
          } catch (e) {
            if (isRefused(e)) incomplete.push({ file: rel, reason: e.reason || e.message });
            else if (e.code !== "ENOENT") incomplete.push({ file: rel, reason: e.message });
            return null;
          }
        },
      };
    });
    const res = checkMigrations(lazy, { schemas });
    // Read, but not to the end: partial, so the report says "File not fully checked" (main's wording).
    for (const u of res.unchecked) if (u.incomplete) incomplete.push({ file: u.file, reason: u.why, partial: true });
    if (res.overBudget) incomplete.push({ file: project, partial: true, reason: "the migrations took more work than their size allows, so Penthera stopped reading them" });
    if (res.overTracked) incomplete.push({ file: res.stoppedAt || project, partial: true, reason: `the migrations define more than ${MAX_TRACKED_OBJECTS} tables and policies, so from this file on Penthera only noted new tables; the findings so far are kept` });
    // Files from where full reading stopped count as not read in Coverage (row 23).
    if (res.stoppedAt) {
      const from = readSql.indexOf(res.stoppedAt);
      if (from !== -1) { migrations -= readSql.length - from; readSql.length = from; }
    }
    if (res.overflow.count) {
      const o = res.overflow;
      const top = [...o.sensitive, ...o.names].slice(0, GROUP_NAMES);
      const shown = top.map((n) => `\`${n}\``).join(", ") + (o.count > top.length ? ` and ${o.count - top.length} more` : "");
      findings.push(finding("supabase-rls-disabled", "high", o.file, o.line,
        `${o.count} tables changed after Penthera's ${MAX_TRACKED_OBJECTS}-object limit (list ${o.hash.digest("hex").slice(0, 16)})`,
        `\`${o.file}\` and later migrations create, move or unprotect ${o.count} tables in exposed schemas after Penthera stopped tracking row-level security, so it can't tell whether a later migration protects them: ${shown}.`,
        "Check each for `alter table … enable row level security;` in a migration. Splitting generated SQL out of supabase/migrations lets the scan read the rest whole.",
        "potential"));
    }
    for (const u of res.unchecked) {
      const more = u.count > 1 ? ` (${u.count} times in this file)` : "";
      findings.push(finding("supabase-sql-unchecked", "medium", u.file, u.line,
        "A migration Penthera couldn't fully read",
        `\`${u.file}\` ${u.why}${more}. Tables made there aren't checked for row-level security.`,
        "Check by hand that every table it creates has row-level security enabled, or write it as plain CREATE TABLE and ALTER TABLE … ENABLE ROW LEVEL SECURITY statements.",
        "potential"));
    }
    // Grouped per migration file (and severity), so a file with many tables is one finding that
    // counts them and names the worst first: ones with private-looking columns (row 13).
    const groups = new Map();
    const group = (k, item) => {
      const g = groups.get(k) || groups.set(k, { items: [], count: 0, names: [] }).get(k);
      g.count++;
      // Every name, for the digest that keeps a suppression to this exact set (bounded by the cap).
      // For a policy, also what it permits (command, roles, which clause is open, permissive), so a
      // broadened policy on the same tables gets a new id and shows again past a baseline (Vercel, PR 312).
      // One JSON tuple per item, so no name (a quoted identifier can hold "|" or a newline) can make
      // two different sets serialize alike: [table] or [table, policy, command, roles, USING open, CHECK open].
      const pf = item.f.policy ? item.f : null;
      g.names.push(JSON.stringify(pf ? [item.raw, pf.policy.name, pf.policy.command, [...new Set(pf.roles)].sort(), !!pf.openUsing, !!pf.openCheck] : [item.raw]));
      // Keep the worst GROUP_NAMES: sensitive first, then the earliest line.
      g.items.push(item);
      if (g.items.length > GROUP_NAMES * 2) g.items = rankItems(g.items).slice(0, GROUP_NAMES);
    };
    for (const f of res.findings) {
      const t = f.table;
      // Shown per part, so a dot inside a quoted name can't make two tables read alike.
      const full = `${shown(t.schema)}.${shown(t.name)}`;
      const raw = [t.schema, t.name];
      const sensitive = t.columns || [];
      if (f.kind === "rls") { group(`rls|${t.file}`, { f, full, raw, sensitive, file: t.file, line: t.line }); continue; }
      const p = f.policy;
      const writes = p.command !== "select";
      const anyone = f.roles.includes("public") || f.roles.includes("anon");
      let severity;
      let confidence = "likely";
      if (!writes) { severity = sensitive.length && anyone ? "medium" : "low"; confidence = "potential"; } else if (p.command === "insert") { severity = anyone ? "medium" : "low"; confidence = "potential"; } else severity = anyone ? "high" : "medium";
      group(`policy|${p.file}|${severity}|${confidence}`, { f, full, raw, sensitive, file: p.file, line: p.line, severity, confidence, writes, anyone });
    }
    for (const [k, g] of groups) {
      const items = rankItems(g.items).slice(0, GROUP_NAMES);
      const lines = [...new Set(items.map((x) => x.line))].sort((a, b) => a - b);
      const first = items.slice().sort((a, b) => a.line - b.line)[0];
      const rest = g.count - items.length;
      const names = items.map((x) => `\`${x.full}\``).join(", ") + (rest > 0 ? ` and ${rest} more` : "");
      if (k.startsWith("rls|")) {
        const conf = res.dynamicRls ? "potential" : "likely";
        const dyn = res.dynamicRls ? " A function or DO block in these migrations turns row-level security on for tables Penthera can't name, so check whether these are among them." : "";
        let out;
        if (g.count === 1) {
          const t = first.f.table;
          const cols = first.sensitive.length ? ` Its columns include ${first.sensitive.slice(0, 5).map((c) => `\`${c}\``).join(", ")}.` : "";
          out = finding("supabase-rls-disabled", "high", t.file, t.line,
            `Table \`${first.full}\` has no row-level security`,
            t.disabledHere
              ? `\`${t.file}\` line ${t.line} disables row-level security on \`${first.full}\`, and no later migration turns it back on. Supabase's API serves the \`${t.schema}\` schema to anyone with the anon key, which ships in your app, so anyone can read and change every row.${cols}${dyn}`
              : `\`${t.file}\` line ${t.line} creates \`${first.full}\`, and no migration enables row-level security on it. Supabase's API serves the \`${t.schema}\` schema to anyone with the anon key, which ships in your app, so anyone can read and change every row.${cols}${dyn}`,
            `Add a migration with \`alter table ${first.full} enable row level security;\` and policies for who may read and write. If row-level security is already on in the dashboard, put it in a migration too, so the repo says what the database does.`,
            conf);
        } else {
          out = finding("supabase-rls-disabled", "high", first.file, first.line,
            `${g.count} tables in \`${first.file}\` have no row-level security (list ${digestOf(g.names)})`,
            `\`${first.file}\` creates or changes ${g.count} tables in exposed schemas that no migration puts under row-level security: ${names}. Supabase's API serves these schemas to anyone with the anon key, which ships in your app, so anyone can read and change their rows.${dyn}`,
            "Add a migration with `alter table <table> enable row level security;` for each, and policies for who may read and write. If row-level security is already on in the dashboard, put it in a migration too.",
            conf);
        }
        if (lines.length > 1) out.lines = lines;
        findings.push(out);
        continue;
      }
      const { severity, confidence } = first;
      let out;
      if (g.count === 1) {
        const { f, full, sensitive, writes, anyone } = first;
        const p = f.policy;
        const who = f.roles.includes("public") ? "everyone (no TO clause, or TO public)" : f.roles.join(" and ");
        const cols = sensitive.length ? ` Its columns include ${sensitive.slice(0, 5).map((c) => `\`${c}\``).join(", ")}.` : "";
        const what = p.command === "select" ? "read every row" : p.command === "insert" ? "insert any row" : p.command === "all" ? "read, change and delete every row" : `${p.command} every row`;
        out = finding("supabase-policy-open", severity, p.file, p.line,
          `Policy "${shown(p.name)}" lets ${anyone ? "anyone" : "any signed-in user"} ${what} of \`${full}\` (${policyGrant(f)})`,
          `\`${p.file}\` line ${p.line}: the policy "${shown(p.name)}" on \`${full}\` applies to ${who}${p.command === "all" ? " for every command" : ` for ${p.command.toUpperCase()}`} with ${f.openUsing ? "USING (true)" : ""}${f.openUsing && f.openCheck ? " and " : ""}${f.openCheck ? (f.checkImplied ? "no WITH CHECK (so USING checks new rows too)" : "WITH CHECK (true)") : ""}, so it checks nothing.${anyone ? " The anon key ships in your app." : " Supabase lets anyone sign up unless you turn it off."}${cols}${writes ? "" : " Fine for data meant to be public."}`,
          `Replace \`true\` with a condition on the row, for example \`(select auth.uid()) = user_id\`, and give each command its own policy.${writes ? "" : " If this table is meant to be public, keep it and make sure it holds nothing private."}`,
          confidence);
      } else {
        const named = items.map((x) => `"${shown(x.f.policy.name)}" on \`${x.full}\` (${x.f.policy.command.toUpperCase()})`).join(", ") + (rest > 0 ? ` and ${rest} more` : "");
        out = finding("supabase-policy-open", severity, first.file, first.line,
          `${g.count} policies in \`${first.file}\` check nothing (list ${digestOf(g.names)})`,
          `\`${first.file}\` has ${g.count} permissive policies for anon, authenticated or everyone whose USING or WITH CHECK is \`true\`: ${named}.`,
          "Replace `true` with a condition on the row, for example `(select auth.uid()) = user_id`, and give each command its own policy. Keep `true` only on tables meant to be public.",
          confidence);
      }
      if (lines.length > 1) out.lines = lines;
      findings.push(out);
    }
  }

  // A key finding on a line says more than the public-name finding on the same line.
  const keyAt = new Set(findings.filter((f) => f.title === "Supabase service-role key in browser code").map((f) => `${f.file}|${f.line}`));
  const out = findings.filter((f) => !(f.title.startsWith("Service-role key under a public env name") && f.lines && f.lines.every((l) => keyAt.has(`${f.file}|${l}`))));
  for (const f of out) {
    if (f.lines && f.lines.length < 2) delete f.lines;
    else if (f.lines) f.lines.sort((a, b) => a - b);
  }
  // The walk and the migration reader can both refuse one file: name it once.
  const seenIncomplete = new Set();
  const once = incomplete.filter((i) => !seenIncomplete.has(i.file) && seenIncomplete.add(i.file));
  return { findings: out, incomplete: once, migrations, read: readSql };
}
