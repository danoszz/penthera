/**
 * A server secret behind a public environment prefix.
 *
 * Next.js inlines every `NEXT_PUBLIC_*` variable into the browser bundle;
 * Vite does the same for `VITE_*`, Expo for `EXPO_PUBLIC_*`, Create React App
 * for `REACT_APP_*`, Nuxt for `NUXT_PUBLIC_*`, SvelteKit and Astro for
 * `PUBLIC_*`, Gatsby for `GATSBY_*`. A name such as `NEXT_PUBLIC_OPENAI_API_KEY`
 * ships the key to everyone who opens the site, whatever the value is. The
 * secret scan matches values, so a placeholder in `.env.example` or a
 * `process.env.NEXT_PUBLIC_RESEND_API_KEY` read in a component scanned clean.
 *
 * This rule reads names. A name fires when the part after the prefix names a
 * secret (API_KEY, TOKEN, SECRET, PASSWORD, SERVICE_ROLE, DATABASE_URL, ...)
 * and nothing in it says the value is public by design (PUBLISHABLE, ANON,
 * SITE_KEY, CLIENT_ID, DSN, ...), minus a short list of browser keys that
 * providers hand out for the client (Firebase, Google Maps, Mapbox, ...).
 * Read: `.env*` files, next.config.*, turbo.json, vercel.json, netlify.toml,
 * and `process.env.X` / `import.meta.env.X` reads in code. One finding per
 * variable name, critical when a committed value also matches a provider key
 * shape, high otherwise. Nothing runs; every hit names its file and line.
 */
import { join, relative, resolve, sep } from "node:path";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { findSecretsInText } from "./secrets.js";
import { stripComments } from "./js-lex.js";
import { walkFiles, lineIndex, CODE_FILE, COMMON_SKIP, WALK_MAX_FILES } from "./walk.js";

export const PUBLIC_ENV_RULE = "public-env-secret";
export const PUBLIC_PREFIXES = ["NEXT_PUBLIC_", "VITE_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_", "GATSBY_"];
const PREFIX_RE = new RegExp(`\\b(${PUBLIC_PREFIXES.join("|")})([A-Z0-9][A-Z0-9_]*)\\b`, "g");

// The part after the prefix names a secret...
const SECRET_PART = /(?:^|_)(?:SECRET|PRIVATE|PRIVATE_KEY|SERVICE_ROLE|SERVICE_KEY|SERVICE_ACCOUNT|API_KEY|APIKEY|ACCESS_KEY|ACCESS_KEY_ID|SECRET_ACCESS_KEY|AUTH_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|API_TOKEN|BEARER|PASSWORD|PASSWD|PWD|WEBHOOK_SECRET|SIGNING_KEY|SIGNING_SECRET|ENCRYPTION_KEY|MASTER_KEY|ADMIN_KEY|DATABASE_URL|DB_URL|DB_PASSWORD|MONGODB_URI|MONGO_URI|REDIS_URL|POSTGRES_URL|CONNECTION_STRING|SMTP_PASS|SMTP_PASSWORD|CREDENTIALS?)(?:_|$)/;
// ...and nothing in it says the value is meant for the browser.
const PUBLIC_PART = /(?:^|_)(?:PUBLISHABLE|PUBLIC|PUB|SITE_KEY|ANON|ANON_KEY|DSN|MEASUREMENT_ID|CLIENT_ID|APP_ID|PROJECT_ID|WEBSITE_ID|ENV_KEY|SEARCH_KEY|SEARCH_API_KEY|SEARCH_ONLY_KEY|WRITE_KEY|BROWSER_KEY|CLIENT_TOKEN|CLIENT_KEY|FRONTEND_KEY|WIDGET_KEY|EMBED_KEY)(?:_|$)/;
// Keys providers issue for the browser and restrict by domain or scope: not a leak by name alone.
const BROWSER_KEYS = new Set([
  "FIREBASE_API_KEY", "GOOGLE_MAPS_API_KEY", "MAPS_API_KEY", "MAPBOX_TOKEN", "MAPBOX_ACCESS_TOKEN",
  "TINYMCE_API_KEY", "STREAM_API_KEY", "STREAM_CHAT_API_KEY", "POSTHOG_API_KEY", "MIXPANEL_TOKEN",
  "AMPLITUDE_API_KEY", "BUGSNAG_API_KEY", "ROLLBAR_ACCESS_TOKEN", "CONTENTFUL_DELIVERY_TOKEN",
  "BUILDER_API_KEY", "ALCHEMY_API_KEY", "INFURA_API_KEY", "WALLETCONNECT_PROJECT_ID",
  "EMAILJS_PUBLIC_KEY", "HCAPTCHA_SITE_KEY", "TURNSTILE_SITE_KEY", "RECAPTCHA_SITE_KEY",
  "VAPID_PUBLIC_KEY", "FINGERPRINT_API_KEY", "LIVEBLOCKS_PUBLIC_KEY", "PADDLE_CLIENT_TOKEN",
  "MUX_ENV_KEY", "SEGMENT_WRITE_KEY", "ALGOLIA_SEARCH_API_KEY", "STRIPE_PUBLISHABLE_KEY",
  "SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY", "CLERK_PUBLISHABLE_KEY", "SENTRY_DSN",
]);

/** Does this variable name (prefix included) name a server secret shipped to the browser? */
export function isPublicSecretName(name) {
  const prefix = PUBLIC_PREFIXES.find((p) => name.startsWith(p));
  if (!prefix) return false;
  const rest = name.slice(prefix.length);
  if (!rest || BROWSER_KEYS.has(rest) || PUBLIC_PART.test(rest)) return false;
  // `TOKEN_SYMBOL`, `TOKEN_ADDRESS`: a token as a thing, not a credential.
  if (/(?:^|_)TOKEN_(?:SYMBOL|NAME|ADDRESS|DECIMALS|CONTRACT|ICON|LOGO|PRICE|LIST|ID|COUNT)(?:_|$)/.test(rest)) return false;
  return SECRET_PART.test(rest);
}

const ENV_FILE = /^\.env(?:\..+)?$|^.+\.env$/;
const CONFIG_FILE = /^(?:next\.config\.[cm]?[jt]s|turbo\.json|vercel\.json|netlify\.toml|app\.json|app\.config\.[cm]?[jt]s)$/;
const ENV_LINE = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=(.*)$/;
const ENV_READ = /(?:process\.env|import\.meta\.env|Deno\.env\.get\(\s*["'])\s*(?:\.\s*|\[\s*["'])?([A-Z][A-Z0-9_]*)/g;
const SKIP = new Set([...COMMON_SKIP, "test", "tests", "__tests__", "fixtures", "__mocks__"]);
export const PUBLIC_ENV_MAX_BYTES = 4 * 1024 * 1024;

/**
 * Sightings of public-prefixed secret names in one file's text:
 * [{ name, line, value }] where value is the assigned text in an env file.
 */
export function publicSecretSightings(text, fileName) {
  const out = [];
  if (ENV_FILE.test(fileName)) {
    text.split("\n").forEach((l, i) => {
      const m = ENV_LINE.exec(l);
      if (m && isPublicSecretName(m[1])) out.push({ name: m[1], line: i + 1, value: m[2].trim() });
    });
    return out;
  }
  if (CONFIG_FILE.test(fileName)) {
    const lineAt = lineIndex(text);
    for (const m of text.matchAll(PREFIX_RE)) if (isPublicSecretName(m[1] + m[2])) out.push({ name: m[1] + m[2], line: lineAt(m.index), value: null });
    return out;
  }
  // Code: reads of the variable, with comments blanked so a mention in a comment is not one.
  const code = stripComments(text);
  const lineAt = lineIndex(code);
  for (const m of code.matchAll(ENV_READ)) if (isPublicSecretName(m[1])) out.push({ name: m[1], line: lineAt(m.index), value: null });
  return out;
}

/**
 * Findings for a repository, one per variable name.
 * @param {string} repoPath
 * @param {{ refused?: object[], ignoredDirs?: Set<string> }} [opts] - files that could not be read go to
 *   `refused` (RefusedFileError); `ignoredDirs` (absolute, from gitIgnored) are not entered
 */
export function scanPublicEnv(repoPath, { refused = [], ignoredDirs = null } = {}) {
  const root = resolve(repoPath);
  const wants = (name) => ENV_FILE.test(name) || CONFIG_FILE.test(name) || CODE_FILE.test(name);
  const skipDirs = ignoredDirs ? new Set([...ignoredDirs].map((d) => resolve(d))) : null;
  const { files, truncated } = walkFiles(root, { wants, skip: SKIP, ignoredDirs: skipDirs });
  // Past the file cap the rest is not read: named, and the scan is incomplete.
  if (truncated) refused.push({ path: join(root, "(repository)"), reason: `it has more than ${WALK_MAX_FILES} files, so the public env check stopped reading` });
  const byName = new Map();
  for (const full of files) {
    const rel = relative(root, full).split(sep).join("/");
    const name = rel.split("/").pop();
    let text;
    try {
      text = readRepoFile(full, { root, label: rel, maxBytes: PUBLIC_ENV_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) { refused.push(e); continue; }
      if (e.code === "ENOENT") continue; // gone since the walk
      // Unreadable (EACCES, EIO, ...): named, and the scan is incomplete, never a crash or a silent pass.
      refused.push({ path: full, reason: `it could not be read (${e.code || e.message})` });
      continue;
    }
    // Code files without a public prefix are left after one cheap test.
    if (!ENV_FILE.test(name) && !PREFIX_RE.test(text)) { PREFIX_RE.lastIndex = 0; continue; }
    PREFIX_RE.lastIndex = 0;
    for (const s of publicSecretSightings(text, name)) {
      const entry = byName.get(s.name) || { name: s.name, places: [], shaped: false };
      entry.places.push({ file: rel, line: s.line, env: ENV_FILE.test(name) });
      // A committed value that is a provider key by shape: the key itself is in the repo and in the bundle.
      if (s.value && /^["']?[A-Za-z0-9_\-./+=]{16,}["']?$/.test(s.value) && findSecretsInText(`${s.name}=${s.value}`, { shapesOnly: true }).length) entry.shaped = true;
      byName.set(s.name, entry);
    }
  }
  const findings = [];
  for (const { name, places, shaped } of [...byName.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    const first = places.find((p) => p.env) || places[0];
    const others = places.filter((p) => p !== first).slice(0, 6).map((p) => `${p.file}:${p.line}`);
    const prefix = PUBLIC_PREFIXES.find((p) => name.startsWith(p));
    findings.push({
      severity: shaped ? "critical" : "high",
      title: `Server secret shipped to the browser: ${name}`,
      description: `\`${name}\` is defined or read in \`${first.file}\` (line ${first.line}${others.length ? `; also ${others.join(", ")}` : ""}). Every variable that starts with \`${prefix}\` is written into the client bundle at build time, so its value is readable by anyone who opens the site.${shaped ? " The committed value matches a provider key shape: treat it as leaked and rotate it." : " Its name says it is a secret; a value that only needs to be public (a publishable key, an anon key, a site key) should say so in its name."}`,
      remediation: `Rename it without the public prefix (\`${name.slice(prefix.length)}\`), read it only in server code (route handlers, Server Actions, server components), and rotate the value if it was ever deployed. If the value is meant for the browser, name it so (PUBLISHABLE, SITE_KEY, CLIENT_ID).`,
      url: first.file,
      file: first.file,
      line: first.line,
      templateId: PUBLIC_ENV_RULE,
      variable: name,
      category: "secrets",
      source: "static-analysis",
      confidence: shaped ? "confirmed" : "likely",
    });
  }
  return findings;
}
