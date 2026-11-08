/**
 * Scan repository source for hardcoded secrets.
 */
import { readdirSync, lstatSync, existsSync, openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
import { join, relative } from "node:path";
import { rulesOf, rulesGeneration, PACK_INPUT_CAP } from "../rules/index.js";
import { secretTag } from "../secret-tags.js";
import { lexJs } from "./js-lex.js";

// Folders the scan never enters, at any depth: dependencies, Penthera's own
// output, framework caches.
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".security-results",
  // Python: virtualenvs and tool caches hold third-party code (Pillow's
  // ImageFont.py matches the AWS key shape), not this project's secrets.
  "venv", ".venv", "site-packages", "__pycache__", ".tox", ".nox",
  ".mypy_cache", ".pytest_cache", ".ruff_cache",
  // Note vaults: plugin bundles and caches, not source.
  ".obsidian",
]);

// Build output, coverage, vendored code and reports. At the repo root they
// are usually generated or third-party, so only the fixed-shape rules run
// there: a provider key prefix or a private key in a shipped bundle is still
// a leak. A root folder git ignores is skipped with the other ignored folders.
// Below the root the same names are often source (`app/api/build/route.ts`,
// `src/reports/`), so every rule runs. Skipping them at any depth let a live
// key in committed `src/vendor/` pass as clean (Vercel review, B01).
const ROOT_OUTPUT_DIRS = new Set(["dist", "build", "coverage", "reports", "vendor"]);

/** Is this a root folder of build output, coverage, vendored code or reports? */
export function isRootOutputDir(name) {
  return ROOT_OUTPUT_DIRS.has(name);
}

const SKIP_FILES = /\.(png|jpg|jpeg|gif|webp|ico|woff|woff2|ttf|eot|zip|tar|gz|pdf|lock)$/i;

// Values that clearly aren't real secrets: placeholders, redactions, and the
// dummy/probe credentials that security tooling (Penthera included) hardcodes
// to test login endpoints, e.g. `password: "invalid-password-12345"`. Matched
// against the assigned value only, with word boundaries so a real secret that
// merely contains one of these substrings isn't suppressed. A value that is
// only a template placeholder (`"${apiKey}"`, `"{{ api_key }}"`) holds no
// secret either: it is filled in at runtime.
// A value that is just the key's own name (`password = "password"`) is a
// placeholder too.
const TEST_VALUE = /\b(?:placeholder|example|changeme|dummy|sample|redacted|invalid|fake|test|your)\b|xxx|\*{3,}|^\$\{[^}]+\}$|^\{\{[^}]+\}\}$|^(?:password|passwd|pwd|pass|secret|api[_-]?key|token)$/i;

// A PEM private key is a header followed by its base64 body. Requiring the
// first 40 body characters (after optional `Proc-Type:`-style header lines,
// with real or JSON-escaped newlines, a comment or quote prefix per line, and
// string concatenation, `"…\\n" +`) keeps docs that only name the header, or
// elide the key as `...`, from counting as a leaked key.
const PEM_NL = String.raw`(?:\\r)?(?:\\n|\r?\n)(?:["'\x60][ \t+.]*\r?\n)?[ \t"'#*+]*`;
const PEM_BODY = String.raw`(?:${PEM_NL}[A-Za-z-]+:[^\r\n\\]*)*(?:${PEM_NL})+[A-Za-z0-9+/]{40}`;

// AWS's documented example keys (AKIAIOSFODNN7EXAMPLE, ASIAJEXAMPLE…, and
// others) all spell EXAMPLE; a run of Xs is a redaction. Neither is a leak.
const AWS_EXAMPLE_KEY = /EXAMPLE|X{8}/;

// ── Password keys (E11b pass 2) ─────────────────────────────────────────
// A key names a password when one of its words does, however it is spelled:
// quoted (`"password":`), prefixed or suffixed (`old_password`, `password1`,
// `DB_PASSWORD`), run together (`PGPASSWORD`), or dotted (`db.password`).
const PASSWORD_WORDS = new Set(["password", "passwd", "passphrase", "pass", "pwd"]);
const PASSWORD_TAIL = /(?:password|passwd|pwd)$/;
// Words that may follow it (`password_confirmation`); any other names
// something about the password (`password_hash`, `passwordMinLength`).
const PASSWORD_TRAILERS = new Set(["confirm", "confirmation", "repeat", "again", "value", "plain", "plaintext", "raw"]);
// A word right before it that makes the key a flag or an action (`allow_empty_password`, `forgotPassword`).
const PASSWORD_NOT_A_VALUE = new Set(["forgot", "reset", "show", "hide", "toggle", "validate", "require", "requires", "allow", "enable", "disable", "skip", "no", "empty", "min", "max", "has", "is"]);
// A word anywhere in the key that makes the value text for people (`LABEL_PASSWORD`, `invalidPassword`).
const UI_TEXT_WORDS = new Set(["label", "title", "mandatory", "placeholder", "hint", "prompt", "message", "msg", "error", "invalid", "incorrect", "wrong", "tooltip", "caption", "heading", "text", "desc", "description", "help", "translation"]);

/** The words of an identifier: `adminPassword2` → ["admin", "password"]. */
export function keyWords(key) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/(?<=[A-Z])(?=[A-Z][a-z])/g, " ")
    .toLowerCase()
    .split(/[^a-z0-9]+|(?<=[a-z])(?=[0-9])|(?<=[0-9])(?=[a-z])/)
    .filter((w) => w && !/^\d+$/.test(w));
}

/** Does this key name a password? Only the last part of a dotted path counts. */
export function isPasswordKey(key) {
  const words = keyWords(key.slice(key.lastIndexOf(".") + 1));
  let at = words.length - 1;
  while (at >= 0 && !PASSWORD_WORDS.has(words[at]) && !PASSWORD_TAIL.test(words[at])) at--;
  return at >= 0 && words.slice(at + 1).every((w) => PASSWORD_TRAILERS.has(w)) && !words.some((w) => UI_TEXT_WORDS.has(w)) && !PASSWORD_NOT_A_VALUE.has(words[at - 1]);
}

// Runs of three or more consecutive characters, at most four (`123456`,
// `qwerty`, `abc123`): what people type when a value only has to be filled in.
const SEQUENCES = ["01234567890", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "9876543210"];
export function isSequential(value) {
  const v = value.toLowerCase();
  let runs = 0;
  for (let i = 0; i < v.length; runs++) {
    let best = 0;
    for (const s of SEQUENCES) {
      const at = s.indexOf(v[i]);
      let n = at < 0 ? 0 : 1;
      while (n && i + n < v.length && s[at + n] === v[i + n]) n++;
      best = Math.max(best, n);
    }
    if (best < 3 || runs > 3) return false;
    i += best;
  }
  return runs > 0;
}

// Published defaults (`admin`, `changeit`, the Java keystore one) leak
// nothing; `string` is what API specs put where an example goes.
const DEFAULT_PASSWORDS = /^(?:admin|administrator|root|guest|user|demo|default|secret|pass|letmein|changeit|foobar|foo|bar|qwerty|password\d*|passw0rd|p@ssw0rd|string)$/i;

// Never a password: booleans, stored hashes (`$2b$…`, `{SSHA}…`), references
// (`$PW`, `#{pw}`, `%(pw)s`, `%PW%`, `<pw>`, `[pw]`, `{pw}`), code after a key
// inside a string (`"Password: ").append(`), text for people (non-ASCII
// letters, a trailing `:`), versions (`^1.0.0`), test values, `mypassword`.
const NOT_A_PASSWORD = new RegExp([
  String.raw`^(?:true|false|yes|no|on|off|null|nil|none|undefined|empty)$`,
  String.raw`^\$(?:2[abxy]?|1|5|6|y|apr1|argon2(?:id|i|d)?|pbkdf2[\w-]*|scrypt|sha\d*)\$`,
  String.raw`^\{(?:S?SHA\d*|S?MD5|CRYPT|PBKDF2[\w-]*|ARGON2\w*|BCRYPT)\}`,
  String.raw`^(?:pbkdf2_sha\d+|bcrypt(?:_sha256)?|argon2|scrypt|sha1|md5)\$`,
  String.raw`^\$(?:\{[^}]*\}|\([^)]*\)|[A-Za-z_]\w*)$`, String.raw`#\{`, String.raw`%\([\w.-]+\)s`, String.raw`^%\w+%$`, String.raw`^<[^>]*>$`, String.raw`^\[[^\]]*\]$`, String.raw`^\{[\w.]*\}$`,
  String.raw`^[),;+.\]}(|&]`, String.raw`^(.)\1*$`,
  String.raw`(?![\x00-\x7f])\p{L}`, String.raw`:$`,
  String.raw`^[~^<>=]+\d`, String.raw`^\d+\.\d+\.\d+$`,
  String.raw`^test`, String.raw`^[a-z]*(?:password|passwd)[a-z]*$`,
].join("|"), "iu");

/** A name, not a secret: `keystore.password`, `my-secret` (not `Password1!`). */
export function isCredentialName(value) {
  return /[._-]/.test(value) && keyWords(value).some((w) => PASSWORD_WORDS.has(w) || PASSWORD_TAIL.test(w) || w === "secret");
}

// A CSS utility class (`text-emerald-400`, `dark:bg-red-500/20`): a style, not a secret.
const CSS_CLASS = /^(?:[a-z]+:)*-?(?:text|bg|border|ring|fill|stroke|from|via|to|shadow|outline|decoration|divide|accent|caret)-[a-z]+(?:-\d{2,3})?(?:\/\d{1,3})?$/;
// A CSS value (`var(--success)`, `hsl(var(--ok))`, `#22c55e`): also a style.
const CSS_VALUE = /^(?:(?:var|hsla?|rgba?|oklch|oklab|lab|lch|calc|color-mix)\(.*\)|#[0-9a-f]{3,8})$/i;

/**
 * A Google Secret Manager name (Firebase Extensions' `extensions/*.env`), parsed:
 * the whole value is `projects/<id or number>/secrets/<name>[/versions/<n|latest>]`.
 * A name that looks machine-made is a pasted key, so it is still reported.
 */
export function isSecretManagerRef(v) {
  const parts = String(v).split("/");
  if (parts.length !== 4 && parts.length !== 6) return false;
  const [p, project, s, name, ver, version] = parts;
  if (p !== "projects" || s !== "secrets") return false;
  if (!/^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|\d{1,20})$/.test(project)) return false;
  if (!/^[A-Za-z0-9_-]{1,255}$/.test(name) || looksGenerated(name)) return false;
  if (parts.length === 6 && (ver !== "versions" || !/^(?:[1-9]\d{0,9}|latest)$/.test(version))) return false;
  return true;
}

const passwordValue = (v) => !isSecretManagerRef(v) && !CSS_CLASS.test(v) && !CSS_VALUE.test(v) && !TEST_VALUE.test(v) && !NOT_A_PASSWORD.test(v) && !DEFAULT_PASSWORDS.test(v) && !isSequential(v) && !isCredentialName(v);

// API keys end in a word pair (`STRIPE_API_KEY`, `client_secret`,
// `aws_secret_access_key`, `oauthToken`). Public keys are meant to ship.
const API_KEY_NAME = /(?:api ?(?:key|token|secret)|secret ?(?:access ?)?key|client ?secret|o?auth ?token)$/;
const namesApiKey = (words) => API_KEY_NAME.test(words.join(" "));
// Broader names whose value is the credential itself (OAuth 2 access, refresh
// and ID tokens; OAuth 1 token secrets; app, signing and webhook secrets), and
// a bare `token` or `secret`. They also name test data and words, so their
// value must look generated (looksGenerated).
const CREDENTIAL_NAME = /(?:(?:access|refresh|bearer|id|session|client|private) token|token secret|(?:consumer|app|application|shared|signing|webhook|cookie) secret)$|^(?:token|secret)$/;
const apiKeyName = (key) => {
  const words = keyWords(key.slice(key.lastIndexOf(".") + 1));
  if (words.some((w) => UI_TEXT_WORDS.has(w) || w === "public" || w === "publishable")) return null;
  return namesApiKey(words) ? "api" : CREDENTIAL_NAME.test(words.join(" ")) ? "broad" : null;
};
export const isApiKeyKey = (key) => apiKeyName(key) !== null;

/** Bits of Shannon entropy per character. */
export function entropy(v) {
  const n = {};
  for (const c of v) n[c] = (n[c] || 0) + 1;
  return Object.values(n).reduce((h, k) => h - (k / v.length) * Math.log2(k / v.length), 0);
}
// Six typed characters in a row (`123456`, `abcdef`): made by hand.
const typedRun = (v) => SEQUENCES.some((s) => [...s.slice(5)].some((_, i) => v.toLowerCase().includes(s.slice(i, i + 6))));
// Words (`MySecretToken`, `local-dev-token-1`): each part one case, CamelCase or a short number.
const wordy = (v) => v.split(/[._\-/:]+/).filter(Boolean).every((p) => /^(?:[A-Z]+|[A-Z]?[a-z]+(?:[A-Z][a-z]+)*|\d{1,4})$/.test(p));
/**
 * A value a machine made: at least 16 characters, two character classes,
 * 2.5 bits of entropy per character, and not words, an email, a reference
 * (`${…}`, `{{…}}`), an elided example (`…`) or typed by hand (`123456`).
 * Thresholds from E11b round 2 (lab notebook 5).
 */
export function looksGenerated(v) {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
  return v.length >= 16 && classes >= 2 && entropy(v) >= 2.5 && !wordy(v) && !/@[\w-]+\.|\$\{|\{\{|\.\.\.$|…$/.test(v) && !typedRun(v);
}
// Not a key: a name (`oauthClientSecret`), a stand-in part (`my_api_key`,
// `sk_test_1`; `key-…` is Mailgun's prefix), or too plain to be generated:
// 8 to 15 letters in one case (`whatever`), or only digits.
const STAND_IN_PARTS = new Set(["token", "secret", "test", "example", "sample", "dummy", "fake", "placeholder", "your", "my"]);
const PLAIN = /^(?:[a-z._-]{8,15}|[A-Z._-]{8,15}|\d+)$/;
// Five identical characters in a row (`1111111`, `bbbbb`) are padding, a redaction or a stand-in.
const apiKeyValue = (v, key) => !isSecretManagerRef(v) && (apiKeyName(key) === "api" || looksGenerated(v)) && !/(.)\1{4}/.test(v) && !TEST_VALUE.test(v) && !NOT_A_PASSWORD.test(v) && !isSequential(v) && !PLAIN.test(v) && !namesApiKey(keyWords(v)) && !v.toLowerCase().split(/[._-]+/).some((p, _, a) => a.length > 1 && STAND_IN_PARTS.has(p));

// Key (maybe quoted, `$`/`@`/`:`-prefixed or `]`-closed), `:`/`=`/`=>`/`:=`,
// and a quoted value `v` or a bare one `u` (config files only). Matching
// starts at a literal key word, so it is fast; a lookbehind reads the rest.
const assignment = (word, min) => new RegExp(
  String.raw`(?<word>${word})(?<=(?<![\w$@.])(?<kq>\\?["'\x60])?[$@:]?(?<pre>[\w.-]*)(?:${word}))(?<post>[\w.-]*)(?<kq2>\\?["'\x60])?\]?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?(?<vq>["'\x60])(?<v>[^"'\x60\s\\]{${min},200})\\?\k<vq>|(?<u>[^\s"'\x60#;,&]{${min},200})(?![^\s"'\x60#;,&]))`,
  "i",
);

// A bare value that points elsewhere: YAML tags, aliases, blocks (`!vault`,
// `*pw`, `|`), `<pw>`, `$PW`, `ENC(…)`, URLs, paths, `env(PW)`, digits.
const BARE_NOT_A_PASSWORD = /^(?:[!&*|><{$\-]|ENC\(|[a-z][\w+.-]*:\/\/|\.{0,2}\/|~\/|[a-z]:\\|[\w.]+[([]|\d+$)/i;

/**
 * The key must be named right and quoted on both sides or neither. Not a
 * ternary (`ok ? "pass" : "fail"`), nor a template literal built at run time.
 */
const accepts = (isKey, isValue) => (m, { config }) => {
  const { kq, kq2, pre, word, post, vq, v, u } = m.groups;
  if (u !== undefined && (!config || BARE_NOT_A_PASSWORD.test(u))) return false;
  if ((kq || "").replaceAll("\\", "") !== (kq2 || "").replaceAll("\\", "")) return false;
  const keyAt = m.index - pre.length - (kq || "").length;
  if (kq && /\?\s*$/.test(m.input.slice(Math.max(0, keyAt - 40), keyAt))) return false;
  if (vq === "`" && v.includes("${")) return false;
  return isKey(pre + word + post) && isValue(v ?? u, pre + word + post);
};

// A bare `pass` key next to a `fail` or `warn` key is a map of test or check
// outcomes (`{ pass: 'complete', fail: 'missing' }`), not a credential.
const STATUS_SIBLING = /(?:^|[\s{,(])["'\x60]?(?:fail|failed|warn|warning|skip|skipped)["'\x60]?\s*:/i;
function inStatusMap(m) {
  const { pre, post } = m.groups;
  if (pre || post || m.groups.word.toLowerCase() !== "pass") return false;
  const near = m.input.slice(Math.max(0, m.index - 200), m.index + m[0].length + 200);
  return STATUS_SIBLING.test(near);
}

const SECRET_PATTERNS = [
  // AWS IAM unique-ID prefixes: AKIA is a long-term access key, ASIA a temporary (STS) one.
  { name: "AWS access key", pattern: /A[KS]IA[0-9A-Z]{16}/, severity: "critical", skipIf: AWS_EXAMPLE_KEY, shape: true },
  // GitHub's token prefixes (GitHub blog, 2021-04-05): ghp_ personal, gho_
  // OAuth, ghu_/ghs_ app, ghr_ refresh; github_pat_ fine-grained.
  { name: "GitHub token", pattern: /gh[pousr]_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{82}/, severity: "critical", shape: true },
  // AI provider keys. Vibecoded apps leak these more than any other credential,
  // often via a NEXT_PUBLIC_/VITE_ variable or a committed notebook. Specific
  // prefixes come first so a key is reported under its real provider. They
  // live in the bundled core rule pack (lib/rules/core/secrets.json).
  ...coreSecrets(),
  // Stripe live secret (sk_) and restricted (rk_) keys, per Stripe's API-key docs.
  // Clerk secret keys share Stripe's sk_live_/sk_test_ prefix, so they are
  // told apart by the variable Clerk's SDKs read (CLERK_SECRET_KEY). Listed
  // before Stripe: a rule claims its span, so a Clerk key is never reported as
  // Stripe's. A test key (sk_test_) still opens the dev instance and its users.
  { name: "Clerk secret key", pattern: /CLERK_SECRET_KEY["']?\s*[:=]\s*["']?(?<v>sk_live_[A-Za-z0-9]{20,})/, severity: "critical", shape: true },
  { name: "Clerk test secret key", pattern: /CLERK_SECRET_KEY["']?\s*[:=]\s*["']?(?<v>sk_test_[A-Za-z0-9]{20,})/, severity: "high", shape: true },
  { name: "Stripe secret key", pattern: /[sr]k_live_[a-zA-Z0-9]{20,}/, severity: "critical", shape: true },
  // Postman API key: PMAK-, 24 hex, -, 34 hex (Postman API docs).
  { name: "Postman API key", pattern: /PMAK-[a-f0-9]{24}-[a-f0-9]{34}/, severity: "high", shape: true },
  {
    name: "Generic API key assignment",
    pattern: assignment("api|secret|token", 8),
    keyWord: "api|secret|token",
    severity: "high",
    skipIf: TEST_VALUE,
    accept: accepts(isApiKeyKey, apiKeyValue),
  },
  {
    name: "Hardcoded password",
    pattern: assignment("pass|pwd", 4),
    keyWord: "pass|pwd",
    severity: "high",
    skipIf: TEST_VALUE,
    accept: (m, ctx) => accepts(isPasswordKey, passwordValue)(m, ctx) && !inStatusMap(m),
  },
  { name: "GCP/Firebase service account", pattern: new RegExp(String.raw`"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----${PEM_BODY}`), severity: "critical", shape: true },
  { name: "Private key block", pattern: new RegExp(String.raw`-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[ \t]*${PEM_BODY}`), severity: "critical", shape: true },
  {
    name: "JWT secret assignment",
    pattern: /(?:jwt[_-]?secret|session[_-]?secret)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    severity: "high",
    skipIf: TEST_VALUE,
  },
  {
    // express-session / cookie-session signing secret written into the
    // session(...) options as a string literal, also as the fallback after
    // `process.env.SESSION_SECRET ||`. Anyone with the repo can
    // sign session cookies. The lookbehind keeps the match (and so the value
    // the placeholder filter sees) to the `secret: '...'` part.
    name: "Hardcoded session secret",
    // `secret:` is checked before the lookbehind: Node 22 ran the lookbehind's
    // 500-character backward scan at every position first, about 0.7 s per MiB
    // (CI timed out on an 8 MiB file). The text matched is the same.
    pattern: /\b(?=secret\s*:)(?<=\b(?:session|cookieSession|expressSession)\s*\(\s*\{[^}]{0,500}?)secret\s*:\s*(?:process\.env\.\w+\s*(?:\|\||\?\?)\s*)?['"][^'"\n]{4,200}['"]/,
    severity: "high",
    skipIf: TEST_VALUE,
  },
];


// A pack rule without the placeholder filter matches a fixed shape (a provider
// prefix); one with it guesses from a key name, like the built-in assignments.
function fromPack(r) {
  return { name: r.name, pattern: r.pattern, severity: r.severity, ...(r.skipPlaceholders ? { skipIf: TEST_VALUE } : { shape: true }), rule: r };
}

function coreSecrets() {
  return rulesOf("secret", { pack: "core" }).map(fromPack);
}

// Built-ins first, then rules from other packs (bundled or --rules), so a
// pack can add detections but never shadow or reorder the built-in ones.
let _patterns = null;
let _generation = -1;
function secretPatterns() {
  if (_generation !== rulesGeneration()) {
    _patterns = [...SECRET_PATTERNS, ...rulesOf("secret", { exceptPack: "core" }).map(fromPack)];
    _generation = rulesGeneration();
  }
  return _patterns;
}

/** The secret rules in effect, in match order (built-ins, then packs). */
export function activeSecretPatterns() {
  return secretPatterns().map(({ name, pattern, severity, skipIf, rule }) => ({ name, pattern, severity, skipIf: !!skipIf, pack: rule?.pack || null }));
}

const SCAN_EXTENSIONS = new Set([
  ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".java",
  ".php", ".cs",
  ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".sh", ".bash", ".zsh",
  ".properties", ".conf", ".xml", // Java, server and app configs
  ".ipynb", // notebooks are a classic place for a pasted provider key
  ".tf", ".tfvars", ".hcl", ".tfstate", // Terraform: state files hold every secret in plain text
  ".pem", ".key", ".p8", ".ppk", // key files
]);

// Docs are full of example passwords and API keys, so in them only the rules
// that match a fixed shape (provider prefixes, private keys) run; the
// assignment guesses do not.
const DOC_EXTENSIONS = new Set([".txt", ".md", ".markdown", ".rst", ".adoc", ".asciidoc"]);

const extOf = (name) => (name.includes(".") ? name.slice(name.lastIndexOf(".")) : "");

// Config files, where a value needs no quotes (`password: s3cret` in YAML,
// `db.password=s3cret` in .properties and .env).
const CONFIG_EXTENSIONS = new Set([".yml", ".yaml", ".properties", ".ini", ".env", ".conf", ".toml", ".cfg"]);

/** An env file by name: `.env`, `.env.local`, `prod.env`, `prod.env.local` (not code such as `vite.env.d.ts`). */
const isEnvName = (name) => name.startsWith(".env") ||
  /\.env(?:\.(?![\w.]*\.(?:[cm]?[jt]sx?|json|py|rb|go|php|java|cs)$)(?!(?:[cm]?[jt]sx?|json|py|rb|go|php|java|cs)$)[\w.-]{1,64})?$/.test(name);
// Shell scripts: they export keys and pass them on command lines.
const SHELL_EXTENSIONS = new Set([".sh", ".bash", ".zsh"]);

/** Is this a config file, where bare `key: value` and `key=value` count? */
export function isConfigFile(relPath) {
  const name = relPath.split("/").pop();
  return CONFIG_EXTENSIONS.has(extOf(name)) || isEnvName(name);
}

/** Does the repo scan skip every folder with this name, at any depth? */
export function isSecretSkipDir(name) {
  return SKIP_DIRS.has(name);
}

/** Would the repo scan read this file? `relPath` uses forward slashes (git paths). */
export function isSecretScanTarget(relPath) {
  const parts = relPath.split("/");
  if (parts.slice(0, -1).some((d) => SKIP_DIRS.has(d))) return false;
  return wantsFile(parts[parts.length - 1]);
}

function wantsFile(entry) {
  if (SKIP_FILES.test(entry)) return false;
  const ext = extOf(entry);
  return SCAN_EXTENSIONS.has(ext) || DOC_EXTENSIONS.has(ext) || isEnvName(entry);
}

// Translation files are UI text: under a password key they hold the word
// "password" in another language. As in docs, only the fixed-shape rules run.
// Only translation file types count: code and `.env` files in a `lang/`
// folder get every rule, or a folder name would hide a password (B07).
const LOCALE_DIRS = new Set(["locale", "locales", "i18n", "l10n", "intl", "lang", "langs", "languages", "translations", "nls"]);
const TRANSLATION_EXTENSIONS = new Set([".json", ".yml", ".yaml", ".properties", ".po"]);
// Files named for a language and region (de-DE.json, pt_BR.yml) are
// translations too. A bare two-letter name (db.json) is not taken as a locale.
const LOCALE_FILE = /^[a-z]{2,3}[-_][A-Z]{2}\.(?:json|ya?ml|properties)$/;

/** Does only the fixed-shape subset of rules run on this file (a doc, a translation)? */
export function isShapesOnlyFile(relPath) {
  const parts = relPath.split("/");
  const name = parts[parts.length - 1];
  const ext = extOf(name);
  return DOC_EXTENSIONS.has(ext) || LOCALE_FILE.test(name) ||
    (TRANSLATION_EXTENSIONS.has(ext) && !isEnvName(name) && parts.slice(0, -1).some((d) => LOCALE_DIRS.has(d.toLowerCase()))) ||
    // An env file (`.env*`, `*.env`, `*.env.*`) or a shell script holds
    // secrets wherever it sits: every rule runs on it, in a root output folder too.
    (parts.length > 1 && ROOT_OUTPUT_DIRS.has(parts[0]) && !isEnvName(name) && !SHELL_EXTENSIONS.has(ext));
}

// A key file often has no extension (`id_rsa`, `server`). Such a file is read
// when it starts with a private-key header, and only the shape rules run on it.
const KEY_FILE_HEAD = /^\s*-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const mayBeKeyFile = (name) => !extOf(name) && !SKIP_FILES.test(name);

/**
 * Which rules the repo scan runs on a file: "all", "shapes" (docs, and key
 * files without an extension) or null (not read). `head` is the start of the
 * file; it only matters for a file without an extension. The one place the
 * scan, and the benchmarks that replay it, decide this.
 */
export function secretRulesFor(relPath, head = "") {
  if (isSecretScanTarget(relPath)) return isShapesOnlyFile(relPath) ? "shapes" : "all";
  const parts = relPath.split("/");
  if (parts.slice(0, -1).some((d) => SKIP_DIRS.has(d)) || !mayBeKeyFile(parts[parts.length - 1])) return null;
  return KEY_FILE_HEAD.test(head) ? "shapes" : null;
}

// A subfolder with its own `.git` (a nested repo, submodule or worktree, such
// as the ones coding agents create under .claude/worktrees) is a separate
// project: scanning it would report its secrets as this repo's. Scan it on its
// own instead. Symlinked folders are not followed, so a link cannot pull files
// from outside the repo into the scan or loop forever.
export function isNestedRepo(dir, root) {
  return dir !== root && existsSync(join(dir, ".git"));
}

// A virtualenv under any name (`env`, `.py311`, ...) is marked by pyvenv.cfg.
export function isVirtualenv(dir) {
  return existsSync(join(dir, "pyvenv.cfg"));
}

// Per-file cap for the repo scan. A file under it is read whole; a larger one
// is not read, and the scan says so and is incomplete (exit 2). Measured on
// 64 MiB of the heaviest content (name = value lines): about 360 MB peak, under
// the 512 MB budget; 96 MiB would be about 530 MB. Before 2.3.2 files up to
// 512 MiB were read in overlapping pieces; whole reads leave no piece edges.
export const MAX_SCAN_BYTES = 64 * 1024 * 1024;

// Regular files only: a FIFO, socket or device named `.env` would block the
// read (or never end), and a symlink could point outside the repo. The name is
// checked before the entry is stat'ed, and an entry that vanishes between the
// listing and the stat (a SQLite -wal file, an editor swap file, build output
// written while the scan runs) is skipped: the scan must not stop on it.
function walkFiles(dir, files = [], root = dir, skipDir = () => false, special = []) {
  if (!existsSync(dir) || isNestedRepo(dir, root) || (dir !== root && (isVirtualenv(dir) || skipDir(dir)))) return files;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch (e) {
    special.push({ path: dir, reason: `the folder could not be listed (${e.code || e.message})` });
    return files;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    // Dirent types come from the listing, so most files are filtered without a stat.
    if (e.isFile() && !wantsFile(e.name) && !mayBeKeyFile(e.name)) continue;
    const full = join(dir, e.name);
    let st;
    try { st = lstatSync(full); } catch { continue; }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      walkFiles(full, files, root, skipDir, special);
    } else if (st.isFile()) {
      // An extensionless file of any size: its first bytes decide whether it is a key.
      if (wantsFile(e.name) || mayBeKeyFile(e.name)) files.push(full);
    } else if (wantsFile(e.name)) {
      // A FIFO, a socket or a device with a name the scan reads: named, never silent.
      special.push({ path: full, reason: "it is not a regular file (a FIFO, a socket or a device)" });
    }
  }
  return files;
}

/**
 * A matched secret as reports show it. In an assignment (KEY=value,
 * "key": "value") the name stays and only the value is masked; showing the
 * last 4 characters of the whole match showed a short password in full
 * (DB_PASSWORD=Xk9q gave DB_P…Xk9q). A value under 20 characters shows
 * nothing; a longer one shows its first and last 4, as key prefixes do.
 */
/**
 * A secret's salted tag, or null when it must not get one. Only a fixed-format
 * rule (`shape`: a provider prefix, a PEM block) is tagged: its value is
 * machine-made, so the tag is no guessable verifier. A password, a generic
 * key=value assignment or a session secret may be a human-chosen word; with
 * the salt in the report, its unkeyed tag would let anyone holding the report
 * check dictionary guesses offline (Vercel Security Review B, 2.3.2). Those
 * keep the count and location comparison. A fixed-format match that is not a
 * whole token, or sits inside an assignment rule's span or URL userinfo, is not
 * tagged either (findIn sets `taggable`), nor is a value masked as *** (too short).
 */
function tagOf(hit) {
  if (!hit.taggable) return null;
  return maskMatch(hit.match).includes("***") ? null : secretTag(hit.match);
}

export function maskMatch(match) {
  const s = String(match);
  let cut = -1;
  for (let i = 0; i < Math.min(s.length, 100); i++) if (s[i] === "=" || s[i] === ":") { cut = i; break; }
  // Only base64 padding (abc==, = to the very end) is not an assignment. Any
  // other value is masked whole, whatever its first character: a password can
  // start with = (password_confirmation==ab1c).
  if (cut > 0 && cut < s.length - 1 && !/^=+$/.test(s.slice(cut))) {
    let start = cut + 1;
    while (start < s.length && " \t\"'`".includes(s[start])) start++;
    // A value that is code ending in a quoted literal (`process.env.X ||
    // 'kq7Zp9'`, the session-secret fallback) masks the literal alone, by the
    // same under-20 rule; masking the whole value showed its last 4 (A07).
    // Only when no other quote comes before it, so no literal shows in clear.
    const rest = s.slice(start);
    const lit = /^([^"'`]+["'`])[^"'`]*["'`]\s*$/.exec(rest);
    if (lit && lit[1].at(-1) === rest.trimEnd().at(-1)) return s.slice(0, start) + lit[1] + maskValue(rest.slice(lit[1].length));
    return s.slice(0, start) + maskValue(rest);
  }
  return maskValue(s);
}

/**
 * A bare secret value (no name around it), as other tools report them: never
 * keeps a prefix, whatever characters it holds.
 */
export function maskRaw(value) {
  return maskValue(String(value));
}

function maskValue(v) {
  // A closing quote stays outside the mask and never counts among the last 4.
  const q = v.length > 1 && "\"'`".includes(v.at(-1)) ? v.at(-1) : "";
  const body = q ? v.slice(0, -1) : v;
  return (body.length < 20 ? "***" : body.slice(0, 4) + "…" + body.slice(-4)) + q;
}

// Lines listed on one finding: the rule, the file, and where each hit is.
const MAX_LINES_PER_FINDING = 200;
// A file can repeat one key shape thousands of times; past as many hits per
// rule as a finding can list, stop looking for more.
const MAX_HITS_PER_RULE = MAX_LINES_PER_FINDING;

/** Every match of a rule. Pack rules added by path see at most PACK_INPUT_CAP chars, as with packMatch(). */
function* allMatches(rule, content) {
  if (rule.rule) {
    const input = rule.rule.origin === "bundled" || content.length <= PACK_INPUT_CAP ? content : content.slice(0, PACK_INPUT_CAP);
    rule.globalPattern ??= new RegExp(rule.rule.pattern.source, rule.rule.pattern.flags.replace(/[gy]/g, "") + "g");
    yield* input.matchAll(rule.globalPattern);
    return;
  }
  if (rule.keyWord) { yield* assignmentMatches(rule, content); return; }
  rule.globalPattern ??= new RegExp(rule.pattern.source, rule.pattern.flags.replace(/[gy]/g, "") + "g");
  yield* content.matchAll(rule.globalPattern);
}

/**
 * The matches of an assignment() rule, as matchAll would give them, with the
 * pattern tried at one or two places per run of key characters ([\w.-])
 * instead of at every key word. Each try reads the whole run (the lookbehind
 * back to its start, `post` to its end), so trying every word in a long run
 * (`a.token.a.token…`) was quadratic (Vercel Security Review, 2.3.2).
 *
 * Every word in a run is followed by the same rest of the run, so they all
 * match or all fail, except for where the key may start: at the run's start,
 * or after a "-" in it (the only run character the lookbehind's
 * (?<![\w$@.]) lets a key start after). So the first word is tried, and if
 * it fails, the first word after the first "-" behind it; no other word can
 * do better. A match ends at a quote or before a delimiter, never inside a
 * run, so the next run starts where the scan stands.
 */
const KEY_RUN = /[\w.-]+/g;
function* assignmentMatches(rule, content) {
  rule.stickyPattern ??= new RegExp(rule.pattern.source, rule.pattern.flags.replace(/[gy]/g, "") + "y");
  rule.wordPattern ??= new RegExp(rule.keyWord, "i");
  const sticky = rule.stickyPattern;
  const word = rule.wordPattern;
  const run = new RegExp(KEY_RUN);
  const at = (i) => { sticky.lastIndex = i; return sticky.exec(content); };
  for (let r = run.exec(content); r; r = run.exec(content)) {
    const w = word.exec(r[0]);
    if (!w) continue;
    let m = at(r.index + w.index);
    if (!m) {
      const dash = r[0].indexOf("-", w.index);
      const w2 = dash === -1 ? null : word.exec(r[0].slice(dash + 1));
      if (w2) m = at(r.index + dash + 1 + w2.index);
    }
    if (!m) continue;
    yield m;
    run.lastIndex = m.index + m[0].length;
  }
}

// A long unbroken run of base64 (an inlined image, font or model file) holds
// key-shaped substrings by chance: `AIza...` and `AKIA...` turn up in image
// data. Real secrets sit between quotes or delimiters, never mid-run, so runs
// this long are blanked before matching. Blanking keeps the length, so match
// indexes (and the line numbers callers derive from them) do not move. The
// scan is one linear pass over maximal runs: the regex it replaces
// (/(?<![A-Za-z0-9+/_-]|-----(?:\\r)?\\)[A-Za-z0-9+/_-]{512,}={0,2}/g) overflowed
// the stack on a run of about 8 MiB, the chunk size, so one inlined data file
// crashed the whole scan. A run right after a PEM header and an escaped
// newline (`-----\nMIIE…` on one line, as in a JSON string) is a key body, not
// a blob, and is kept.
const isBlobChar = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 43 || c === 47 || c === 95 || c === 45;
const BLOB_MIN = 512;

export function maskEncodedBlobs(text) {
  const n = text.length;
  let parts = null;
  let last = 0;
  for (let i = 0; i < n;) {
    if (!isBlobChar(text.charCodeAt(i))) { i++; continue; }
    let j = i + 1;
    while (j < n && isBlobChar(text.charCodeAt(j))) j++;
    // Kept: shorter than the threshold, or a PEM body right after `-----\` or `-----\r\`.
    const pemBody = text.startsWith("-----\\", i - 6) || text.startsWith("-----\\r\\", i - 8);
    if (j - i >= BLOB_MIN && !pemBody) {
      let e = j;
      for (let k = 0; k < 2 && e < n && text.charCodeAt(e) === 61; k++) e++; // up to two "=" of padding
      (parts ||= []).push(text.slice(last, i), " ".repeat(e - i));
      last = e;
      i = e;
      continue;
    }
    i = j;
  }
  if (!parts) return text;
  parts.push(text.slice(last));
  return parts.join("");
}

/**
 * Find secrets in a string of text (a source file, a JS bundle, a config).
 * Returns every hit: `{ name, severity, match, index }`, with the raw match so
 * callers decide how to mask it. Placeholder values are skipped one match at a
 * time, so a placeholder never hides a real secret of the same rule later in
 * the text. At most one rule fires per span: once a specific AI-provider rule
 * matches a span, broader rules skip that span. `path` (relative, forward
 * slashes) says what kind of file this is: in a config file a bare value
 * (`password: s3cret`) counts too.
 */
export function findSecretsInText(content, opts = {}) {
  const hits = findIn(content, opts);
  // JSON and JavaScript read "\u0073k_live_" as "sk_live_". The raw text is the evidence; a
  // decoded copy is only searched, and what it finds points at the start of its line.
  const decoded = decodeEscapes(content);
  if (decoded === content) return hits;
  const lineStarts = lineStartsOf(content);
  const decodedStarts = lineStartsOf(decoded);
  const seen = new Set(hits.map((h) => `${h.name}|${lineIn(lineStarts, h.index)}`));
  for (const h of findIn(decoded, opts)) {
    const line = lineIn(decodedStarts, h.index);
    if (seen.has(`${h.name}|${line}`)) continue;
    seen.add(`${h.name}|${line}`);
    hits.push({ ...h, index: lineStarts[line - 1] });
  }
  return hits;
}

/** \uXXXX escapes as the characters they stand for, when printable: never a line break, so lines stay. */
function decodeEscapes(text) {
  if (!text.includes("\\u")) return text;
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (m, hex) => {
    const c = parseInt(hex, 16);
    return c >= 0x20 && c !== 0x7f && (c < 0xd800 || c > 0xdfff) ? String.fromCharCode(c) : m;
  });
}

/**
 * Whether a fixed-format hit may carry a value tag (tagOf). The tag is a fast,
 * unkeyed verifier with its salt in the same report, so a value a person may
 * have chosen must never get one (Vercel Security Review B and the
 * Fact-checker, 2.3.2). Only a whole token qualifies, outside every
 * assignment-rule span and outside URL userinfo; the weak legacy `sk-` shape
 * never does. A hit that gets no tag is still reported, and its baseline
 * compares count and masked value instead.
 */
const TOKEN_BEFORE = /^(?:|[\s"'`=:,])$/;
const TOKEN_AFTER = /^(?:|[\s"'`,])$/;
const NEVER_TAGGED = new Set(["secret.openai-api-key-legacy-format"]);
const USERINFO_END = new Set([..." \t\r\n/?#\"'`"]);

/**
 * The user:password part of every scheme://user:pass@host. A scan from each
 * `://` to the next delimiter: linear, where a regex with the scheme in front
 * took quadratic time on a long run of letters.
 */
function userinfoSpans(content, out) {
  for (let i = content.indexOf("://"); i !== -1; i = content.indexOf("://", i + 3)) {
    let j = i + 3;
    while (j < content.length && !USERINFO_END.has(content[j]) && content[j] !== "@") j++;
    if (content[j] === "@") out.push([i + 3, j + 1]);
  }
}

function wholeToken(content, start, end) {
  const before = content[start - 1] || "";
  if (!TOKEN_BEFORE.test(before) || !TOKEN_AFTER.test(content[end] || "")) return false;
  // `:` before the match is a YAML or JSON key, never a URL's user:password.
  if (before !== ":") return true;
  const lead = content.slice(Math.max(0, start - 300), start - 1);
  const at = lead.lastIndexOf("://");
  return at === -1 || [...lead.slice(at + 3)].some((c) => USERINFO_END.has(c) || c === "@");
}

// A test location: a test folder or a *.test.* / *.spec.* file, or a verify-
// or smoke- script directly in scripts/. Any other scripts/ file is real code.
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|e2e|cypress|playwright)\/|\.(?:test|spec)\.[^/]+$|(?:^|\/)scripts?\/(?:verify|smoke)-[^/]+\.[cm]?[jt]sx?$/i;
// The test account's address, as a value: `testEmail = "…"` or `username: "…"`,
// the whole string an address at a reserved test domain (RFC 2606, 6761).
const TEST_ADDRESS = /^[\w.+%${}-]{1,64}@((?:[a-z0-9-]+\.)*(?:example\.(?:com|net|org)|[a-z0-9-]+\.(?:test|example|invalid|localhost)))$/i;
const ACCOUNT_NAME = /email|user|login/i;
const IDENT = /[A-Za-z_$][\w$]*/y;
/** A code line as tokens; a string literal is one token, so text inside it is never code. Null if one is unclosed. */
function lineTokens(line) {
  const out = [];
  for (let i = 0; i < line.length;) {
    const ch = line[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1, v = "";
      while (j < line.length && line[j] !== ch) { if (line[j] === "\\") { v += line[j + 1] ?? ""; j += 2; } else v += line[j++]; }
      if (j >= line.length) return null;
      out.push({ str: true, v });
      i = j + 1;
      continue;
    }
    IDENT.lastIndex = i;
    const m = IDENT.exec(line);
    out.push(m ? { id: true, v: m[0] } : { v: ch });
    i += m ? m[0].length : 1;
  }
  return out;
}
/** A field set to a test address, at a code position: `name`/`"name"`, `:` or `=`, one whole string, then , ; } ) or the end. */
function accountField(line) {
  const t = lineTokens(line);
  for (let k = 0; t && k + 2 < t.length; k++) {
    const [key, op, val, next] = [t[k], t[k + 1], t[k + 2], t[k + 3]];
    if (!(key.id || key.str) || (op.v !== ":" && op.v !== "=") || !val.str || !ACCOUNT_NAME.test(key.v) || key.v.length > 64) continue;
    if (next && !(!next.id && !next.str && ",;})".includes(next.v))) continue;
    const addr = TEST_ADDRESS.exec(val.v);
    if (addr) return { name: key.v, domain: addr[1].toLowerCase() };
  }
  return null;
}
/**
 * The code lines of a window, in one pass: block, line and `#` comments and
 * multi-line template literals are blanked across lines (a window that starts
 * inside a comment is blanked up to its end), and a line that ends inside a
 * quote (a regex such as /"/, or text) or starts with `*` is dropped.
 */
function codeLines(near) {
  const c = [...near];
  const blank = (a, b) => { for (let k = a; k < b; k++) if (c[k] !== "\n") c[k] = " "; };
  const open = near.indexOf("/*"), close = near.indexOf("*/");
  let i = close !== -1 && (open === -1 || close < open) ? (blank(0, close + 2), close + 2) : 0;
  const bad = new Set();
  let line = near.slice(0, i).split("\n").length - 1;
  for (; i < c.length; i++) {
    const ch = near[i];
    if (ch === "\n") { line++; continue; }
    if (ch === "/" && near[i + 1] === "*") { const j = near.indexOf("*/", i + 2); const e = j === -1 ? c.length : j + 2; line += near.slice(i, e).split("\n").length - 1; blank(i, e); i = e - 1; continue; }
    if ((ch === "/" && near[i + 1] === "/") || (ch === "#" && (i === 0 || /\s/.test(near[i - 1])))) { const j = near.indexOf("\n", i); const e = j === -1 ? c.length : j; blank(i, e); i = e - 1; continue; }
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < near.length && near[j] !== ch && (ch === "`" || near[j] !== "\n")) j += near[j] === "\\" ? 2 : 1;
      if (ch === "`" && near.slice(i, j).includes("\n")) { line += near.slice(i, j + 1).split("\n").length - 1; blank(i, j + 1); i = j; continue; }
      if (j >= near.length || near[j] !== ch) { bad.add(line); i = j - 1; continue; }
      i = j;
    }
  }
  return c.join("").split("\n").filter((l, n) => !bad.has(n) && !/^\s*\*/.test(l));
}
const NEAR_LINES = 3;
// Bounded read per hit, however long the line.
const NEAR_CHARS = 1000;

/**
 * Why a password hit is a test account's, or null. Proven, not matched: a test
 * location, and an email, user or login field set to a test address, as code
 * (never a comment), within NEAR_LINES lines.
 */
function testAccountReason(content, index, path, fileCode) {
  if (!path || !TEST_PATH.test(path)) return null;
  let from = index;
  for (let n = 0; n <= NEAR_LINES && from > 0; n++) from = content.lastIndexOf("\n", from - 1);
  let to = index;
  for (let n = 0; n <= NEAR_LINES && to !== -1; n++) to = content.indexOf("\n", to + 1);
  const a = Math.max(0, from, index - NEAR_CHARS);
  const b = Math.min(to === -1 ? content.length : to, index + NEAR_CHARS);
  const near = content.slice(a, b);
  // The window must read the same lexed alone as lexed from the file's start:
  // if not, it starts inside a template, string or comment, and its text is
  // not code. No file-start state (a later chunk): no downgrade (Vercel, row 14).
  const whole = fileCode();
  if (whole === null || lexJs(near).code !== whole.slice(a, b)) return null;
  for (const code of codeLines(near)) {
    const f = accountField(code);
    if (f) return `\`${f.name}\` is set to an address at ${f.domain} on a nearby line, in a test location`;
  }
  return null;
}

const overlaps = (spans, start, end) => spans.some(([a, b]) => start < b && end > a);

const TEST_ACCOUNT_LEX_MAX = 4 * 1024 * 1024;

function findIn(content, { shapesOnly = false, path = "", fromFileStart = false } = {}) {
  content = maskEncodedBlobs(content);
  // Lexed once, from the file's start, only when a test-account hit needs it.
  let lexed;
  // Past TEST_ACCOUNT_LEX_MAX the text is not lexed and no hit is downgraded: the
  // check only ever lowers confidence, so not knowing keeps the finding as it is
  // (a 60 MiB file peaked at 1.35 GB, Mythos review of PR 281).
  const fileCode = () => (lexed === undefined ? (lexed = fromFileStart && content.length <= TEST_ACCOUNT_LEX_MAX ? lexJs(content).code : null) : lexed);
  const ctx = { config: !!path && isConfigFile(path) };
  const hits = [];
  const claimed = [];
  // Every span an assignment-style rule (generic key, password, JWT, session,
  // a pack rule that guesses by name) matches, before any filter: a key-shaped
  // value inside one may be a value a person chose. When those rules did not
  // run (shapesOnly) or stopped early, the spans are not known, so nothing is tagged.
  const assigned = [];
  let spansKnown = !shapesOnly;
  userinfoSpans(content, assigned);
  for (const rule of secretPatterns()) {
    if (shapesOnly && !rule.shape) continue;
    let found = 0;
    for (const match of allMatches(rule, content)) {
      const start = match.index;
      const end = start + match[0].length;
      if (!rule.shape) assigned.push([start, end]);
      // For assignment-style rules, test the placeholder/dummy filter against
      // the assigned value only (not the whole `key = "value"` match), so a
      // variable named e.g. `testToken` can't mask a real secret.
      const value = match.groups?.v ?? match.groups?.u ?? (match[0].match(/['"]([^'"]+)['"]/) || [, match[0]])[1];
      if (rule.skipIf && rule.skipIf.test(value)) continue;
      if (rule.accept && !rule.accept(match, ctx)) continue;
      if (claimed.some(([a, b]) => start < b && end > a)) continue;
      claimed.push([start, end]);
      const hit = { name: rule.name, severity: rule.severity, match: match[0], index: start };
      if (rule.name === "Hardcoded password") {
        const why = testAccountReason(content, start, path, fileCode);
        if (why) hit.testAccount = why;
      }
      if (rule.shape && !NEVER_TAGGED.has(rule.rule?.id) && wholeToken(content, start, end)) hit.taggable = [start, end];
      hits.push(hit);
      if (++found >= MAX_HITS_PER_RULE) {
        if (!rule.shape) spansKnown = false;
        // Past the cap the rest is unread: none may go to Check first.
        for (const h of hits) if (h.name === rule.name) delete h.testAccount;
        break;
      }
    }
  }
  // Decided once every span is known: a later rule can cover an earlier hit.
  for (const h of hits) {
    if (!h.taggable) continue;
    if (spansKnown && !overlaps(assigned, ...h.taggable)) h.taggable = true;
    else delete h.taggable;
  }
  return hits;
}

/**
 * Where each line of `text` starts, built once per text. Looking each hit up
 * in it keeps a file with many lines and many hits linear: rescanning from
 * offset 0 for every hit took about 19 s on a hostile 2 MB bundle (C03).
 */
function lineStartsOf(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

/** 1-based line number of a character offset: how many lines start at or before it. */
function lineIn(starts, index) {
  let lo = 0;
  let hi = starts.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (starts[mid] <= index) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Open a regular file for reading, or null when it is not one (anymore): it
 * vanished, or was swapped for a FIFO, device or symlink after the walk.
 * O_NONBLOCK: a FIFO must not make open wait for a writer. O_NOFOLLOW: never
 * read through a symlink.
 */
function openRegularFile(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
    const st = fstatSync(fd);
    if (!st.isFile()) { closeSync(fd); return { error: "it is not a regular file" }; }
    return { fd, size: st.size };
  } catch (e) {
    if (fd !== undefined) closeSync(fd);
    // Gone since the listing (a swap file, build output): nothing to read.
    return e.code === "ENOENT" ? null : { error: e.code || e.message };
  }
}


/**
 * The whole file's text, read up to `size` bytes. Files are read whole, never
 * in pieces: piece edges and their overlap were where a secret could hide, and
 * the size cap (MAX_SCAN_BYTES) keeps memory bounded instead.
 */
function readWhole(fd, size) {
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = readSync(fd, buf, off, size - off, off);
    if (n === 0) break;
    off += n;
  }
  return { text: buf.subarray(0, off).toString("utf-8"), linesBefore: 0 };
}

// An ignored file never reaches a commit, so a key in it is a local dev
// secret (the usual `.env`), not a leak. It is still reported, at this
// severity, so a key that is shared some other way is not invisible.
const LOCAL_ONLY_SEVERITY = "low";

/**
 * Scan a repository's files for secrets. `ignored` is what git ignores under
 * `repoPath` (gitIgnored() in lib/git.js): ignored folders are skipped and a
 * hit in an ignored file is reported as local only. It is passed in rather
 * than looked up here so this module never runs git (the site bundles it).
 */
export function scanSecrets(repoPath, { maxBytes = MAX_SCAN_BYTES, ignored = null, refused = null } = {}) {
  const findings = [];
  const skipDir = ignored ? (dir) => ignored.dirs.has(dir) : undefined;
  // A file the scan could not read goes to `refused` ({ path, reason, message }),
  // so the caller names it and the run is incomplete (exit 2).
  const refuse = (path, reason) => refused?.push({ path, reason, message: `${relative(repoPath, path).split(/[\\/]/).join("/")} was not read: ${reason}` });
  const special = [];
  const files = walkFiles(repoPath, [], repoPath, skipDir, special);
  for (const s of special) refuse(s.path, s.reason);

  for (const filePath of files) {
    const file = openRegularFile(filePath);
    if (!file) continue;
    if (file.error) {
      if (wantsFile(filePath.split(/[\\/]/).pop())) refuse(filePath, file.error);
      continue;
    }

    const rel = relative(repoPath, filePath);
    const localOnly = !!ignored && ignored.files.has(filePath);
    let head = "";
    if (!wantsFile(filePath.split(/[\\/]/).pop())) {
      // An extensionless file is read only if it starts like a key.
      const buf = Buffer.alloc(Math.min(file.size, 256));
      readSync(file.fd, buf, 0, buf.length, 0);
      head = buf.toString("utf-8");
    }
    const scope = secretRulesFor(rel.split(/[\\/]/).join("/"), head);
    if (!scope) { closeSync(file.fd); continue; }
    const shapesOnly = scope === "shapes";

    try {
      if (file.size > maxBytes && refused) {
        refuse(filePath, `it is over the ${Math.round(maxBytes / 1024 / 1024)} MiB secret-scan limit`);
        continue;
      }
      if (file.size > maxBytes) {
        findings.push({
          severity: "info",
          title: "File too large to scan for secrets",
          description: `\`${rel}\` is ${file.size} bytes, over the ${maxBytes}-byte secret-scan limit, so it was not checked.`,
          url: rel,
          category: "secrets",
          source: "secret-scan",
        });
        continue;
      }

      // One finding per rule per file (the finding id is per rule and file),
      // pointing at the first hit; every hit's line is listed in `lines`, so a
      // file with ten keys shows ten places to fix. A hit in the overlap of
      // two chunks is seen twice and listed once.
      const byRule = new Map();
      for (const { text, linesBefore } of [readWhole(file.fd, file.size)]) {
        let starts = null;
        for (const hit of findSecretsInText(text, { shapesOnly, path: rel.split(/[\\/]/).join("/"), fromFileStart: linesBefore === 0 })) {
          starts ??= lineStartsOf(text);
          const line = linesBefore + lineIn(starts, hit.index);
          const seen = byRule.get(hit.name);
          // One non-test hit puts it back in Act on.
          if (seen && !hit.testAccount && seen.finding.confidence === "potential") {
            delete seen.finding.confidence;
            seen.finding.description = seen.plain;
          }
          if (seen) {
            if (seen.lines.size < MAX_LINES_PER_FINDING) seen.lines.add(line);
            if (seen.tags.size < MAX_LINES_PER_FINDING) seen.tags.add(tagOf(hit));
            continue;
          }
          const finding = {
            severity: localOnly ? LOCAL_ONLY_SEVERITY : hit.severity,
            title: `${hit.name} in source`,
            description: localOnly
              ? `Possible secret in \`${rel}\`: \`${maskMatch(hit.match)}\`. The file is ignored by git, so it is not committed; it is reported at ${LOCAL_ONLY_SEVERITY} instead of ${hit.severity}. Rotate the key if this file was ever shared.`
              : `Possible secret in \`${rel}\`: \`${maskMatch(hit.match)}\``,
            url: rel,
            line,
            category: "secrets",
            source: "secret-scan",
            ...(localOnly ? { localOnly: true } : {}),
          };
          const plain = finding.description;
          if (hit.testAccount && !localOnly) {
            finding.confidence = "potential";
            finding.description = `Possible test password in \`${rel}\` (${hit.testAccount}): \`${maskMatch(hit.match)}\`. Check it is a test account's, not a real one.`;
          }
          byRule.set(hit.name, { finding, plain, lines: new Set([line]), tags: new Set([tagOf(hit)]) });
          findings.push(finding);
        }
      }
      for (const { finding, lines, tags } of byRule.values()) {
        // Salted one-way tags of every value this finding holds (lib/secret-tags.js):
        // a baseline compares them, so a swapped key is new, never "unchanged".
        // Only for fixed-format rules, and only when every value is long enough
        // to show as abcd…wxyz (tagOf): a tag of a password or of a value masked
        // as *** could be brute-forced from the salt in the same report, so such
        // a finding keeps the count check.
        if (!tags.has(null)) finding.valueTags = [...tags].sort();
        if (lines.size < 2) continue;
        finding.lines = [...lines].sort((a, b) => a - b);
        const more = finding.lines.slice(1);
        const shown = more.slice(0, 10).join(", ");
        finding.description += ` Also on line${more.length > 1 ? "s" : ""} ${shown}${more.length > 10 ? ` and ${more.length - 10} more` : ""}.`;
      }
    } finally {
      closeSync(file.fd);
    }
  }

  return findings;
}
