/**
 * The one place agent findings hide secrets in what they show: a launch
 * command, a hook command, a registry URL, a permission rule. Findings quote
 * config so the reader can find the line; the quote must never carry the
 * credential that sits in it.
 *
 * - redactUrl: strips URL userinfo (`https://user:pass@host` → `https://***@host`)
 *   and the values of secret-named query parameters (`?token=***`).
 * - redactCommand: redactUrl, plus the value after a secret-named flag
 *   (`--api-key ***`), `name=***` and `Name: ***` with a secret name,
 *   `Bearer|Basic|Token ***`, `curl -u ***`, `mysql -p***`, and every hit of
 *   the secret scan (shown as maskMatch shows rule hits).
 *
 * Every replacement is made by a regex over the same string it changes, and a
 * hit is replaced by its own text, never by an offset into another copy
 * (R14). A finding that quotes only part of a command passes the whole
 * command as `context`: what the redactor finds there is also hidden in the
 * part, so a fragment that lost the flag in front of a value still hides it.
 */
import { findSecretsInText, maskMatch } from "../whitebox/secrets.js";

const HIDDEN = "***";
// A word that names a credential. The regexes find a candidate name with any
// of these in it; isSecretName() then decides on the whole name, so `pat` in
// `--path`, `key` in `--keyboard` and `sig` in `--signal` are not credentials.
const SECRET_WORD = String.raw`(?:token|secret|passw(?:or)?d|passwd|pwd|pass|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|bearer|cookie|session|signature|sig|key|pat)`;
// A value: ANSI-C quoted ($'…'), quoted, or bare.
const VALUE = String.raw`(?:\$'(?:[^'\\\n]|\\.){0,512}'|\$?"[^"\n]*"|'[^'\n]*'|[^\s"'\`;&|),]+)`;

// Name parts are bounded ({0,64}) so a long run of word characters cannot
// make a pattern quadratic: these run over whole hook scripts.
const NAME = String.raw`[\w.-]{0,64}`;

// scheme://userinfo@ : everything before the last @ of the authority.
const USERINFO = /\b([a-z][a-z0-9+.-]{0,30}:\/\/)([^\s/?#"'`@]*@)+/gi;
// ?name=value or &name=value with a secret-looking name.
const QUERY_SECRET = new RegExp(String.raw`([?&;])([^=&#\s"'\`]{0,64}?${SECRET_WORD}[^=&#\s"'\`]{0,64})(=)([^&#\s"'\`]*)`, "gi");
// --api-key value, --api-key=value, -token value.
const FLAG_SECRET = new RegExp(String.raw`((?:^|[\s"'(])--?)(${NAME}?${SECRET_WORD}${NAME})(=|\s+)(${VALUE})`, "gi");
// NAME=value with a secret-looking name.
const ASSIGN_SECRET = new RegExp(String.raw`\b(${NAME}?${SECRET_WORD}${NAME})(=)(${VALUE})`, "gi");
// Header-style `X-Api-Key: value`, `Cookie: a=b`, `"api_key": "value"`.
const HEADER_SECRET = new RegExp(String.raw`\b([\w-]{0,64}?${SECRET_WORD}[\w-]{0,64})(["']?[ \t]*:[ \t]*)(?!\/\/)(?!(?:Bearer|Basic|Token|Digest)\b)(${VALUE})`, "gi");
// An auth scheme and its credential.
const SCHEME_SECRET = new RegExp(String.raw`(\b(?:Bearer|Basic|Token|Digest)\s+)(${VALUE})`, "gi");
// curl/wget `-u user:pass`, `--user user:pass`, `--proxy-user user:pass`: only a value with a colon.
const USER_PASS = new RegExp(String.raw`((?:^|[\s"'(])(?:-u|-U|--user|--proxy-user|--http-user)(?:=|\s+))("[^"\n:]{0,256}:[^"\n]{0,256}"|'[^'\n:]{0,256}:[^'\n]{0,256}'|[^\s"'\`;&|:]{0,256}:[^\s"'\`;&|]{0,256})`, "g");
// Tools whose short flag takes a password: `mysql -pSECRET` (mysqldump,
// mariadb...), `sshpass -p`, `docker login -p` (podman, helm registry
// login...), `redis-cli -a`, `openssl -k`. Only these: `-p` is a port in
// `docker run -p 8080:80` and `psql -p 5432`, and a project in `docker compose -p`.
const TOOL_PASS = new RegExp(String.raw`(\b(?:(?:mysql\w{0,20}|mariadb\w{0,20}|sshpass)\b[^\n|;&]{0,200}?\s-p\s*|(?:docker|podman|nerdctl|helm|oras|skopeo|buildah)(?:\s+registry)?\s+login\b[^\n|;&]{0,200}?\s-p\s*|redis-cli\b[^\n|;&]{0,200}?\s-a\s*|openssl\b[^\n|;&]{0,200}?\s-[kK]\s+))(${VALUE})`, "g");
// `htpasswd -b [file] user password`: the last of the plain arguments.
const HTPASSWD = new RegExp(String.raw`(\bhtpasswd\b(?:\s+-\w{1,8}){0,8}?\s+-\w{0,8}b\w{0,8}(?:\s+-\w{1,8}){0,8}\s+(?:${VALUE}\s+)?${VALUE}\s+)(${VALUE})`, "g");
// A curl or wget command, up to the end of its stage, and its -H/--header values.
const CURL_SEGMENT = /\b(?:curl|wget)\b[^\n|;&]*/g;
const HEADER_FLAG = new RegExp(String.raw`((?:^|\s)(?:-H|--header)(?:=|\s+))(${VALUE})`, "g");
// Headers whose value is never a credential; every other -H value is hidden.
const SAFE_HEADERS = new Set([
  "accept", "accept-charset", "accept-encoding", "accept-language", "cache-control", "connection", "content-encoding",
  "content-language", "content-length", "content-type", "dnt", "expect", "host", "if-match", "if-modified-since",
  "if-none-match", "origin", "pragma", "range", "referer", "te", "upgrade-insecure-requests", "user-agent",
  "x-forwarded-for", "x-forwarded-proto", "x-github-api-version", "x-requested-with",
]);

// Whole parts of a name that make it a credential (`GH_PAT`, `X-Auth`, `db.pass`, `apiKey`).
const SECRET_PARTS = new Set(["key", "sig", "auth", "pat", "pass", "pwd", "passwd", "oauth", "secret", "token", "cookie", "session", "bearer", "credential", "credentials", "signature", "password", "passphrase", "apikey", "jwt"]);
// Words that make a name a credential wherever they sit in it (`PGPASSWORD`, `authToken`).
const SECRET_INFIX = /token|secret|passw(?:or)?d|passphrase|api_?key|access_?key|private_?key|credential|bearer|cookie|signature|authoriz/;
// A value that is a switch, not a credential (`AUTH_ENABLED=true`).
const NOT_A_SECRET = /^(?:["']?)(?:true|false|yes|no|on|off|none|null|nil|enabled?|disabled?|[01])(?:["']?)$/i;

/**
 * Does this name (`--api-key`, `GH_PAT`, `X-Auth-Token`, `apiKey`) name a
 * credential? The short words (key, sig, auth, pat, pass, pwd) count only as
 * a whole part of the name: split at `_`, `-`, `.` and a camelCase step.
 */
export function isSecretName(name) {
  const raw = String(name ?? "");
  const flat = raw.toLowerCase().replace(/[-.]/g, "_");
  if (SECRET_INFIX.test(flat.replace(/_/g, "")) || SECRET_INFIX.test(flat)) return true;
  const parts = raw.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/);
  return parts.some((p) => SECRET_PARTS.has(p));
}

const keepQuotes = (v) => {
  const m = /^(\$?)(["']).*\2$/s.exec(v);
  return m ? `${m[1]}${m[2]}${HIDDEN}${m[2]}` : HIDDEN;
};
const unquote = (v) => String(v ?? "").replace(/^\$?(["'])(.*)\1$/s, "$2");
const secretValue = (name, v) => isSecretName(name) && !NOT_A_SECRET.test(unquote(v));

/** URL userinfo and secret-named query values, hidden. */
export function redactUrl(text) {
  return String(text ?? "")
    .replace(USERINFO, (_, scheme) => `${scheme}${HIDDEN}@`)
    .replace(QUERY_SECRET, (all, lead, name, eq, v) => (secretValue(name, v) ? `${lead}${name}${eq}${HIDDEN}` : all));
}

/** A -H value with the credential after the header name hidden, unless the header is on the safe list. */
function maskHeaderValue(v) {
  const m = /^(\$?["']?)([^:\s"']{1,128})(:[ \t]*)(?:(Bearer|Basic|Token|Digest)(\s+))?(.*?)(["']?)$/s.exec(v);
  if (!m || SAFE_HEADERS.has(m[2].toLowerCase()) || !m[6] || m[6] === HIDDEN) return v;
  return `${m[1]}${m[2]}${m[3]}${m[4] ? m[4] + m[5] : ""}${HIDDEN}${m[7]}`;
}

/** The credential part of a -H value (for hiding it in a quoted part), or null. */
function headerSecret(v) {
  const m = /^\$?["']?([^:\s"']{1,128}):[ \t]*(?:(?:Bearer|Basic|Token|Digest)\s+)?(.*?)["']?$/s.exec(v);
  return m && !SAFE_HEADERS.has(m[1].toLowerCase()) && m[2] ? m[2] : null;
}

const maskCurlHeaders = (text) =>
  text.replace(CURL_SEGMENT, (seg) => seg.replace(HEADER_FLAG, (_, flag, v) => `${flag}${maskHeaderValue(v)}`));

/**
 * The values the patterns above would hide in `text` (for hiding them in a
 * quoted part of it). Only credentials: a value under a secret name, a URL's
 * userinfo, an auth scheme's credential, a tool's password argument.
 */
function secretValues(text) {
  const out = [];
  const add = (v) => {
    const s = unquote(v);
    if (s.length >= 4 && s !== HIDDEN) out.push(s);
  };
  for (const m of text.matchAll(USERINFO)) {
    const info = m[0].slice(m[1].length, -1);
    add(info);
    for (const part of info.split(/[:@]/)) add(part);
  }
  for (const m of text.matchAll(QUERY_SECRET)) if (secretValue(m[2], m[4])) add(m[4]);
  for (const m of text.matchAll(FLAG_SECRET)) if (secretValue(m[2], m[4])) add(m[4]);
  for (const m of text.matchAll(ASSIGN_SECRET)) if (secretValue(m[1], m[3])) add(m[3]);
  for (const m of text.matchAll(HEADER_SECRET)) if (secretValue(m[1], m[3])) add(m[3]);
  for (const m of text.matchAll(SCHEME_SECRET)) add(m[2]);
  for (const m of text.matchAll(USER_PASS)) {
    add(m[2]);
    add(m[2].replace(/^["']|["']$/g, "").split(":").slice(1).join(":"));
  }
  for (const m of text.matchAll(TOOL_PASS)) add(m[2]);
  for (const m of text.matchAll(HTPASSWD)) add(m[2]);
  for (const seg of text.match(CURL_SEGMENT) || []) {
    for (const m of seg.matchAll(HEADER_FLAG)) add(headerSecret(m[2]));
  }
  return out;
}

/**
 * The longest k < |a| + 1 such that `a`'s first k characters are the last k
 * of `b` (KMP over `a`, run along `b`): linear in |a| + |b|.
 */
function overlap(a, b) {
  if (!a.length || !b.length) return 0;
  const pi = new Int32Array(a.length);
  for (let i = 1, k = 0; i < a.length; i++) {
    while (k && a[i] !== a[k]) k = pi[k - 1];
    if (a[i] === a[k]) k++;
    pi[i] = k;
  }
  let q = 0;
  for (let i = 0; i < b.length; i++) {
    if (q === a.length) q = pi[q - 1];
    while (q && b[i] !== a[q]) q = pi[q - 1];
    if (b[i] === a[q]) q++;
  }
  return q;
}

/**
 * Hide each value wherever it appears, and its start or end where the text
 * begins or ends inside it: a part cut from a command can cut a value in two.
 * Each overlap is found in one linear pass (no loop over every cut length),
 * so a long value costs its length, not its length squared.
 */
const hideAll = (text, values) => {
  let out = text;
  const vs = [...new Set(values)].sort((a, b) => b.length - a.length);
  for (const v of vs) if (out.includes(v)) out = out.split(v).join(HIDDEN);
  for (const v of vs) {
    // The text starts with the end of v: the longest prefix of the text that is a suffix of v.
    const head = overlap(out.slice(0, v.length - 1), v);
    if (head >= 4) out = HIDDEN + out.slice(head);
    // The text ends with the start of v: the longest prefix of v that is a suffix of the text.
    const tail = overlap(v.slice(0, v.length - 1), out.slice(-(v.length - 1)));
    if (tail >= 4) out = out.slice(0, -tail) + HIDDEN;
  }
  return out;
};

/**
 * A command (or any config text) with every credential the patterns know
 * hidden. `context` is the whole text `text` was cut from, when it is a part.
 */
export function redactCommand(text, context = text) {
  let out = String(text ?? "");
  const whole = String(context ?? "");
  // Secret-scan hits first, on the text as written. A hit found only in the
  // decoded copy of the text (\u escapes) has no place in the raw text, so the
  // whole text is withheld rather than guessed at.
  for (const src of whole === out ? [out] : [out, whole]) {
    for (const h of findSecretsInText(src)) {
      if (!src.includes(h.match)) return "(not shown: it holds an escaped secret)";
      if (out.includes(h.match)) out = out.split(h.match).join(maskMatch(h.match));
      else if (src === whole) out = hideAll(out, secretValues(h.match).concat(bareValue(h.match)));
    }
  }
  const fromContext = whole === String(text ?? "") ? [] : secretValues(whole);
  out = maskCurlHeaders(redactUrl(out))
    .replace(FLAG_SECRET, (all, dash, name, sep, v) => (secretValue(name, v) ? `${dash}${name}${sep}${keepQuotes(v)}` : all))
    .replace(ASSIGN_SECRET, (all, name, eq, v) => (secretValue(name, v) ? `${name}${eq}${keepQuotes(v)}` : all))
    .replace(HEADER_SECRET, (all, name, sep, v) => (secretValue(name, v) ? `${name}${sep}${keepQuotes(v)}` : all))
    .replace(SCHEME_SECRET, (_, scheme, v) => `${scheme}${keepQuotes(v)}`)
    .replace(USER_PASS, (_, flag, v) => `${flag}${keepQuotes(v)}`)
    .replace(TOOL_PASS, (_, head, v) => `${head}${keepQuotes(v)}`)
    .replace(HTPASSWD, (_, head, v) => `${head}${keepQuotes(v)}`);
  return hideAll(out, fromContext);
}

/** The value part of a rule hit (`KEY="v"` → v), for hiding it in a part of the text. */
function bareValue(match) {
  const m = /[=:]\s*["'`]?([^"'`\s]{4,})/.exec(match);
  return m ? [m[1]] : match.length >= 4 ? [match] : [];
}
