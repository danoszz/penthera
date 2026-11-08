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
  const parts = raw.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/(?<=[A-Z])(?=[A-Z][a-z])/g, "_").toLowerCase().split(/[^a-z0-9]+/);
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
/**
 * `"Name: Bearer value"` split into its parts in code. One regex for all of it
 * backtracked: its whitespace runs and the lazy value could trade characters
 * (quadratic on a padded header).
 */
function headerParts(v) {
  const head = /^(\$?["']?)([^:\s"']{1,128}):/.exec(v);
  if (!head) return null;
  let i = head[0].length;
  while (v[i] === " " || v[i] === "\t") i++;
  const sep = v.slice(head[0].length - 1, i);
  const scheme = /^(Bearer|Basic|Token|Digest)(\s+)/.exec(v.slice(i));
  if (scheme) i += scheme[0].length;
  let value = v.slice(i);
  const quote = /["']$/.test(value) ? value.slice(-1) : "";
  if (quote) value = value.slice(0, -1);
  return { pre: head[1], name: head[2], sep, scheme: scheme ? scheme[1] + scheme[2] : "", value, quote };
}

function maskHeaderValue(v) {
  const h = headerParts(v);
  if (!h || SAFE_HEADERS.has(h.name.toLowerCase()) || !h.value || h.value === HIDDEN) return v;
  return `${h.pre}${h.name}${h.sep}${h.scheme}${HIDDEN}${h.quote}`;
}

/** The credential part of a -H value (for hiding it in a quoted part), or null. */
function headerSecret(v) {
  const h = headerParts(v);
  return h && !SAFE_HEADERS.has(h.name.toLowerCase()) && h.value ? h.value : null;
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
  const scanned = []; // the secret scan's hits, for hiding their encoded forms
  // Secret-scan hits first, on the text as written. A hit found only in the
  // decoded copy of the text (\u escapes) has no place in the raw text, so the
  // whole text is withheld rather than guessed at.
  for (const src of whole === out ? [out] : [out, whole]) {
    for (const h of findSecretsInText(src)) {
      if (!src.includes(h.match)) return "(not shown: it holds an escaped secret)";
      scanned.push(...bareValue(h.match), h.match);
      if (out.includes(h.match)) out = out.split(h.match).join(maskMatch(h.match));
      else if (src === whole) out = hideAll(out, secretValues(h.match).concat(bareValue(h.match)));
    }
  }
  const known = secretValues(whole);
  const fromContext = whole === String(text ?? "") ? [] : known;
  out = maskCurlHeaders(redactUrl(out))
    .replace(FLAG_SECRET, (all, dash, name, sep, v) => (secretValue(name, v) ? `${dash}${name}${sep}${keepQuotes(v)}` : all))
    .replace(ASSIGN_SECRET, (all, name, eq, v) => (secretValue(name, v) ? `${name}${eq}${keepQuotes(v)}` : all))
    .replace(HEADER_SECRET, (all, name, sep, v) => (secretValue(name, v) ? `${name}${sep}${keepQuotes(v)}` : all))
    .replace(SCHEME_SECRET, (_, scheme, v) => `${scheme}${keepQuotes(v)}`)
    .replace(USER_PASS, (_, flag, v) => `${flag}${keepQuotes(v)}`)
    .replace(TOOL_PASS, (_, head, v) => `${head}${keepQuotes(v)}`)
    .replace(HTPASSWD, (_, head, v) => `${head}${keepQuotes(v)}`);
  return hideEncoded(hideAll(out, fromContext), known.concat(scanned));
}

// ── Encoded copies of a secret ───────────────────────────────────────────
// A credential set in plain text can be printed again encoded: `?u=ghp%5F…`
// in a URL, `a+b` for a space, base64 in a header, hex. The patterns above see
// only the plain form. So the runs in the quote that look encoded (percent
// escapes, base64, hex) are decoded, and a run is hidden when it holds a known
// value or a hit of the secret scan (Red Team E23). The work is the quote's
// few runs against the known values, never every value encoded every way.

// Runs cut at the characters that separate URL parts, so `?u=` stays readable.
const PCT_RUN = /(?:%[0-9A-Fa-f]{2}|[^\s%"'`<>|;&()=?/:#,@\\])+/g;
const PCT_ESCAPE = /%[0-9A-Fa-f]{2}|\+/;
const B64_RUN = /[A-Za-z0-9+/_-]{8,}={0,2}/g;
const HEX_RUN = /\b(?:[0-9A-Fa-f]{2}){4,}\b/g;
const latin1ToUtf8 = (s) => Buffer.from(s, "latin1").toString("utf8");
const PCT_DECODES = /%[0-9A-Fa-f]{2}/;
const PCT_ROUNDS = 4;
// Stands for a run too deeply encoded to read: always hidden.
const OPAQUE = "\u0000opaque\u0000";
const pctDecode = (s) => latin1ToUtf8(s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));

/** { start, end, ds } for every run of `text` that may be an encoded value; ds are its decoded texts. */
function encodedRuns(text) {
  const out = [];
  const at = (m, ds) => out.push({ start: m.index, end: m.index + m[0].length, ds });
  for (const m of text.matchAll(PCT_RUN)) {
    if (!PCT_ESCAPE.test(m[0])) continue;
    // Decoded again while it still holds escapes: `ghp%255F…` is ghp_ encoded
    // twice (Reviewer, Low). At most PCT_ROUNDS rounds; a run that still
    // decodes further is hidden whatever it holds (fail closed).
    const ds = [];
    let d = m[0];
    let round = 0;
    for (; round < PCT_ROUNDS && PCT_DECODES.test(d); round++) { d = pctDecode(d); ds.push(d, d.replace(/\+/g, " ")); }
    if (round === PCT_ROUNDS && PCT_DECODES.test(d)) ds.push(OPAQUE);
    if (!ds.length) ds.push(m[0].replace(/\+/g, " "));
    at(m, ds);
  }
  for (const m of text.matchAll(B64_RUN)) at(m, [Buffer.from(m[0], "base64").toString("utf8"), Buffer.from(m[0], "base64url").toString("utf8")]);
  for (const m of text.matchAll(HEX_RUN)) at(m, [Buffer.from(m[0], "hex").toString("utf8")]);
  return out;
}

/**
 * All of `needles` in one Aho-Corasick automaton: building it costs their
 * total length, and `test` or `spans` costs the text's length. Checking each
 * needle against each run was runs x needles (Vercel T, 2.3.2).
 * spans(text): [start, end) of the longest needle ending at each place.
 */
function matcher(needles) {
  const next = [new Map()];
  const fail = [0];
  const best = [0]; // the longest needle that ends at this state, by its suffixes too
  for (const v of needles) {
    let st = 0;
    for (let k = 0; k < v.length; k++) {
      const c = v[k];
      let to = next[st].get(c);
      if (to === undefined) { to = next.length; next.push(new Map()); fail.push(0); best.push(0); next[st].set(c, to); }
      st = to;
    }
    best[st] = Math.max(best[st], v.length);
  }
  const queue = [...next[0].values()];
  for (let k = 0; k < queue.length; k++) {
    const u = queue[k];
    for (const [c, v] of next[u]) {
      let f = fail[u];
      while (f && !next[f].has(c)) f = fail[f];
      const t = u === 0 ? undefined : next[f].get(c);
      fail[v] = t !== undefined && t !== v ? t : 0;
      best[v] = Math.max(best[v], best[fail[v]]);
      queue.push(v);
    }
  }
  const walk = (text, onEnd) => {
    let st = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      while (st && !next[st].has(c)) st = fail[st];
      st = next[st].get(c) ?? 0;
      if (best[st] && onEnd(i + 1, best[st])) return true;
    }
    return false;
  };
  return {
    test: (text) => walk(text, () => true),
    spans: (text) => { const out = []; walk(text, (end, len) => { out.push([end - len, end]); return false; }); return out; },
  };
}

/** `text` with each [start, end) span (sorted by start or not) replaced by HIDDEN, overlapping spans merged. */
function hideSpans(text, spans) {
  if (!spans.length) return text;
  spans.sort((x, y) => x[0] - y[0]);
  let out = "";
  let at = 0;
  for (const [start, end] of spans) {
    if (end <= at) continue;
    if (start >= at) out += text.slice(at, start) + HIDDEN;
    at = end;
  }
  return out + text.slice(at);
}

// The values a quote is checked against are capped: past either cap the
// excerpt is withheld (fail closed), never printed half checked.
const ENCODED_MAX_VALUES = 4096;
const ENCODED_MAX_CHARS = 1024 * 1024;
const WITHHELD = "(not shown: it may hold an encoded secret, and there are too many secret values to check)";

function hideEncoded(text, values) {
  const known = [...new Set(values.map(unquote))].filter((v) => v.length >= 4 && v !== HIDDEN);
  const runs = encodedRuns(text);
  if (!known.length && !runs.length) return text;
  const hits = runs.length ? findSecretsInText(runs.flatMap((r) => r.ds).join("\n")).flatMap((h) => [h.match, ...bareValue(h.match)]) : [];
  const needles = [...new Set(known.concat(hits))].filter((v) => v.length >= 4 && v !== HIDDEN);
  if (runs.some((r) => r.ds.includes(OPAQUE))) needles.push(OPAQUE);
  if (!needles.length) return text;
  if (needles.length > ENCODED_MAX_VALUES || needles.reduce((n, v) => n + v.length, 0) > ENCODED_MAX_CHARS) return WITHHELD;
  const m = matcher(needles);
  // A known value written out again elsewhere in the text, as it is, and the
  // runs that hold one once decoded; hidden in one rebuild.
  const spans = m.spans(text);
  for (const r of runs) if (r.ds.some(m.test)) spans.push([r.start, r.end]);
  return hideSpans(text, spans);
}

/** The value part of a rule hit (`KEY="v"` → v), for hiding it in a part of the text. */
function bareValue(match) {
  const m = /[=:]\s*["'`]?([^"'`\s]{4,})/.exec(match);
  return m ? [m[1]] : match.length >= 4 ? [match] : [];
}
