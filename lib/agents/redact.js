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
// A word that names a credential. Over-masking a harmless value is fine; a
// finding never needs the value of `--auth-mode` to make its point.
const SECRET_WORD = String.raw`(?:token|secret|passw(?:or)?d|passwd|pwd|pass|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|bearer|cookie|session|signature|sig|key)`;
const VALUE = String.raw`(?:"[^"\n]*"|'[^'\n]*'|[^\s"'\`;&|),]+)`;

// Name parts are bounded ({0,64}) so a long run of word characters cannot
// make a pattern quadratic: these run over whole hook scripts.
const NAME = String.raw`[\w.-]{0,64}`;

// scheme://userinfo@ : everything before the last @ of the authority.
const USERINFO = /\b([a-z][a-z0-9+.-]{0,30}:\/\/)([^\s/?#"'`@]*@)+/gi;
// ?name=value or &name=value with a secret-looking name.
const QUERY_SECRET = new RegExp(String.raw`([?&;][^=&#\s"'\`]{0,64}?${SECRET_WORD}[^=&#\s"'\`]{0,64}=)([^&#\s"'\`]*)`, "gi");
// --api-key value, --api-key=value, -token value.
const FLAG_SECRET = new RegExp(String.raw`((?:^|[\s"'(])--?${NAME}?${SECRET_WORD}${NAME})(=|\s+)(${VALUE})`, "gi");
// NAME=value with a secret-looking name.
const ASSIGN_SECRET = new RegExp(String.raw`(\b${NAME}?${SECRET_WORD}${NAME}=)(${VALUE})`, "gi");
// Header-style `X-Api-Key: value`, `Cookie: a=b`, `"api_key": "value"`.
const HEADER_SECRET = new RegExp(String.raw`(\b[\w-]{0,64}?${SECRET_WORD}[\w-]{0,64}["']?[ \t]*:[ \t]*)(?!\/\/)(?!(?:Bearer|Basic|Token|Digest)\b)(${VALUE})`, "gi");
// An auth scheme and its credential.
const SCHEME_SECRET = new RegExp(String.raw`(\b(?:Bearer|Basic|Token|Digest)\s+)(${VALUE})`, "gi");
// curl/wget `-u user:pass`, `--user user:pass`, `--proxy-user user:pass`: only a value with a colon.
const USER_PASS = new RegExp(String.raw`((?:^|[\s"'(])(?:-u|-U|--user|--proxy-user|--http-user)(?:=|\s+))("[^"\n:]{0,256}:[^"\n]{0,256}"|'[^'\n:]{0,256}:[^'\n]{0,256}'|[^\s"'\`;&|:]{0,256}:[^\s"'\`;&|]{0,256})`, "g");
// `-p` as a password flag: mysql -pSECRET (glued), docker login -p SECRET,
// sshpass -p SECRET. (docker run -p 8080:80 is a port and is hidden too.)
const MYSQL_PASS = /(\b(?:mysql\w{0,20}|docker|podman|nerdctl|skopeo|buildah|helm|oras|sshpass)\b[^\n|;&]{0,200}?\s-p\s*)([^\s"'`;&|]+)/g;

const keepQuotes = (v) => (/^(["']).*\1$/s.test(v) ? v[0] + HIDDEN + v[0] : HIDDEN);

/** URL userinfo and secret-named query values, hidden. */
export function redactUrl(text) {
  return String(text ?? "")
    .replace(USERINFO, (_, scheme) => `${scheme}${HIDDEN}@`)
    .replace(QUERY_SECRET, (_, name) => `${name}${HIDDEN}`);
}

/** The values the patterns above would hide in `text` (for hiding them in a quoted part of it). */
function secretValues(text) {
  const out = [];
  const add = (v) => {
    const s = String(v ?? "").replace(/^(["'])(.*)\1$/s, "$2");
    if (s.length >= 4 && s !== HIDDEN) out.push(s);
  };
  for (const m of text.matchAll(USERINFO)) {
    const info = m[0].slice(m[1].length, -1);
    add(info);
    for (const part of info.split(/[:@]/)) add(part);
  }
  for (const m of text.matchAll(QUERY_SECRET)) add(m[2]);
  for (const m of text.matchAll(FLAG_SECRET)) add(m[3]);
  for (const m of text.matchAll(ASSIGN_SECRET)) add(m[2]);
  for (const m of text.matchAll(HEADER_SECRET)) add(m[2]);
  for (const m of text.matchAll(SCHEME_SECRET)) add(m[2]);
  for (const m of text.matchAll(USER_PASS)) {
    add(m[2]);
    add(m[2].replace(/^["']|["']$/g, "").split(":").slice(1).join(":"));
  }
  for (const m of text.matchAll(MYSQL_PASS)) add(m[2]);
  return out;
}

/**
 * Hide each value wherever it appears, and its start or end where the text
 * begins or ends inside it: a part cut from a command can cut a value in two.
 */
const hideAll = (text, values) => {
  let out = text;
  const vs = [...new Set(values)].sort((a, b) => b.length - a.length);
  for (const v of vs) out = out.split(v).join(HIDDEN);
  for (const v of vs) {
    for (let n = v.length - 1; n >= 4; n--) {
      if (out.startsWith(v.slice(-n))) { out = HIDDEN + out.slice(n); break; }
    }
    for (let n = v.length - 1; n >= 4; n--) {
      if (out.endsWith(v.slice(0, n))) { out = out.slice(0, -n) + HIDDEN; break; }
    }
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
  out = redactUrl(out)
    .replace(FLAG_SECRET, (_, flag, sep, v) => `${flag}${sep}${keepQuotes(v)}`)
    .replace(ASSIGN_SECRET, (_, name, v) => `${name}${keepQuotes(v)}`)
    .replace(HEADER_SECRET, (_, name, v) => `${name}${keepQuotes(v)}`)
    .replace(SCHEME_SECRET, (_, scheme, v) => `${scheme}${keepQuotes(v)}`)
    .replace(USER_PASS, (_, flag, v) => `${flag}${keepQuotes(v)}`)
    .replace(MYSQL_PASS, (_, head) => `${head}${HIDDEN}`);
  return hideAll(out, fromContext);
}

/** The value part of a rule hit (`KEY="v"` → v), for hiding it in a part of the text. */
function bareValue(match) {
  const m = /[=:]\s*["'`]?([^"'`\s]{4,})/.exec(match);
  return m ? [m[1]] : match.length >= 4 ? [match] : [];
}
