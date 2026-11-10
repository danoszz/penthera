/**
 * The one secret scrubber every output goes through: the terminal report,
 * JSON, Markdown, SARIF, the share card, the agent brief, MCP results, error
 * messages and logs. The engines already mask what they report; this is the
 * net under them, for a key that reaches an output some other way (a title
 * built from a file name, a URL, an error that quotes a config, another
 * tool's output).
 *
 * It masks what has a known, fixed shape, so it never guesses at prose:
 *
 * - every fixed-shape rule of the secret scan (provider prefixes such as
 *   `sk_live_`, `ghp_`, `AKIA`, `sk-ant-`, `AIza`, private key blocks), read
 *   from the active rules, so a rule added to the scan is scrubbed here too;
 * - shapes outputs can carry that the scan reports through other rules: JWTs
 *   (Supabase keys are JWTs), `sb_secret_`, Stripe test and webhook secrets,
 *   Slack, npm, GitLab, SendGrid and Vercel Blob tokens;
 * - the password in URL userinfo (`postgres://app:pw@db` → `app:***@db`) and
 *   the credential after `Bearer`.
 *
 * A hit is masked as the reports mask it (maskMatch: the first and last 4 of
 * a long value, *** for a short one), so a scrubbed report reads like the
 * scanner's own. Masked text never matches again: scrubbing twice changes
 * nothing, and a report that went through it compares with one that did not.
 *
 * Callers scrub before they cut text to a length: a key cut in half no longer
 * matches its shape, and its first half would print in clear.
 */
import { activeSecretPatterns, maskMatch } from "./whitebox/secrets.js";
import { rulesGeneration } from "./rules/index.js";

// Shapes beyond the scan's own fixed-shape rules. Bounded quantifiers only:
// these run over every string of every report. The JWT starts only where a
// run of token characters starts, so a long run of `eyJeyJ…` is tried once.
const EXTRA_SHAPES = [
  { name: "JWT", pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}/g },
  { name: "Supabase secret key", pattern: /sb_secret_[A-Za-z0-9_-]{20,200}/g },
  { name: "Stripe test or webhook secret", pattern: /(?:[sr]k_test_|whsec_)[A-Za-z0-9]{20,200}/g },
  { name: "Slack token", pattern: /xox[abposr]-[A-Za-z0-9-]{10,200}/g },
  { name: "npm token", pattern: /npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g },
  { name: "GitLab token", pattern: /glpat-[A-Za-z0-9_-]{20,200}/g },
  { name: "SendGrid key", pattern: /SG\.[A-Za-z0-9_-]{16,100}\.[A-Za-z0-9_-]{16,100}/g },
  { name: "Vercel Blob token", pattern: /vercel_blob_rw_[A-Za-z0-9_]{16,200}/g },
];

const HIDDEN = "***";

/**
 * How far past a cut a caller scrubs: a key that starts before the cut and
 * ends after it is still matched whole (a PEM key is about 3,300 characters).
 * Scrubbing a bounded window keeps a megabyte title cheap.
 */
export const SCRUB_MARGIN = 8192;
// scheme://user:password@ : the password, up to the last @ of the authority.
const USERINFO = /\b([a-z][a-z0-9+.-]{1,30}:\/\/)([^\s/?#@:"'`<>]{0,256}):([^\s/?#"'`<>]{1,256})@/gi;
const BEARER = /\b(Bearer\s+)([A-Za-z0-9._~+/-]{16,4096}=*)/g;
// A private key block, BEGIN to END, hidden whole: the scan's rule matches its
// header and first line, and the lines after would print. A block cut before
// its END line is hidden up to the end of its key characters.
const PEM_HEAD = String.raw`-----BEGIN ((?:[A-Z]{1,12} ){0,3}PRIVATE KEY(?: BLOCK)?)-----`;
const PEM_FULL = new RegExp(String.raw`${PEM_HEAD}[\s\S]{0,16384}?-----END \1-----`, "g");
const PEM_OPEN = new RegExp(String.raw`${PEM_HEAD}(?:[A-Za-z0-9+/=:,\s-]|\\[rn]){0,16384}`, "g");

// Every shape above needs a run of 16 token characters, an @ or a PEM header.
// Most strings in a report have none and skip the full check.
const MAYBE = /[A-Za-z0-9_-]{16}|@|-----BEGIN/;

let shapes = null;
let generation = -1;

/**
 * The scan's fixed-shape rules as global regexes, rebuilt when the rules
 * change (a --rules pack). A rule with a placeholder filter guesses from a key
 * name (`password = …`) and stays out: in prose it would mask words.
 */
function scanShapes() {
  if (generation !== rulesGeneration()) {
    shapes = activeSecretPatterns()
      .filter((p) => !p.skipIf || p.name === "AWS access key")
      .map((p) => ({ name: p.name, pattern: new RegExp(p.pattern.source, p.pattern.flags.replace(/[gy]/g, "") + "g") }))
      .concat(EXTRA_SHAPES);
    generation = rulesGeneration();
  }
  return shapes;
}

// A match glued to letters or digits on its left (`disk-…`) is part of a
// longer word, not a token.
const glued = (s, i) => i > 0 && /[A-Za-z0-9]/.test(s[i - 1]);

/**
 * `text` with every secret of a known shape masked. Anything not a string
 * comes back as it is. `mask` turns a hit into what is shown (the share card
 * shows `[hidden]`, keeping no characters of the key at all).
 */
export function scrubSecrets(text, mask = maskMatch) {
  if (typeof text !== "string" || !MAYBE.test(text)) return text;
  let out = text;
  if (out.includes("-----BEGIN ")) {
    out = out
      .replace(PEM_FULL, (_, kind) => `-----BEGIN ${kind}-----${HIDDEN}-----END ${kind}-----`)
      .replace(PEM_OPEN, (m, kind) => (m.length === `-----BEGIN ${kind}-----`.length ? m : `-----BEGIN ${kind}-----${HIDDEN}`));
  }
  for (const { pattern } of scanShapes()) {
    pattern.lastIndex = 0;
    if (!pattern.test(out)) continue;
    pattern.lastIndex = 0;
    out = out.replace(pattern, (m, ...rest) => {
      // replace() passes the groups, then the offset, then the whole string.
      const i = rest.findIndex((x) => typeof x === "number");
      return glued(rest[i + 1], rest[i]) ? m : mask(m);
    });
  }
  return out
    .replace(USERINFO, (all, scheme, user, pass) => (pass === HIDDEN ? all : `${scheme}${user}:${HIDDEN}@`))
    .replace(BEARER, (all, lead, v) => (v === HIDDEN ? all : `${lead}${HIDDEN}`));
}

/**
 * A copy of `value` with every string in it scrubbed (object keys stay).
 * Objects and arrays that hold nothing to scrub come back as they are, so a
 * clean report costs one walk and no copy. Not plain objects (a Buffer, a
 * Date, a Map) are left alone.
 */
export function scrubDeep(value, seen = new WeakMap()) {
  if (typeof value === "string") return scrubSecrets(value);
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value);
  if (Array.isArray(value)) {
    seen.set(value, value);
    let copy = null;
    for (let i = 0; i < value.length; i++) {
      const v = scrubDeep(value[i], seen);
      if (v !== value[i]) (copy ??= value.slice())[i] = v;
    }
    if (copy) seen.set(value, copy);
    return copy || value;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return value;
  seen.set(value, value);
  let copy = null;
  for (const k of Object.keys(value)) {
    const v = scrubDeep(value[k], seen);
    if (v !== value[k]) (copy ??= { ...value })[k] = v;
  }
  if (copy) seen.set(value, copy);
  return copy || value;
}
