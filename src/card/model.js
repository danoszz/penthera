/**
 * What the share card says, as plain data. Everything comes from the brief
 * (src/report/brief.js) and the scan results: the verdict is the brief's own,
 * so the card and the brief can never disagree, and no model is involved.
 *
 * The card is made to be posted, so it carries no file paths, no file
 * contents and nothing shaped like a key: a finding's title loses its path and
 * any token-like string is replaced before it reaches the card.
 */
import { basename, resolve } from "node:path";
import { VERDICTS, bucketOf } from "../report/brief.js";
import { siteUnread, readNothing } from "../report/unread.js";
import { uncheckedDeps } from "../../lib/deps/report.js";
import { dropLastWord } from "./kit.js";
import { scrubSecrets, SCRUB_MARGIN } from "../../lib/scrub.js";

export const CARD_SCHEMA = "penthera.card/1";

// A long run of key-like characters with at least one digit: an API key, a token, a hash.
const TOKEN = /[A-Za-z0-9_\-+/=]{20,}/g;
const AUTH_SCHEMES = new Set(["bearer", "basic", "token", "digest", "negotiate"]);
const SECRET_PARTS = ["password", "passwd", "pwd", "token", "secret", "key", "auth", "cookie", "session", "credential", "signature"];
// A scoped package name, with its version already cut at "@": "@scope/pkg" plus trailing punctuation.
const SCOPED = /^["'(]?@[\w.-]+\/[\w.-]+["'),:;]?$/;
/** A word's key name without quotes, brackets or a trailing ":" / "=", and whether it ended in one. */
function keyOf(word) {
  let w = word.toLowerCase().replace(/^["'{(\[]+/, "");
  let sep = false;
  while (w && "\"':=".includes(w[w.length - 1])) {
    if (w.endsWith(":") || w.endsWith("=")) sep = true;
    w = w.slice(0, -1);
  }
  return { name: w, sep };
}

/**
 * One word made safe to post. Dependency titles are `name@version` or
 * `name from → to`, and a lockfile version can be a URL with credentials in it
 * (`pkg@https://user:pw@host/pkg.tgz?token=x`, `file:/Users/me/x.tgz`), so:
 * - a word is cut at its first "@" (a package's version, an email's domain),
 *   keeping a scoped package's leading "@";
 * - then any word left with a ":" inside it (not only at its end) is dropped:
 *   schemes, `user:pw`, `file:../path`, `github:org/repo`, JSON pairs, host:port;
 * - a word starting with "//" (a scheme-relative URL) or holding a percent
 *   escape is dropped;
 * - a query string or fragment is cut off, and a `key=value` keeps only the key.
 * Only plain loops scan the word, so its length cannot slow this down.
 */
function redactWord(word) {
  let w = word;
  const end = /[:,;]$/.test(w) ? w[w.length - 1] : "";
  const at = w.indexOf("@", 1);
  if (at > 0) w = w.slice(0, at) + end;
  // Any path or URL piece: a slash or backslash anywhere, or a home path. Only a scoped
  // package name (@scope/pkg) is kept, since it is public.
  if (w.startsWith("~")) return "";
  if (w.includes("\\")) return "";
  if (w.includes("/") && !SCOPED.test(w)) return "";
  for (let i = 0; i < w.length - 1; i++) {
    const next = w[i + 1];
    if (w[i] === ":" && next !== ":") return "";
    if (w[i] === "%" && i + 2 < w.length && /[0-9a-f]{2}/i.test(w.slice(i + 1, i + 3))) return "";
  }
  for (const mark of ["?", "#"]) {
    const cut = w.indexOf(mark);
    if (cut > 0 && cut < w.length - 1) w = w.slice(0, cut);
  }
  const eq = w.indexOf("=");
  if (eq > 0 && eq < w.length - 1) w = `${w.slice(0, eq)}=[hidden]`;
  return w;
}

/** True for a key name that holds a secret: DB_PASSWORD, x-api-key, X-Auth-Token, secret_key. */
const isSecretKey = (name) => name === "pw" || name === "pass" || SECRET_PARTS.some((p) => name.includes(p));

/**
 * Hide the value after a sensitive key written with a separator (`password:
 * x`, `token= x`, `pw = x`, `DB_PASSWORD: x`) and after an auth scheme
 * (`Bearer x`). The whole value goes, up to the next word ending in "," or ";"
 * (or the closing quote of a quoted value), as one "[hidden]". A key named in
 * prose ("a hardcoded key in source") hides nothing.
 */
function hideValues(words) {
  const out = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const { name, sep } = keyOf(w);
    let j = i + 1;
    while (j < words.length && (words[j] === ":" || words[j] === "=")) j++;
    const keyed = (isSecretKey(name) && (sep || j > i + 1)) || AUTH_SCHEMES.has(name) && i > 0 && isSecretKey(keyOf(words[i - 1]).name);
    out.push(...words.slice(i, j));
    if (!keyed || j >= words.length) { i = j - 1; continue; }
    // The value: up to a closing quote, or to a word ending a clause, or to the end.
    const quote = /^["']/.test(words[j]) ? words[j][0] : null;
    let k = j;
    for (; k < words.length; k++) {
      const v = words[k];
      if (quote ? (k > j || v.length > 1) && v.endsWith(quote) : /[,;]$/.test(v)) break;
    }
    out.push("[hidden]");
    i = Math.min(k, words.length - 1);
  }
  return out;
}

const NOT_DRAWN = /[^\x20-\x7e·×→←•…–]/g;

/** Make a string safe to post: no URLs, credentials, versions, paths, key-like tokens, backticks or control characters. */
export function publicText(s, max = 120) {
  // Cut first: a title is repo-controlled and can be megabytes long, and every
  // regex below must run on a bounded string. Then remove every character that
  // is dropped anyway (backticks, emphasis, anything the pixel font can't draw,
  // zero-width characters) BEFORE the checks: removing them later could join
  // pieces into a URL or a key the checks never saw.
  // Secrets of a known shape are masked first (lib/scrub.js), over a bounded
  // window past the cut, so a key the cut would split is still masked whole.
  const raw = scrubSecrets(String(s ?? "").slice(0, max * 4 + SCRUB_MARGIN), () => "[hidden]");
  let t = raw.slice(0, max * 4);
  // A cut in the middle of a word could leave the visible start of a key: drop that piece.
  if (raw.length > t.length && !/\s/.test(raw[t.length])) {
    let k = t.length;
    while (k > 0 && !/\s/.test(t[k - 1])) k--;
    t = t.slice(0, k);
  }
  t = t
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/[—]/g, "-").replace(/[‘’]/g, "'").replace(/[“”]/g, '"')
    .replace(/[`*_]/g, "")
    .replace(NOT_DRAWN, "");
  t = hideValues(t.split(/\s+/).map(redactWord).filter(Boolean)).join(" ")
    .replace(TOKEN, (m) => (/\d/.test(m) ? "[hidden]" : m))
    // A key split by dots or dashes (ghp.ABC...123.xyz) is still a key.
    .split(" ").map((w) => { const bare = w.replace(/[.-]/g, ""); return bare.length >= 20 && /\d/.test(bare) && /^[A-Za-z0-9+/=]+$/.test(bare) ? "[hidden]" : w; }).join(" ")
    .replace(/\s+/g, " ")
    .trim();
  // A title whose path was taken out can end on "in", "at" or "from": drop that word.
  const tail = t.slice(t.lastIndexOf(" ") + 1).toLowerCase();
  if (t.includes(" ") && ["in", "at", "from"].includes(tail)) t = t.slice(0, t.lastIndexOf(" ")).trimEnd();
  if ([...t].length > max) t = `${dropLastWord([...t].slice(0, max - 1).join(""))}…`;
  return t;
}

/** A bare rule slug ("command-injection") reads as words on a card. */
const titleCase = (t) => (/^[a-z0-9]+(?:-[a-z0-9]+)+$/.test(t) ? `${t[0].toUpperCase()}${t.slice(1).replace(/-/g, " ")}` : t);

/** The name of what was scanned: the folder name or the host, never a full path. */
function targetName(results) {
  const names = [];
  for (const r of results) {
    const t = String(r.target || "");
    if (!t) continue;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
      try { names.push(new URL(t).hostname); } catch { /* not a URL after all */ }
    } else names.push(basename(resolve(t)) || "repo");
  }
  const uniq = [...new Set(names.map((n) => publicText(n, 40)).filter(Boolean))];
  return uniq.length ? uniq.slice(0, 2).join(" + ") : "my app";
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** The worst agent-audit grade and its score out of 100, as the audit's rules set them, or null. */
function agentGrade(audits) {
  const graded = audits.filter((x) => /^[A-F]$/.test(String(x?.grade)) && Number.isInteger(x.score) && x.score >= 0 && x.score <= 100);
  if (!graded.length) return null;
  const worst = graded.reduce((w, x) => (x.score < w.score ? x : w));
  return { letter: worst.grade, score: worst.score };
}

/**
 * The grade that leads the card, or null. Only a deterministic grade that covers the whole
 * card counts: today that is an agent-config audit on its own (repo and URL scans have no
 * score, and none is invented). A suppressed, unread or empty run keeps its own big sign.
 */
function cardGrade(results, tone) {
  if (!["fix", "review", "check", "clean"].includes(tone)) return null;
  const modes = results.flatMap((r) => r.modes || [r.mode]).flatMap((m) => String(m).split("+"));
  if (!modes.length || modes.some((m) => m !== "agents")) return null;
  if (results.some((r) => r.agents?.unparsed)) return null;
  return agentGrade(results.map((r) => r.agents));
}

/** The command that made this kind of card, for its footer. */
function commandOf(results) {
  const modes = new Set(results.flatMap((r) => r.modes || [r.mode]).flatMap((m) => String(m).split("+")));
  if (modes.size === 1 && modes.has("agents")) return "npx penthera agents --card";
  return "npx penthera --card";
}

/** The four things a card reports on, each read, partly read, not read or not run. */
function checkedList(results) {
  const modes = new Set(results.flatMap((r) => r.modes || (r.mode ? [r.mode] : [])).flatMap((m) => String(m).split("+")));
  const of = (mode) => results.filter((r) => (r.modes || [r.mode]).some((m) => String(m).split("+").includes(mode)));

  const code = { id: "code", name: "Code", state: "not-run", detail: "not run" };
  if (modes.has("repo")) {
    const rs = of("repo");
    const files = rs.reduce((n, r) => n + (r.coverage?.files || 0), 0);
    const nothing = rs.every(readNothing);
    const skipped = rs.some((r) => (r.coverage?.families || []).some((f) => !f.ran || Object.values(f.skipped || {}).some((v) => v > 0)));
    code.state = nothing ? "nothing" : skipped ? "partly" : "read";
    code.detail = nothing ? "nothing to read" : `${plural(files, "file")}${skipped ? ", some skipped" : ""}`;
  }

  const deps = { id: "deps", name: "Dependencies", state: "not-run", detail: "not run" };
  if (modes.has("deps")) {
    const d = of("deps").map((r) => r.deps).filter(Boolean);
    const total = d.reduce((n, x) => n + (x.total || 0), 0);
    const scanned = d.reduce((n, x) => n + (x.scanned || 0), 0);
    const gaps = d.map(uncheckedDeps).filter(Boolean);
    deps.state = !total ? "nothing" : gaps.some((g) => g.none) && !scanned ? "nothing" : gaps.length ? "partly" : "read";
    deps.detail = !total ? "no lockfile read" : gaps.length ? `${scanned} of ${total} packages read` : plural(total, "package");
  }

  const agents = { id: "agents", name: "AI-agent configs", state: "not-run", detail: "not run" };
  if (modes.has("agents")) {
    const a = of("agents").map((r) => r.agents).filter(Boolean);
    const files = a.reduce((n, x) => n + (x.inventory?.configFiles?.length || 0), 0);
    const broken = a.reduce((n, x) => n + (x.unparsed || 0), 0);
    agents.state = broken ? "partly" : files ? "read" : "nothing";
    // The agent audit's own grade, from its rules; shown as it prints in the terminal.
    const g = agentGrade(a);
    agents.detail = broken ? `${plural(broken, "file")} unreadable` : g ? `${g.letter} · ${g.score}/100` : files ? plural(files, "file") : "none found";
    agents.files = files;
  }

  const site = { id: "site", name: "Live site", state: "not-run", detail: "not run, add a URL" };
  if (modes.has("url")) {
    const rs = of("url");
    const unread = rs.some(siteUnread) || rs.some((r) => r.httpStatus === 403);
    site.state = unread ? "unread" : "read";
    site.detail = unread ? "not read" : "passive checks";
  }
  return [code, deps, agents, site];
}

/** The big number and the words under it. Never a clean-looking zero for a run that read nothing. */
function heroOf(brief, tone) {
  const c = brief.counts;
  if (tone === "unread") return { value: "?", label: "site not read" };
  if (tone === "none") return { value: "?", label: "nothing to assess" };
  if (tone === "suppressed") return { value: String(c.suppressed), label: "suppressed, not counted" };
  if (c.act) return { value: String(c.act), label: "to fix first" };
  if (c.check) return { value: String(c.check), label: "to check first" };
  if (tone === "review") return { value: "!", label: "to review" };
  return { value: "0", label: "to fix" };
}

function toneOf(verdict) {
  if (verdict === VERDICTS.fix) return "fix";
  if (verdict === VERDICTS.review) return "review";
  if (verdict === VERDICTS.check) return "check";
  if (verdict === VERDICTS.clean) return "clean";
  if (verdict === VERDICTS.none) return "none";
  if (verdict === VERDICTS.unread) return "unread";
  return "suppressed";
}

/** Short lines for what this run did not check. Always at least one. */
function notCheckedLines(brief, checked, tone, results) {
  const out = [];
  if (tone === "unread") out.push("We couldn't see your site, so this says nothing about it");
  if (tone === "none") out.push("The check read nothing here, so this is not a clean result");
  if (brief.counts.suppressed) out.push(`${brief.counts.suppressed} suppressed findings, not counted here`);
  // What the engines themselves say they could not read (MCP tool descriptions, unparsed files).
  for (const r of results) for (const l of r.agents?.notChecked || []) out.push(publicText(l.replace(/\.$/, ""), 140));
  for (const k of checked) {
    if (k.state === "partly") out.push(`${k.name}: ${k.detail}`);
    else if (k.state === "unread" && tone !== "unread") out.push(`${k.name}: not read`);
  }
  // Checks that were not part of the run are already rows on the receipt ("NOT RUN").
  // As in the brief: only a repo or live-site run can be mistaken for a check of login and payments.
  const modes = results.flatMap((r) => r.modes || [r.mode]).flatMap((m) => String(m).split("+"));
  if (modes.includes("repo") || modes.includes("url")) out.push("Login, access rules and payments: not proven");
  if (!out.length) out.push("No finding is not proof of safety: Penthera reports what its rules match");
  return [...new Set(out)];
}

const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** The single finding to fix first: the most severe one that needs a change, first as the engines reported it. */
function topFinding(results, brief) {
  let best = null;
  for (const r of results) for (const f of r.findings || []) {
    const b = bucketOf(f, { skillTarget: !!r.agents?.skillTarget }).bucket;
    if (b !== "act" && b !== "check") continue;
    const rank = (b === "act" ? 0 : 10) + (SEV[f.severity] ?? 9);
    if (!best || rank < best.rank) best = { f, rank };
  }
  if (!best) return null;
  const f = best.f;
  const first = (s) => (/^(.+?[.!?])(?:\s|$)/.exec(String(s).replace(/\s+/g, " ").trim()) || [null, s])[1];
  return { title: f.title, fix: f.remediation ? first(f.remediation) : null, severity: f.severity, tone: brief.verdict };
}

/**
 * @param {object} brief  buildBrief() output
 * @param {object[]} results  the scan results the brief was built from
 * @param {{ version: string, date?: string }} opts
 */
export function buildCardModel(brief, results, { version, date } = {}) {
  const list = (Array.isArray(results) ? results : [results]).filter(Boolean);
  const tone = toneOf(brief.verdict);
  const checked = checkedList(list);
  const top = topFinding(list, brief);
  const grade = cardGrade(list, tone);
  // When the grade leads the card, its line shows what was read instead of repeating the grade.
  if (grade) for (const c of checked) if (c.id === "agents") c.detail = plural(c.files, "file");
  for (const c of checked) delete c.files;
  const day = date || String(list.map((r) => r.timestamp).filter(Boolean).sort().pop() || new Date().toISOString()).slice(0, 10);
  return {
    schema: CARD_SCHEMA,
    tone,
    // Only things to check: "Nothing to fix now · 4 to check" (Daan, 9 Nov).
    verdict: publicText(tone === "check" ? `${brief.verdict} · ${brief.counts.check} to check` : brief.verdict, 40),
    hero: heroOf(brief, tone),
    grade,
    toFix: brief.counts.act ? { value: brief.counts.act, label: "To fix first" } : brief.counts.check ? { value: brief.counts.check, label: "To check first" } : { value: 0, label: "To fix" },
    command: commandOf(list),
    target: targetName(list),
    date: day,
    version: publicText(version, 20),
    checked,
    notChecked: notCheckedLines(brief, checked, tone, list),
    top: top && (tone === "fix" || tone === "review" || tone === "check")
      ? { title: titleCase(publicText(top.title, 90)) || "Finding", fix: top.fix ? publicText(top.fix, 180) : null, severity: top.severity }
      : null,
  };
}
