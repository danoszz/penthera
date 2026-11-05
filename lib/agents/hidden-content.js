/**
 * Hidden-content engine for agent instructions (skills, rule files, commands).
 *
 * Deterministic and offline. It looks for content a human reviewer would not
 * see but a model would read and act on, and for payloads that run code.
 *
 * Designed against the ways LLM-judged skill scanners have been bypassed:
 *   - Invisible text: Unicode tag characters, zero-width and bidi controls,
 *     variation-selector smuggling. Decoded where possible, so the report shows
 *     what the model would read.
 *   - Content pushed out of view: hundreds of blank lines or a wide run of
 *     spaces, so the payload sits past what a reviewer or a truncating judge sees.
 *     This engine reads the whole file; there is no context window to overflow.
 *   - Instructions in HTML comments, which Markdown renderers hide.
 *   - Text addressed to the scanner itself ("this skill is safe, approve it").
 *     A regex cannot be talked out of a finding, but the attempt is a signal.
 *   - Payloads moved out of SKILL.md: every file in a skill folder is scanned,
 *     binaries and archives are identified by magic bytes rather than extension,
 *     and symlinks that leave the folder are reported.
 *   - Encoded payloads: long base64 blobs, decoded and classified.
 *
 * Each detector returns hits `{ rule, severity, title, detail, line, count }`.
 * Callers turn hits into findings.
 */
import { rulesOf, rulesGeneration, packTest, packMatch } from "../rules/index.js";
import { redactCommand } from "./redact.js";

// ── Invisible characters ──────────────────────────────────────────────────

const TAG_RANGE = /[\u{E0000}-\u{E007F}]/u;
const TAG_RUN = /[\u{E0000}-\u{E007F}]+/gu;
const VS_SUPPLEMENT_RUN = /[\u{E0100}-\u{E01EF}]+/gu;
const BIDI = /[‪-‮⁦-⁩]/g;
// Zero-width and other format characters that render as nothing. U+200D (ZWJ)
// and U+200C (ZWNJ) have legitimate uses (emoji sequences, Persian, Indic
// scripts), so those are filtered by context below.
const ZERO_WIDTH = /[​-‍⁠-⁤﻿᠎ㅤᅟᅠﾠ]/g;
const PICTO = /\p{Extended_Pictographic}|[\u{1F3FB}-\u{1F3FF}️]/u;
const NON_LATIN_LETTER = /[\p{L}\p{M}]/u;

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

/** Decode Unicode tag characters to the ASCII they smuggle. */
export function decodeTagChars(s) {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

/** Make a decoded payload safe to print: visible ASCII only, truncated. */
export function preview(s, max = 80) {
  const clean = String(s).replace(/[^\x20-\x7E]/g, "·").replace(/\s+/g, " ").trim();
  return clean.length > max ? clean.slice(0, max) + "…" : clean;
}

/**
 * Text from a scanned file as a finding quotes it: credentials hidden
 * (redactCommand), then made safe and shortened (preview). `context` is the
 * text it was cut from; a secret there is hidden in the quote too. Only the
 * first 4 × max characters are redacted: the rest is cut anyway.
 */
export function quote(text, max = 80, context) {
  const s = String(text ?? "");
  const part = s.length > max * 4 ? s.slice(0, max * 4) : s;
  return preview(redactCommand(part, context ?? s), max);
}

/** The line around `text[index, index + length)`, at most 8 KiB either side: the context of a quoted match. */
function lineAround(text, index, length) {
  const from = Math.max(text.lastIndexOf("\n", index) + 1, index - 8192);
  let to = text.indexOf("\n", index + length);
  if (to < 0) to = text.length;
  return text.slice(from, Math.min(to, index + length + 8192));
}

function detectInvisible(text) {
  const hits = [];

  const tagRuns = [...text.matchAll(TAG_RUN)];
  if (tagRuns.length) {
    const decoded = tagRuns.map((m) => decodeTagChars(m[0])).join(" ").trim();
    const count = tagRuns.reduce((n, m) => n + [...m[0]].length, 0);
    hits.push({
      rule: "unicode-tags",
      severity: "critical",
      title: "Hidden text in Unicode tag characters",
      detail: `${count} invisible tag character(s) (U+E0000–E007F). A model reads them as text; a reviewer sees nothing.` +
        (decoded ? ` Decoded: "${quote(decoded)}"` : ""),
      line: lineOf(text, tagRuns[0].index),
      count,
    });
  }

  const vsRuns = [...text.matchAll(VS_SUPPLEMENT_RUN)];
  if (vsRuns.length) {
    const count = vsRuns.reduce((n, m) => n + [...m[0]].length, 0);
    hits.push({
      rule: "variation-selectors",
      severity: "high",
      title: "Data hidden in variation selectors",
      detail: `${count} supplementary variation selector(s) (U+E0100–E01EF). These are invisible and can encode arbitrary bytes ("emoji smuggling").`,
      line: lineOf(text, vsRuns[0].index),
      count,
    });
  }

  const bidi = [...text.matchAll(BIDI)];
  if (bidi.length) {
    hits.push({
      rule: "bidi-controls",
      severity: "high",
      title: "Bidirectional control characters",
      detail: `${bidi.length} bidi override/isolate character(s) (U+202A–202E, U+2066–2069). They reorder how text displays, so what a reviewer reads differs from what the model reads (Trojan Source).`,
      line: lineOf(text, bidi[0].index),
      count: bidi.length,
    });
  }

  const zw = [];
  for (const m of text.matchAll(ZERO_WIDTH)) {
    const ch = m[0];
    const i = m.index;
    if (ch === "﻿" && i === 0) continue; // byte-order mark
    // A zero-width space at the start of a line before ``` or ~~~ is the usual
    // trick for showing a code fence inside a fenced block.
    if (ch === "​" && (i === 0 || text[i - 1] === "\n") && /^(?:```|~~~)/.test(text.slice(i + 1, i + 4))) continue;
    const prev = text.slice(Math.max(0, i - 2), i);
    const next = text.slice(i + 1, i + 3);
    if (ch === "‍" && PICTO.test(prev) && PICTO.test(next)) continue; // emoji ZWJ sequence
    if (ch === "‌" || ch === "‍") {
      const p = [...prev].pop() || "";
      const n = [...next][0] || "";
      // ZWNJ/ZWJ between letters of a non-Latin script is ordinary orthography.
      if (NON_LATIN_LETTER.test(p) && NON_LATIN_LETTER.test(n) && /[^\x00-ɏ]/.test(p + n)) continue;
    }
    zw.push(i);
  }
  if (zw.length) {
    hits.push({
      rule: "zero-width",
      severity: zw.length >= 3 ? "high" : "medium",
      title: "Zero-width or invisible characters",
      detail: `${zw.length} zero-width/invisible character(s). They can split keywords to dodge filters or carry a hidden binary encoding.`,
      line: lineOf(text, zw[0]),
      count: zw.length,
    });
  }

  return hits;
}

// ── Whitespace inflation ──────────────────────────────────────────────────

export const DEFAULTS = {
  blankLines: 40,       // consecutive blank lines before more content
  horizontalRun: 200,   // consecutive spaces/tabs on one line before more content
  base64MinLength: 200, // characters in one base64 run
};

// Linear scans, not regexes: a nested whitespace quantifier backtracks
// quadratically on exactly the input an attacker would write here.
function detectWhitespaceInflation(text, opts) {
  const hits = [];
  const lines = text.split("\n");
  let run = 0;
  let longestV = 0;
  let firstV = null;
  let countV = 0;
  let longestH = 0;
  let firstH = null;
  let countH = 0;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (/^[ \t\r]*$/.test(ln)) { run++; continue; }
    if (run >= opts.blankLines) {
      countV++;
      longestV = Math.max(longestV, run);
      if (firstV === null) firstV = i + 1;
    }
    run = 0;
    let ws = 0;
    for (let j = 0; j < ln.length; j++) {
      const ch = ln.charCodeAt(j);
      if (ch === 32 || ch === 9 || ch === 0xa0) { ws++; continue; }
      if (ws >= opts.horizontalRun && ch !== 13) {
        countH++;
        longestH = Math.max(longestH, ws);
        if (firstH === null) firstH = i + 1;
      }
      ws = 0;
    }
  }
  if (countV) {
    hits.push({
      rule: "whitespace-vertical",
      severity: "high",
      title: "Content hidden below a wall of blank lines",
      detail: `${longestV} consecutive blank lines, then more content. This pushes text past where a reviewer stops scrolling, and past what a truncating scanner reads.`,
      line: firstV,
      count: countV,
    });
  }
  if (countH) {
    hits.push({
      rule: "whitespace-horizontal",
      severity: "high",
      title: "Content hidden off-screen to the right",
      detail: `A run of ${longestH} spaces, then more text on the same line. Editors and diff views without wrapping never show it.`,
      line: firstH,
      count: countH,
    });
  }
  return hits;
}

// ── Instructions in hidden places ─────────────────────────────────────────

export const INSTRUCTION_PATTERNS = [
  /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|other)\b[^.\n]{0,20}\b(?:instructions?|rules?|prompts?|guidelines?|directions?)\b/i,
  /\b(?:ignore|disregard|forget)\b[^.\n]{0,30}\bthe user\b/i,
  /\b(?:you|assistant|claude|agent|model|ai|llm)\b[^.\n]{0,30}\b(?:must|should|shall|will|are to|need to|have to)\b/i,
  /\bdo(?:n'?t| not) (?:tell|inform|mention|reveal|show|alert|ask|notify)\b/i,
  /\bwithout (?:asking|telling|informing|confirm\w*|permission|the user)/i,
  /\b(?:system prompt|developer message|new instructions?)\b/i,
  /\b(?:run|execute|exec|invoke)\b[^.\n]{0,40}\b(?:command|script|bash|shell|curl|wget|powershell)\b/i,
  /\b(?:send|upload|post|exfiltrat\w*|transmit|forward|copy)\b[^\n]{0,60}(?:https?:\/\/|\btokens?\b|\bsecrets?\b|\bapi keys?\b|\bcredentials?\b|\.env\b|\benv(?:ironment)?\s+(?:files?|var(?:iable)?s?)\b|\bssh\b|\bpasswords?\b)/i,
  // Credential paths: lib/rules/core/agent-instructions.json.
  ...rulesOf("agent-instruction", { pack: "core" }).map((r) => r.pattern),
];
const packInstructions = () => rulesOf("agent-instruction", { exceptPack: "core" });

// Text addressed to an automated reviewer. Legitimate skills have no reason to
// talk to a security scanner.
const SCANNER_DIRECTED = /\b(?:security |safety |skill |code )?(?:scanners?|reviewers?|auditors?|judges?|classifiers?|analy[sz]ers?|moderators?)\b[^.\n]{0,60}\b(?:is|as|are|mark|classify|report|treat|consider|rate|label)\b[^.\n]{0,30}\b(?:safe|benign|harmless|clean|trusted|approved?|pass(?:ed)?|low[- ]risk|false positive)\b/i;

export function looksLikeInstruction(s) {
  return INSTRUCTION_PATTERNS.some((re) => re.test(s)) || packInstructions().some((r) => packTest(r, s));
}

function detectHiddenInstructions(text) {
  const hits = [];
  const comments = [...text.matchAll(/<!--([\s\S]*?)-->/g)];
  const bad = comments.filter((m) => looksLikeInstruction(m[1]));
  if (bad.length) {
    hits.push({
      rule: "html-comment-instructions",
      severity: "high",
      title: "Instructions hidden in an HTML comment",
      detail: `${bad.length} HTML comment(s) contain instructions. Markdown renderers hide comments, the model still reads them. First: "${quote(bad[0][1])}"`,
      line: lineOf(text, bad[0].index),
      count: bad.length,
    });
  }
  const scanner = text.match(SCANNER_DIRECTED);
  if (scanner) {
    hits.push({
      rule: "scanner-directed",
      severity: "high",
      title: "Text addressed to a security scanner",
      detail: `Tries to talk an automated reviewer into a verdict: "${quote(scanner[0], 80, lineAround(text, scanner.index, scanner[0].length))}". This is how LLM-judged scanners get bypassed.`,
      line: lineOf(text, scanner.index),
      count: 1,
    });
  }
  return hits;
}

// ── Code execution patterns ───────────────────────────────────────────────

const SHELL = String.raw`(?:sudo\s+)?(?:env\s+\S*\s*)?(?:ba|z|da|k|fi|c|tc)?sh\b`;
const INTERPRETER = String.raw`(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php|deno|bun)\b`;
const PS_DOWNLOAD = String.raw`\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b`;

// The patterns of the form `<source> ... | <sink>` are matched by the helpers
// below rather than by `re` itself (kept as the definition). As one regex
// they restart the scan at every <source> on a line, which is quadratic on a
// line full of them; the helpers return the same match in linear time.

function matchAt(text, start, end) {
  const m = [text.slice(start, end)];
  m.index = start;
  return m;
}

/** `source[^\n|]*\|\s*sink`: the source sits in the pipeline stage just before the pipe. */
function pipedFrom(source, sink) {
  const pipe = new RegExp(String.raw`\|\s*${sink}`, "gi");
  return (text) => {
    // The last newline before the pipe, tracked forward: a backward search
    // per pipe re-read the whole prefix of a line with no newline, which was
    // quadratic on "|sh|sh|sh..." (about 45 minutes at the 5 MB cap). The
    // previous "|" is at most one match back, so lastIndexOf stays linear.
    let lastNl = -1;
    let nextNl = text.indexOf("\n");
    for (const m of text.matchAll(pipe)) {
      while (nextNl !== -1 && nextNl < m.index) { lastNl = nextNl; nextNl = text.indexOf("\n", nextNl + 1); }
      const start = m.index === 0 ? 0 : Math.max(text.lastIndexOf("|", m.index - 1), lastNl) + 1;
      const s = source.exec(text.slice(start, m.index));
      if (s) return matchAt(text, start + s.index, m.index + m[0].length);
    }
    return null;
  };
}

/**
 * `first[^\n]*second`: leftmost `first`, extended to the last `second` that
 * starts on its line. A `second` that begins with `\|` may run past the line
 * end (`\|\s*sh` spans a newline), so it is tried at each pipe on the line.
 */
function thenOnLine(first, second) {
  const firstG = new RegExp(first, "gi");
  const secondG = new RegExp(second, "gi");
  const secondY = new RegExp(second, "iy");
  const atPipe = second.startsWith("\\|");
  const lastOnLine = (text, from, eol) => {
    let last = null;
    if (atPipe) {
      for (let p = text.indexOf("|", from); p >= 0 && p < eol; p = text.indexOf("|", p + 1)) {
        secondY.lastIndex = p;
        const b = secondY.exec(text);
        if (b) last = b;
      }
    } else {
      for (const b of text.slice(from, eol).matchAll(secondG)) last = { 0: b[0], index: from + b.index };
    }
    return last;
  };
  return (text) => {
    let skipTo = 0;
    for (const a of text.matchAll(firstG)) {
      if (a.index < skipTo) continue;
      const aEnd = a.index + a[0].length;
      let eol = text.indexOf("\n", aEnd);
      if (eol < 0) eol = text.length;
      // Only the first `first` on a line needs checking: any `second` after a
      // later one is also after this one.
      skipTo = eol;
      const last = lastOnLine(text, aEnd, eol);
      if (last) return matchAt(text, a.index, last.index + last[0].length);
    }
    return null;
  };
}

function earliest(...finders) {
  return (text) => {
    let best = null;
    for (const f of finders) {
      const m = f(text);
      if (m && (!best || m.index < best.index)) best = m;
    }
    return best;
  };
}

const JS_EVAL_REMOTE = /\b(?:eval|Function)\s*\(\s*(?:await\s+)?(?:atob|Buffer\.from|fetch|require\(\s*["']child_process|\(await fetch)/;
const evalAsCallback = thenOnLine(String.raw`\bfetch\s*\(`, String.raw`\.then\(\s*(?:(?:globalThis|window|self)\.)?eval\s*\)`);

export const EXEC_PATTERNS = [
  {
    rule: "curl-pipe-shell", label: "download piped to a shell",
    re: new RegExp(String.raw`\b(?:curl|wget|fetch|iwr)\b[^\n|]*\|\s*${SHELL}`, "i"),
    match: pipedFrom(/\b(?:curl|wget|fetch|iwr)\b/i, SHELL),
  },
  {
    rule: "curl-pipe-interpreter", label: "download piped to an interpreter",
    re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php|deno|bun)\b/i,
    match: pipedFrom(/\b(?:curl|wget)\b/i, INTERPRETER),
  },
  // Process and command substitution: lib/rules/core/agent-exec.json.
  ...rulesOf("agent-exec", { pack: "core" }).map((r) => ({ rule: r.id, label: r.label, re: r.pattern })),
  {
    rule: "base64-pipe-shell", label: "decoded base64 piped to a shell",
    re: new RegExp(String.raw`base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*${SHELL}`, "i"),
    match: thenOnLine(String.raw`base64\s+(?:-d|--decode|-D)\b`, String.raw`\|\s*${SHELL}`),
  },
  { rule: "shell-eval", label: "eval of command output", re: /\beval\s+["']?\$\(/ },
  {
    rule: "js-eval-remote", label: "eval of fetched or decoded content",
    re: JS_EVAL_REMOTE,
    // Also eval passed as the callback of a fetch: fetch(url).then((r) => r.text()).then(eval).
    match: (text) => text.match(JS_EVAL_REMOTE) || evalAsCallback(text),
  },
  { rule: "py-exec-remote", label: "exec of fetched or decoded content", re: /\bexec\s*\(\s*(?:base64\.b64decode|__import__|compile|urllib|requests\.get|zlib\.decompress|marshal\.loads|bytes\.fromhex)/ },
  {
    rule: "powershell-iex", label: "PowerShell Invoke-Expression of a download",
    re: /\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b/i,
    match: earliest(
      thenOnLine(String.raw`\b(?:iex|Invoke-Expression)\b`, PS_DOWNLOAD),
      thenOnLine(PS_DOWNLOAD, String.raw`\|\s*(?:iex|Invoke-Expression)\b`),
    ),
  },
];

/** Find remote-code-execution patterns in a string (a file, a hook command). */
export function findExecPatterns(text) {
  const out = [];
  for (const p of execPatterns()) {
    const m = p.pack ? packMatch(p.pack, text) : p.match ? p.match(text) : text.match(p.re);
    if (m) out.push({ rule: p.rule, label: p.label, match: m[0], index: m.index });
  }
  return out;
}

// Built-ins, then rules from other packs (bundled or --rules).
let _exec = null;
let _execGen = -1;
function execPatterns() {
  if (_execGen !== rulesGeneration()) {
    _exec = [...EXEC_PATTERNS, ...rulesOf("agent-exec", { exceptPack: "core" }).map((r) => ({ rule: r.id, label: r.label, re: r.pattern, pack: r }))];
    _execGen = rulesGeneration();
  }
  return _exec;
}

function detectExec(text) {
  return findExecPatterns(text).map((m) => ({
    rule: m.rule,
    severity: "high",
    title: `Remote code execution pattern: ${m.label}`,
    detail: `\`${quote(m.match, 120, lineAround(text, m.index, m.match.length))}\`. An agent following this runs code nobody reviewed, fetched at run time.`,
    line: lineOf(text, m.index),
    count: 1,
  }));
}

// ── Base64 blobs ──────────────────────────────────────────────────────────

const MAGIC = [
  { name: "ELF executable", test: (b) => b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 },
  { name: "Windows executable", test: (b) => b[0] === 0x4d && b[1] === 0x5a },
  { name: "Mach-O executable", test: (b) => {
    const m = b.readUInt32BE?.(0);
    return [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(m);
  } },
  { name: "zip archive", test: (b) => b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07) },
  { name: "gzip archive", test: (b) => b[0] === 0x1f && b[1] === 0x8b },
  { name: "bzip2 archive", test: (b) => b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68 },
  { name: "xz archive", test: (b) => b[0] === 0xfd && b[1] === 0x37 && b[2] === 0x7a && b[3] === 0x58 },
  { name: "7z archive", test: (b) => b[0] === 0x37 && b[1] === 0x7a && b[2] === 0xbc && b[3] === 0xaf },
  { name: "rar archive", test: (b) => b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21 },
  { name: "WebAssembly module", test: (b) => b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d },
  // CPython bytecode: a 2-byte version magic followed by \r\n.
  { name: "Python bytecode (.pyc)", test: (b) => b.length >= 16 && b[2] === 0x0d && b[3] === 0x0a && b[1] < 0x10 },
  { name: "tar archive", test: (b) => b.length > 262 && b.toString("latin1", 257, 262) === "ustar" },
];

/** Name the executable/archive format of a buffer, or null. */
export function sniffBinary(buf) {
  if (!buf || buf.length < 4) return null;
  const hit = MAGIC.find((m) => m.test(buf));
  return hit ? hit.name : null;
}

function isPrintable(buf) {
  if (!buf.length) return false;
  let ok = 0;
  for (const b of buf) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) ok++;
  return ok / buf.length > 0.95;
}

function detectBase64(text, opts) {
  const re = new RegExp(`[A-Za-z0-9+/_-]{${opts.base64MinLength},}={0,2}`, "g");
  const blobs = [];
  for (const m of text.matchAll(re)) {
    const s = m[0];
    // Real base64 mixes cases and digits; hex digests, identifiers and long
    // words do not.
    if (!/[A-Z]/.test(s) || !/[a-z]/.test(s) || !/[0-9]/.test(s)) continue;
    if (/^[0-9a-f]+$/i.test(s)) continue;
    const before = text.slice(Math.max(0, m.index - 40), m.index);
    const image = /data:image\/[a-z+.-]+;base64,$/i.test(before);
    const buf = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    const binary = sniffBinary(buf);
    let decodedText = null;
    if (!binary && isPrintable(buf)) decodedText = buf.toString("utf-8");
    const execInside = decodedText ? findExecPatterns(decodedText) : [];
    const instructionInside = decodedText ? looksLikeInstruction(decodedText) : false;
    blobs.push({ index: m.index, length: s.length, image, binary, decodedText, execInside, instructionInside });
  }
  if (!blobs.length) return [];

  const worst = blobs.find((b) => b.binary) || blobs.find((b) => b.execInside.length) ||
    blobs.find((b) => b.instructionInside) || blobs.find((b) => !b.image) || blobs[0];
  let severity = "medium";
  let what = "an opaque encoded payload a reviewer cannot read";
  if (worst.binary) { severity = "high"; what = `a ${worst.binary}`; }
  else if (worst.execInside.length) { severity = "high"; what = `a ${worst.execInside[0].label} (\`${quote(worst.execInside[0].match, 80, worst.decodedText)}\`)`; }
  else if (worst.instructionInside) { severity = "high"; what = `hidden instructions ("${quote(worst.decodedText)}")`; }
  else if (worst.image) { severity = "low"; what = "an inline image"; }
  else if (worst.decodedText) what = `encoded text ("${quote(worst.decodedText, 60)}")`;

  return [{
    rule: "base64-blob",
    severity,
    title: "Large base64 blob",
    detail: `${blobs.length} base64 run(s) of ${opts.base64MinLength}+ characters; the largest is ${Math.max(...blobs.map((b) => b.length))}. It decodes to ${what}.`,
    line: lineOf(text, worst.index),
    count: blobs.length,
  }];
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Scan one text file for hidden content.
 * @param {string} text
 * @param {object} [opts] { blankLines, horizontalRun, base64MinLength, markdown }
 */
export function scanHiddenContent(text, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  return [
    ...detectInvisible(text),
    ...detectWhitespaceInflation(text, o),
    ...detectHiddenInstructions(text),
    ...detectExec(text),
    ...detectBase64(text, o),
  ];
}

export function hasTagChars(text) {
  return TAG_RANGE.test(text);
}

// Extensions that are binary or archives no matter what the bytes say.
export const BINARY_EXTENSIONS = /\.(?:pyc|pyo|pyd|so|dylib|dll|exe|bin|jar|class|whl|egg|zip|tar|tgz|gz|bz2|xz|7z|rar|wasm|node|deb|rpm|dmg|pkg|msi|apk)$/i;
// Media that ships in skills legitimately.
export const MEDIA_EXTENSIONS = /\.(?:png|jpe?g|gif|webp|ico|bmp|avif|woff2?|ttf|otf|eot|mp3|mp4|wav|ogg|webm|mov|pdf)$/i;
