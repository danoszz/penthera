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

// A shell as a pipe's target. Two readers, and a hit from either counts
// (HEURISTICS R12, bypass checklist row 16): the stage parser below, and
// main's old regex beside it (legacyShellAfterPipe), so a form the old regex
// caught can never be lost to the rewrite.
//
// The stage parser reads the pipeline stage after the "|" as shell words:
//   - quotes and escapes are read as the shell reads them, so `FOO="a b" sh`
//     is one assignment and one command word, and `ba""sh` is bash;
//   - redirections and their targets (`>`, `>>`, `2>`, `&>`, `<`, `>|`,
//     `2>&1`, attached or spaced) are taken out of the words, so
//     `bash>/var/log/x` has the command word `bash`, not `x`;
//   - the stage ends at the next unquoted |, ;, &, ), backtick or line end
//     (a "\" at the end of a line continues it, as does a line that ends in
//     "|"), and a "(" or "{" that opens a group is passed over;
//   - wrappers that run the next word as a command (sudo, doas, env, nohup,
//     exec, command, builtin, time, nice, setsid, stdbuf, timeout), by name
//     or by any path, are skipped with their options, the values that take
//     one (`env -u NAME`, `sudo -u USER`, `nice -n 5`, `timeout 10`, …), and
//     every word that starts with "-" or has "=" in it;
//   - `env -S STRING` and `--split-string=STRING` run STRING, so its words
//     are read next, from a stack of positions in the strings already read:
//     no word is copied or spliced in, so repeated -S stays linear;
//   - the first word left decides: its name after the last "/" must be a
//     shell (sh, bash, zsh, dash, ksh, fish, csh, tcsh).
// There is no cap on the words: padding past a cap would hide the shell.
const SHELL_BASE = /^(?:ba|z|da|k|fi|c|tc)?sh\b/i;
const wrapper = (short = "", long = [], positional = 0) => ({ short, long: new Set(long), positional });
const WRAPPERS = {
  env: { ...wrapper("uCSP", ["--unset", "--chdir", "--split-string"]), split: true },
  sudo: wrapper("CDghpRrTtUu", ["--close-from", "--chdir", "--group", "--host", "--prompt", "--chroot", "--role", "--command-timeout", "--type", "--other-user", "--user"]),
  doas: wrapper("Cu"),
  nohup: wrapper(),
  exec: wrapper("a"),
  command: wrapper(),
  builtin: wrapper(),
  time: wrapper("fo", ["--format", "--output"]),
  nice: wrapper("n", ["--adjustment"]),
  setsid: wrapper(),
  stdbuf: wrapper("ioe", ["--input", "--output", "--error"]),
  timeout: wrapper("sk", ["--signal", "--kill-after"], 1),
};
const NO_OPTS = wrapper();
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const isStageEnd = (c) => c === "|" || c === ";" || c === "&" || c === ")" || c === "`" || c === "\n";
const isBlank = (c) => c === " " || c === "\t" || c === "\r" || c === "\f" || c === "\v";
const isSpace = (c) => isBlank(c) || c === "\n";
const isRedirect = (text, i) => text[i] === ">" || text[i] === "<" || (text[i] === "&" && text[i + 1] === ">");
const unquote = (w) => { let a = 0, b = w.length; while (a < b && "'\"\\".includes(w[a])) a++; while (b > a && "'\"\\".includes(w[b - 1])) b--; return w.slice(a, b); };

/**
 * One shell word from `i`, with quotes and escapes taken out: { lit, i, quoted }.
 * Stops at an unquoted blank, stage end or redirection. A quote with no end
 * runs to the end of the text. Each character is read once.
 */
function readWord(text, i, prose = false) {
  let lit = "";
  let quoted = false;
  while (i < text.length) {
    const c = text[i];
    // The prose reading: an apostrophe inside a word ("don't") is not a quote. It
    // is dropped, as quote removal would drop it, so `b'a'sh` still reads as bash.
    if (prose && c === "'" && i > 0 && isLetter(text[i - 1]) && isLetter(text[i + 1] || "")) { quoted = true; i++; continue; }
    if (c === "\\") {
      if (text[i + 1] === "\n") { i += 2; continue; }
      if (i + 1 < text.length) lit += text[i + 1];
      quoted = true;
      i += 2;
      continue;
    }
    // A quote ends at its closing quote or at a line break (an unclosed quote
    // in prose, "don't", stops at the end of its line), as in pipeBoundaries.
    if (c === "'") {
      let j = i + 1;
      while (j < text.length && text[j] !== "'" && text[j] !== "\n") j++;
      lit += text.slice(i + 1, j);
      quoted = true;
      i = text[j] === "'" ? j + 1 : j;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"' && text[j] !== "\n") {
        if (text[j] === "\\" && j + 1 < text.length) {
          const n = text[j + 1];
          if (n !== "\n") lit += n === '"' || n === "\\" || n === "$" || n === "`" ? n : "\\" + n;
          j += 2;
          continue;
        }
        lit += text[j++];
      }
      quoted = true;
      i = text[j] === '"' ? j + 1 : j;
      continue;
    }
    if (isBlank(c) || isStageEnd(c) || c === "<" || c === ">") break;
    lit += c;
    i++;
  }
  return { lit, i: Math.min(i, text.length), quoted };
}

/** Past a redirection operator at `i` and its target word. */
function skipRedirect(text, i, zsh = false) {
  if (text[i] === "&") i++; // &> and &>>
  const op = text[i++];
  if (text[i] === op) i++; // >> <<
  if (op === "<" && text[i] === "<") i++; // <<<
  // The pipe after zsh's number glob `<1-9>|`: bash, ksh and sh read `<1-9` and `>|`, zsh a
  // glob and a pipe. A stage read the zsh way (`zsh`, started at such a pipe) stops there,
  // so these stages never overlap; every other stage reads it as main did (blind review, 22 Nov).
  if ((text[i] === "|" && !(zsh && op === ">" && globPipe(text, i))) || text[i] === "&" || (op === "<" && (text[i] === "-" || text[i] === ">"))) i++; // >| >& <& <<- <>
  while (i < text.length && isBlank(text[i])) i++;
  if (i < text.length && !isStageEnd(text[i]) && !isRedirect(text, i)) i = readWord(text, i).i;
  return i;
}

/** The words of the stage that starts after `from`, as [literal, end] pairs, without redirections. */
function stageWords(text, from, prose = false, zsh = false) {
  let i = from;
  // Blank space and line breaks right after the pipe: `curl … |` then `sh` on the next line.
  while (i < text.length && (isSpace(text[i]) || (text[i] === "\\" && text[i + 1] === "\n"))) i += text[i] === "\\" ? 2 : 1;
  // Read lazily, one word per call: a stage of millions of short words was
  // held whole as an array (1.7 GB at the 16 MiB hook-script cap, Reviewer).
  return () => {
    for (;;) {
      while (i < text.length && (isBlank(text[i]) || (text[i] === "\\" && text[i + 1] === "\n"))) i += text[i] === "\\" ? 2 : 1;
      if (i >= text.length || (!isRedirect(text, i) && isStageEnd(text[i]))) return null;
      if (isRedirect(text, i)) { i = skipRedirect(text, i, zsh); continue; }
      if (text[i] === "(") { i++; continue; } // a subshell: ( sh )
      const w = readWord(text, i, prose);
      i = w.i;
      // `2>file`: a number right before a redirection is its file descriptor.
      if (!w.quoted && /^\d+$/.test(w.lit) && (text[i] === ">" || text[i] === "<")) { i = skipRedirect(text, i, zsh); continue; }
      return [w.lit, i];
    }
  };
}

/** The stage parser's answer: the end of the shell's word, or -1. */
function parsedShellAfterPipe(text, pipe, prose = false, zsh = globPipe(text, pipe)) {
  // Frames: the stage's words (read one at a time), then the strings env -S runs ({ s, i, lim, end }).
  const stack = [{ next: stageWords(text, pipe + 1, prose, zsh) }];
  let opts = NO_OPTS;
  let skipValue = false;
  let skipPositional = 0;
  let splitNext = false;
  while (stack.length) {
    const top = stack[stack.length - 1];
    let s, a, lim, end, f = null;
    if (top.next) {
      const w = top.next();
      if (!w) { stack.pop(); continue; }
      [s, end] = w;
      a = 0;
      lim = s.length;
      if (splitNext && !skipValue) { splitNext = false; stack.push({ s, i: 0, lim, end }); continue; }
    } else {
      while (top.i < top.lim && isSpace(top.s[top.i])) top.i++;
      if (top.i >= top.lim) { stack.pop(); continue; }
      ({ s, lim, end } = top);
      a = top.i;
      f = top;
      splitNext = false; // inside a split string, -S's value is simply the next word
    }
    // A stage word is the whole literal; a word of a split string ends at a space.
    const inWord = (j) => j < lim && (!f || !isSpace(s[j]));
    const wordEnd = (j) => { while (inWord(j)) j++; return j; };
    const consume = (j) => { if (f) f.i = j; };
    // Run a split string from j: the rest of a split-string word, or a new frame over the stage word.
    const split = (j) => { if (f) f.i = j; else stack.push({ s, i: j, lim, end }); };

    if (skipValue) { skipValue = false; consume(wordEnd(a)); continue; }
    if (s[a] === "-") {
      if (s[a + 1] === "-") {
        let j = a;
        while (inWord(j) && s[j] !== "=") j++;
        const name = s.slice(a, j);
        if (inWord(j)) { // --name=value
          if (opts.split && name === "--split-string") split(j + 1);
          else consume(wordEnd(j));
          continue;
        }
        if (opts.long.has(name)) { if (opts.split && name === "--split-string") splitNext = true; else skipValue = true; }
        consume(j);
        continue;
      }
      let c = a + 1;
      for (; inWord(c); c++) {
        if (!opts.short.includes(s[c])) continue;
        // -S runs its value: read it next. Any other value is skipped.
        if (opts.split && s[c] === "S") { if (inWord(c + 1)) split(c + 1); else { splitNext = true; consume(c + 1); } }
        else if (inWord(c + 1)) consume(wordEnd(c + 1));
        else { skipValue = true; consume(c + 1); }
        break;
      }
      if (!inWord(c)) consume(c);
      continue;
    }
    const b = wordEnd(a);
    consume(b);
    const w = f ? unquote(s.slice(a, b)) : s;
    if (!w || w === "{" || w === "!") continue;
    // An assignment (NAME=value, by the shell grammar) is never the command,
    // and is read before any basename: `X=/usr/bin/timeout bash` must not pick
    // the timeout wrapper, whose positional skip would eat `bash` (Vercel R).
    if (ASSIGNMENT.test(w)) continue;
    const base = w.slice(w.lastIndexOf("/") + 1);
    if (Object.hasOwn(WRAPPERS, base)) { opts = WRAPPERS[base]; skipPositional = opts.positional; continue; }
    if (skipPositional > 0) { skipPositional--; continue; }
    if (w.includes("=")) continue;
    return SHELL_BASE.test(base) ? end : -1;
  }
  return -1;
}

/**
 * Main's regex for a pipe into a shell, kept beside the parser (R12). Written
 * so its whitespace runs cannot split one run between them: main's
 * `env\s+\S*\s*` was quadratic on `| env` and long blank space. The same
 * strings match. Tried at one "|" (sticky), so the work per pipe is the blank
 * space and the one word after it, and those of different pipes don't overlap.
 */
// Leading assignments (`| X=1 sh`, `| X=/usr/bin/timeout bash`) are taken
// too, so this regex alone covers every form main's did, and more. A value
// stops at a blank, "|", ";" or "&", so the work stays inside one stage.
const LEGACY_SHELL = /\|\s*(?:[A-Za-z_]\w*=[^\s|;&]*\s+)*(?:sudo\s+)?(?:env\s+(?:\S+\s*)?)?(?:ba|z|da|k|fi|c|tc)?sh\b/iy;
export function legacyShellAfterPipe(text, pipe) {
  LEGACY_SHELL.lastIndex = pipe;
  const m = LEGACY_SHELL.exec(text);
  return m ? pipe + m[0].length : -1;
}

/**
 * The pipeline boundaries of `text`: the "|" characters outside quotes and not
 * escaped, found in one forward pass with one quote and escape state (Vercel
 * S: a parse started at every raw "|", escaped ones too, read on past later
 * pipes, quadratic on a run of `\|`). Quotes end at a line break, as in
 * readWord, so the two agree: a stage parsed from a boundary never reads past
 * the next one, and each character is read by one stage parse.
 */
function pipeBoundaries(text) {
  const marks = new Uint8Array(text.length);
  boundaryPass(text, marks, false);
  // Prose: an apostrophe inside a word ("it's", "don't") is not a quote. A
  // second pass reads it as a plain character, and a pipe that either pass
  // finds is a boundary, so an apostrophe that pairs with a later real quote
  // can't hide the pipes between them (Reviewer, fifth pass).
  if (/[A-Za-z]'[A-Za-z]/.test(text)) boundaryPass(text, marks, true);
  return marks;
}

const isLetter = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");

/**
 * One pass of pipeBoundaries: marks the "|" outside quotes and escapes. Inside
 * double quotes, `$(...)` and backticks are code again (bash runs them), so a
 * pipe there is a boundary too; a stack keeps the quote to return to.
 * `prose`: a letter'letter apostrophe is plain.
 */
function boundaryPass(text, marks, prose) {
  let q = "";
  let qAt = -1;
  const subs = []; // substitutions opened inside "...": { depth, tick }
  for (let i = 0; ; i++) {
    const c = i < text.length ? text[i] : "\n";
    if (c === "\n") {
      // A quote still open at the line's end never closed: read the line again
      // from just after it, as if it were a plain character, so the pipes
      // after it are boundaries. No quote of that kind follows it on the line,
      // so a line is read at most three times: still linear.
      if (q) { i = qAt; q = ""; qAt = -1; subs.length = 0; continue; }
      subs.length = 0;
      if (i >= text.length) break;
      continue;
    }
    if (q === "'") { if (c === "'") q = ""; continue; }
    if (c === "\\") { i++; continue; }
    if (q === '"') {
      if (c === '"') q = "";
      else if (c === "$" && text[i + 1] === "(") { subs.push({ depth: 0, tick: false }); q = ""; i++; }
      else if (c === "`") { subs.push({ depth: 0, tick: true }); q = ""; }
      continue;
    }
    // subs[-1] on an empty stack is a slow property lookup in V8, per character.
    const top = subs.length ? subs[subs.length - 1] : null;
    if (top) {
      if (top.tick ? c === "`" : c === ")" && top.depth === 0) { subs.pop(); q = '"'; continue; }
      if (!top.tick && c === "(") top.depth++;
      else if (!top.tick && c === ")") top.depth--;
    }
    if (c === "'" && prose && i > 0 && isLetter(text[i - 1]) && isLetter(text[i + 1] || "")) continue;
    if (c === "'" || c === '"') { q = c; qAt = i; }
    else if (c === "|") marks[i] |= prose ? 2 : 1;
  }
}

/** Does the `>` right before `pipe` close zsh's number glob `<->` or `<1-9>`? Reads back over this pipe's own digits only. */
function globPipe(text, pipe) {
  if (text[pipe - 1] !== ">") return false;
  let k = pipe - 2;
  while (k >= 0 && text[k] >= "0" && text[k] <= "9") k--;
  if (text[k] !== "-") return false;
  k--;
  while (k >= 0 && text[k] >= "0" && text[k] <= "9") k--;
  if (text[k] !== "<") return false;
  // `\<1-2>` is a literal `<`, no glob: the `>|` after it is a real noclobber redirection
  // (Vercel 01M81ZND280YXHQKE6Y4GZ32A6). Counts back over this glob's own backslash run.
  let bs = 0;
  for (k--; k >= 0 && text[k] === "\\"; k--) bs++;
  return bs % 2 === 0;
}

/**
 * Is the pipe at `pipe` part of a redirection operator: `>|` (noclobber), or `<|`, `<<|`,
 * `2<|`, which ksh reads as input redirections (`2<| g bash` runs what was piped in)?
 * skipRedirect takes that pipe into the operator, so it is no stage boundary: a stage
 * started there read a file name as the command, and the stage read from the pipe before
 * already crossed it, so visiting it again re-read the rest of the line at every such pipe
 * (quadratic, Vercel 01M81PA232AMNB5SY2KD9SK6XZ, 01M81W6NMFBR969DTHNXZAWCER). Only a real
 * operator: after an odd run of backslashes the `>` or `<` is a literal and the pipe
 * separates stages (Vercel 01M81RX6174RRCJGFE054SE1EX).
 */
function redirectPipe(text, pipe) {
  if (text[pipe - 1] !== ">" && text[pipe - 1] !== "<") return false;
  if (globPipe(text, pipe)) return false;
  let bs = 0;
  for (let k = pipe - 2; k >= 0 && text[k] === "\\"; k--) bs++;
  return bs % 2 === 0;
}

/**
 * A reader for one text: (pipe) -> the end of the shell's word, or -1. The
 * boundaries are found once. The parser runs at a boundary; main's regex runs
 * at every raw "|" (it is linear per pipe), so a quoted or escaped pipe is
 * still read as main read it. Either hit counts.
 */
export function shellPipeReader(text) {
  let marks = null;
  return (pipe) => {
    marks ||= pipeBoundaries(text);
    // Each boundary is read with the reading that found it: a pipe only the prose
    // pass marks is parsed with the prose reading too, so a word glued by an
    // intra-word apostrophe is not re-read to the line's end per pipe (Vercel, PR 281).
    // At the pipe of a redirection only main's regex reads (R12: nothing it caught is lost); the
    // parser would cross every later `>|` or `<|` from each of them (blind review, 22 Nov).
    if (redirectPipe(text, pipe)) return legacyShellAfterPipe(text, pipe);
    const end = marks[pipe] & 1 ? parsedShellAfterPipe(text, pipe) : marks[pipe] & 2 ? parsedShellAfterPipe(text, pipe, true) : -1;
    return end !== -1 ? end : legacyShellAfterPipe(text, pipe);
  };
}

/**
 * The stage parser alone, for the stages after the first (Vercel 01M81EJ2X60G4EFCGC78143380,
 * 01M81JZEKWK9DVXH848JDVC3Q9): main's word reader with its wrapper arity table, env -S
 * splitting and quoting, run only at the pipe boundaries pipeBoundaries finds once per text,
 * and without the legacy regex fallback, which read to the end of the line at every pipe.
 * Stages do not overlap, so the work over a line is linear. Main's full reader (with the
 * fallback) still reads the stage right after the download (pipedFrom).
 */
export function stageParserReader(text) {
  let marks = null;
  const quotedAt = QUOTED_STAGE(text);
  return (pipe) => {
    marks ||= pipeBoundaries(text);
    if (redirectPipe(text, pipe)) return -1;
    if (marks[pipe] & 1) return parsedShellAfterPipe(text, pipe);
    if (marks[pipe] & 2) return parsedShellAfterPipe(text, pipe, true);
    // A pipe pipeBoundaries does not mark: inside a quoted string (`bash -c "curl … | cat | sh"`,
    // `ssh host '…'`, a JSON command) or escaped (`\|`). Read by a regex anchored at the pipe,
    // with no optional parts that could overlap and every repeat capped, so its cost per pipe
    // is constant (the review of d7ab9f34: these forms were not read at all).
    return quotedAt(pipe);
  };
}
// Wrappers before the shell in a quoted or escaped stage: a wrapper name, then flags (each
// starts with "-", so no flag can also be the next wrapper) or assignments, at most 16 of each.
const Q_TOKEN = String.raw`[^\s|;&"'\`]{1,256}`;
const Q_REDIR = String.raw`\d{0,4}(?:&>|>&|<&|>>|[<>])[^\s|;&"'\`<>]{0,256}`;
// Whitespace runs between tokens are unbounded (a cap hid a shell behind 17 spaces: Vercel
// 01M81PAAD8CRYYKVKPMD6RTSNJ); no token starts with whitespace, so runs never overlap.
const Q_WRAPPER = String.raw`(?:[\w.~-]{0,64}\/){0,8}(?:sudo|nohup|exec|command|builtin|setsid|time|nice|stdbuf|doas|timeout|env)(?:[ \t]+(?:-${Q_TOKEN}|[A-Za-z_]\w{0,63}=(?:${Q_TOKEN})?|${Q_REDIR}|\d{1,8})){0,16}[ \t]+`;
const Q_SHELL = new RegExp(String.raw`\\?\|[ \t]*(?:${Q_REDIR}[ \t]+){0,8}(?:${Q_WRAPPER}){0,8}(?:${Q_REDIR}[ \t]+){0,8}\\?["']?(?:[\w.~-]{0,64}\/){0,8}(?:ba|z|da|k|fi|c|tc)?sh(?![\w.-])`, "y");
function QUOTED_STAGE(text) {
  return (pipe) => { Q_SHELL.lastIndex = text[pipe - 1] === "\\" ? pipe - 1 : pipe; const m = Q_SHELL.exec(text); return m ? m.index + m[0].length : -1; };
}

/** Does the stage after the "|" at `pipe` run a shell? One-off form of shellPipeReader. */
export function shellAfterPipe(text, pipe) {
  return shellPipeReader(text)(pipe);
}

/** The parser alone, for the differential test. */
export const _parsedShellAfterPipe = parsedShellAfterPipe;

/** Index of the first "|" whose stage runs a shell, or -1. */
export function firstShellPipe(text) {
  const at = shellPipeReader(text);
  for (let p = text.indexOf("|"); p !== -1; p = text.indexOf("|", p + 1)) if (at(p) !== -1) return p;
  return -1;
}

// The rule's pattern as a regex, kept for the rule list and pack exports.
// Matching uses shellAfterPipe.
const SHELL_DOC = String.raw`(?:sudo\s+)?(?:[\w.~-]*/)*(?:env\s+)?(?:ba|z|da|k|fi|c|tc)?sh\b`;
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

/** `\|\s*sink` at a pipe: (text) -> (pipe) -> the sink's end or -1, made once per text. */
const WS = /\s/;
const regexAtPipe = (sink) => {
  const re = new RegExp(String.raw`\|\s*${sink}`, "iy");
  return (text) => (p) => {
    // A stage that cannot start a command name (`|"|`, `|\|`, `||`) is skipped before the regex.
    let k = p + 1;
    // Every whitespace `\s` accepts, Unicode included, as the regex after it reads it
    // (Vercel 01M81GXJPSXKCEAAJMNNX0KAAM: an ASCII-only skip hid `| iex` after a no-break space).
    while (k < text.length && WS.test(text[k])) k++;
    const c = text[k];
    // A stage may start with a redirection (`| </dev/null sh`, `| 2>&1 sh`).
    if (c === undefined || (c === '"' || c === "'" ? !/[\w./~]/.test(text[k + 1] || "") : !/[\w./~<>&]/.test(c))) return -1;
    re.lastIndex = p; const m = re.exec(text); return m ? p + m[0].length : -1;
  };
};

// main's reading: the download in the stage right before the pipe (kept as the base, R12).
function pipedFrom(source, sinkFor) {
  const sourceG = new RegExp(source.source, source.flags.replace(/[gy]/g, "") + "g");
  return (text) => {
    // The last newline before the pipe, tracked forward: a backward search
    // per pipe re-read the whole prefix of a line with no newline, which was
    // quadratic on "|sh|sh|sh..." (about 45 minutes at the 5 MB cap). The
    // previous "|" is at most one match back, so lastIndexOf stays linear.
    let lastNl = -1;
    let nextNl = text.indexOf("\n");
    let prevPipe = -1;
    // The source's matches, found once for the whole text and walked with a
    // pointer: matching it in a slice per pipe cost a copy per pipe, which V8
    // can make slow on a large text (83 s for 5 MiB of `| env -S x`). A source
    // match never holds "|" or a line break, so it lies inside one stage, and
    // the first one at or after the stage's start is the stage's leftmost.
    const sources = [...text.matchAll(sourceG)].map((m) => [m.index, m.index + m[0].length]);
    const sinkAt = sinkFor(text);
    let k = 0;
    for (let p = text.indexOf("|"); p !== -1 && k < sources.length; prevPipe = p, p = text.indexOf("|", p + 1)) {
      while (nextNl !== -1 && nextNl < p) { lastNl = nextNl; nextNl = text.indexOf("\n", nextNl + 1); }
      const start = Math.max(prevPipe, lastNl) + 1;
      while (k < sources.length && sources[k][0] < start) k++;
      // The source must be in the stage just before this pipe; only then is the sink read.
      if (k >= sources.length || sources[k][1] > p) continue;
      const end = sinkAt(p);
      if (end !== -1) return matchAt(text, sources[k][0], end);
    }
    return null;
  };
}

/**
 * `first[^\n]*second`: leftmost `first`, extended to the last `second` that
 * starts on its line. A `second` that begins with `\|` may run past the line
 * end (`\|\s*sh` spans a newline), so it is tried at each pipe on the line.
 */
// A pipe whose stage can start a command name: the wider readings visit only these, found by
// one native regex, so 16 MiB of `"|` or `\|` costs no JavaScript loop per pipe (CI, 22 Nov).
const CANDIDATE_PIPE = /\|(?!\|)[ \t\r\n]*["']?[\w./~<>&]/g;
let candText = null, candAt = -1, candFrom = -1;
/** The first candidate pipe at or after `from`, or -1. Searches again only when `from` passes the cached one. */
function nextCandidate(text, from) {
  if (candText !== text || from < candFrom || (candAt !== -1 && from > candAt)) {
    candText = text; candFrom = from;
    CANDIDATE_PIPE.lastIndex = from;
    const c = CANDIDATE_PIPE.exec(text);
    candAt = c ? c.index : -1;
  }
  return candAt;
}
function thenOnLine(first, second, { skipOr = false, candidates = false } = {}) {
  const firstG = new RegExp(first, "gi");
  // `second` is a regex source, or a reader factory (text) -> (pipe) -> end | -1 tried at each pipe.
  const atPipeFn = typeof second === "function" ? second : null;
  const secondG = atPipeFn ? null : new RegExp(second, "gi");
  const atPipe = atPipeFn || second.startsWith("\\|");
  const sinkFor = atPipeFn || (atPipe ? regexAtPipe(second.slice(2)) : null);
  // Pipe positions once per text: indexOf("|") from each line ran to the end of a
  // file with no pipes, once per line (quadratic, blind review of batch 1).
  let pipesOf = null, pipes = null;
  const firstPipe = (text, from) => {
    if (pipesOf !== text) { pipesOf = text; pipes = []; for (let i = text.indexOf("|"); i !== -1; i = text.indexOf("|", i + 1)) pipes.push(i); }
    let lo = 0, hi = pipes.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (pipes[mid] < from) lo = mid + 1; else hi = mid; }
    return lo;
  };
  const lastOnLine = (text, from, eol, sinkAt) => {
    let last = null;
    if (atPipe && candidates) {
      // The next candidate is cached per text: a search per line that found none ran to the
      // end of the file each time (quadratic on lines with no pipe).
      for (let p = nextCandidate(text, from); p !== -1 && p < eol; p = nextCandidate(text, p + 1)) {
        if (skipOr && text[p - 1] === "|") continue;
        const end = sinkAt(p);
        if (end !== -1) last = { 0: text.slice(p, end), index: p };
      }
    } else if (atPipe) {
      let k = firstPipe(text, from);
      for (let p = pipes[k] ?? -1; p >= 0 && p < eol; p = pipes[++k] ?? -1) {
        // `a || sh b` is "or", not a pipe (the curl rules only; base64 and iex read as on main).
        if (skipOr && (text[p + 1] === "|" || text[p - 1] === "|")) continue;
        const end = sinkAt(p);
        if (end !== -1) last = { 0: text.slice(p, end), index: p };
      }
    } else {
      for (const b of text.slice(from, eol).matchAll(secondG)) last = { 0: b[0], index: from + b.index };
    }
    return last;
  };
  return (text) => {
    let skipTo = 0;
    const sinkAt = sinkFor ? sinkFor(text) : null;
    for (const a of text.matchAll(firstG)) {
      if (a.index < skipTo) continue;
      const aEnd = a.index + a[0].length;
      let eol = text.indexOf("\n", aEnd);
      if (eol < 0) eol = text.length;
      // Only the first `first` on a line needs checking: any `second` after a
      // later one is also after this one.
      skipTo = eol;
      const last = lastOnLine(text, aEnd, eol, sinkAt);
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

// `curl -o /tmp/a URL && sh /tmp/a`, `wget -O f URL; bash f`, `curl -sSLo a URL && bash a`,
// `curl -O URL/i.sh && sh i.sh`, `curl URL > f && chmod +x f && ./f`: a path a download saved,
// run later: on the same or a continued line, or on a later line where the runner starts a command.
// Linear: one pass over saves, one over runs, keyed by the path; no regex backtracking
// over a line (the patterns hold no unbounded run next to another).
const DL_CMD = /\b(?:curl|wget)\b/gi;
// An output flag (alone, glued or in a cluster: -o a, -oa, -sSLo a, -O a, --output=a,
// --output-document a) or a redirect, then the path.
const DL_OUT = /(?:(?<=\s)-[a-zA-Z]*[oO](?:\s+|(?=[./~\w]))|--output(?:-document)?(?:=|\s+)|>\s*)(["']?)([^\s"';&|<>]+)\1/g;
// A URL's scheme; the rest of the URL is read once, forward, by urlBasename (a regex with
// `[^…]*\/([^…]+)` rescanned the suffix at every scheme: Vercel 01M81D7JAEHCS2BK2ZJDNKM0QJ).
const DL_REMOTE = /\b(?:https?|ftp):\/\//g;
const URL_STOP = new Set([" ", "\t", "\n", "\r", '"', "'", "|", ";", "&", "<", ">"]);
/** The URL token from `i` (after the scheme) to its end, and the last path segment's name, or null. */
function urlBasename(text, i) {
  let end = i, lastSlash = -1, pathEnd = -1;
  while (end < text.length && !URL_STOP.has(text[end])) {
    const c = text[end];
    if (pathEnd === -1 && (c === "?" || c === "#")) pathEnd = end;
    if (pathEnd === -1 && c === "/") lastSlash = end;
    end++;
  }
  if (lastSlash === -1) return { end, name: null };
  const name = text.slice(lastSlash + 1, pathEnd === -1 ? end : pathEnd);
  return { end, name: name || null };
}
// What runs a file: a shell or interpreter by name (also after a path, `/bin/sh`), then
// its flags, an optional `<`, and the file. The name is found by a regex with no
// repetition; the rest is read by tokens (a repeated wrapper group backtracked on
// `env env env …`, blind review of batch 1).
const RUNNER_NAME = /(?<=^|[\s(`/])(?:(?:ba|z|da|k|fi|tc)?sh|source|\.|python[0-9.]*|node|perl|ruby|php|deno|bun)(?=[ \t])/g;
const TOKEN_STOP = new Set([" ", "\t", "\n", ";", "&", "|", "(", ")", "<", ">", "`"]);
/** The file a runner at `end` runs: skip flags (at most 8) and a `<`, return [path, end] or null. */
function runnerTarget(text, end) {
  let i = end;
  for (let tokens = 0; tokens < 10; tokens++) {
    while (text[i] === " " || text[i] === "\t") i++;
    if (text[i] === "<") { i++; continue; }
    const start = i;
    while (i < text.length && !TOKEN_STOP.has(text[i])) i++;
    if (i === start) return null;
    const tok = text.slice(start, i);
    if (tok.startsWith("-")) continue;
    const path = tok.replace(/^["']/, "").replace(/["']$/, "");
    return path ? [path, i] : null;
  }
  return null;
}
const CHMOD = /\bchmod\b/g;
const RUN_WORD_STOP = new Set([" ", "\t", "\n", "\r", '"', "'", ";", "&", "|", "(", ")", "<", ">", "`"]);
const EXECUTABLE_MODE = /^(?:[ugoa]*[+=][rwX]*x|[0-7]?[1357][0-7]{2}|[0-7]?[0-7][1357][0-7]|[0-7]?[0-7]{2}[1357])$/;
const norm = (p) => p.replace(/^\.\//, "");

/**
 * Can a command start at `i`? Line start, after a separator (`;`, `|`, `&`, `(`, `$(`, a
 * backtick) or a wrapper (`sudo`, `env`, `exec`, `nohup`, `time`, `command`), or the start of a
 * quoted body run as code (`bash -c "…"`, `sh -lc '…'`, `eval "…"`). Reads back at most 40 characters.
 */
function commandPosition(text, i, depth = 0) {
  let k = i;
  while (k > 0 && (text[k - 1] === " " || text[k - 1] === "\t")) k--;
  if (k === 0 || "\n;|&(`".includes(text[k - 1])) return true;
  const q = text[k - 1];
  if (q === '"' || q === "'") {
    const before = text.slice(Math.max(0, k - 41), k - 1);
    return /(?:^|\s)(?:-[a-zA-Z]*c|eval)\s*$/.test(before) || /\$\($/.test(before);
  }
  const word = text.slice(Math.max(0, k - 12), k).split(/\s/).pop();
  return depth < 4 && /^(?:sudo|env|exec|nohup|time|command|then|do|else)$/.test(word) && commandPosition(text, k - word.length, depth + 1);
}

/** Does the word at `i` (after any path before it) start a command: line start, a separator, or a wrapper? */
function startsCommand(text, i, depth = 0) {
  let k = i;
  while (k > 0 && !/\s/.test(text[k - 1]) && !";&|(`".includes(text[k - 1])) k--;
  let j = k;
  while (j > 0 && (text[j - 1] === " " || text[j - 1] === "\t")) j--;
  if (j === 0 || text[j - 1] === "\n" || ";&|(`".includes(text[j - 1])) return true;
  const word = text.slice(Math.max(0, j - 8), j).split(/\s/).pop();
  return depth < 4 && /^(?:sudo|env|exec|nohup|command|then|do|else)$/.test(word) && startsCommand(text, j - word.length, depth + 1);
}

// Both readings, and a hit from either: every downloader word (a Dockerfile's `RUN curl`, a
// JSON launch command, `$ curl` in docs) and only those at a command position (so a word
// inside another command's arguments, `wget --header "X: curl"`, cannot claim the download).
function downloadThenRun(text) {
  return downloadThenRunWith(text, false) || downloadThenRunWith(text, true);
}

function downloadThenRunWith(text, positionOnly) {
  // Continued lines (`&& \` then a newline) are one command.
  text = text.replace(/\\\r?\n/g, "  ");
  // Segment starts: an output flag belongs to the curl or wget of its own command.
  // Only a curl or wget where a command can start counts: not the word inside another
  // command's arguments (`wget --header "X: curl" …`, Vercel 01M81J4P1T65EM44K1DKJFX9BD).
  const all = [...text.matchAll(DL_CMD)].map((m) => m.index);
  const cmds = positionOnly ? all.filter((i) => commandPosition(text, i)) : all;
  if (!cmds.length) return null;
  // The last separator before i, by one forward scan that stops at the last query: an array
  // of every separator cost 8 million entries on 16 MiB of `"|` (CI timing, 22 Nov).
  let scan = 0, lastSep = -1, ci = 0, inS = false, inD = false, esc = false, prevLiteral = false;
  const segStart = (i) => {
    // `&` separates commands, except in a redirection (`2>&1`, `&>f`, `<&3`): Vercel 01M81GX5A9BKY6BCFZMZ8N3CCT.
    // A small shell reader: single and double quotes and backslash escapes are tracked, and
    // `;`, `|`, `&` separate commands only outside quotes and unescaped. A redirection's `&`
    // (`2>&1`, `&>f`, `<&3`, after an unescaped `>`/`<`) is no separator. A newline ends any
    // quote, so an unclosed decoy quote cannot swallow the rest of the file.
    // (Vercel 01M81GX5A9BKY6BCFZMZ8N3CCT, 01M81HBH284HKWT0GEWW9E0R55, 01M81HKWG8PMBSDPD6CXAYQZDW.)
    for (; scan < i; scan++) {
      const c = text.charCodeAt(scan);
      if (c === 10) { lastSep = scan; inS = inD = esc = false; prevLiteral = false; continue; }
      if (esc) { esc = false; prevLiteral = true; continue; }
      if (c === 92 && !inS) { esc = true; continue; }
      if (inS) { if (c === 39) inS = false; prevLiteral = false; continue; }
      if (inD) { if (c === 34) inD = false; prevLiteral = false; continue; }
      if (c === 39) inS = true;
      else if (c === 34) inD = true;
      else if (c === 59 || c === 124) lastSep = scan;
      else if (c === 38) {
        const p = text[scan - 1], n = text[scan + 1];
        const redirect = ((p === ">" || p === "<") && !prevLiteral) || n === ">";
        if (!redirect) lastSep = scan;
      }
      prevLiteral = false;
    }
    return lastSep;
  };
  // The nearest curl or wget before `i` in its segment, not the first: inside a quoted
  // `bash -c "curl a; wget URL/i.sh; sh i.sh"` body a harmless curl must not claim wget's
  // download (Vercel 01M81HWRT5611WTCF243Z3PVG2). Queries come in increasing order.
  const cmdIn = (from, i) => { while (ci < cmds.length && cmds[ci] < i) ci++; return ci > 0 && cmds[ci - 1] >= from ? cmds[ci - 1] : -1; };
  const saved = new Map(); // path -> [download start, end of the saving flag]
  const save = (path, at, end) => {
    if (!path || path === "-" || path === "/dev/null") return;
    const k = norm(path);
    if (!saved.has(k) || saved.get(k)[1] > end) saved.set(k, [at, end]);
  };
  for (const m of text.matchAll(DL_OUT)) {
    const c = cmdIn(segStart(m.index) + 1, m.index);
    if (c !== -1) save(m[2], c, m.index + m[0].length);
  }
  scan = 0; lastSep = -1; ci = 0; inS = inD = esc = prevLiteral = false;
  // `curl -O URL/i.sh` and a plain `wget URL/i.sh` save under the URL's last name.
  let urlSeen = 0;
  for (const m of text.matchAll(DL_REMOTE)) {
    // A scheme inside a URL already read is part of that URL.
    if (m.index < urlSeen) continue;
    const u = urlBasename(text, m.index + m[0].length);
    urlSeen = u.end;
    m[1] = u.name;
    if (!m[1]) continue;
    m[0] = text.slice(m.index, u.end);
    const c = cmdIn(segStart(m.index) + 1, m.index);
    if (c === -1) continue;
    // A plain curl writes to stdout: only `curl -O`/`--remote-name`, or a wget with no -O, saves under the URL's name.
    const head = text.slice(Math.max(c, m.index - 400), m.index);
    const isCurl = /^curl/i.test(text.slice(c, c + 4));
    if (isCurl ? /\s-[a-zA-Z]*O(?:\s|$)|--remote-name/.test(head) : !/\s-[a-zA-Z]*O|--output-document/.test(head)) save(m[1], c, m.index + m[0].length);
  }
  if (!saved.size) return null;
  const executable = new Set();
  for (const m of text.matchAll(CHMOD)) {
    const words = text.slice(m.index + 5, m.index + 200).split(/[;&|\n]/, 1)[0].trim().split(/\s+/);
    if (words.some((w) => EXECUTABLE_MODE.test(w))) for (const w of words) executable.add(norm(w.replace(/^["']|["']$/g, "")));
  }
  // Newline positions, for "is the run on the save's own line?".
  const nls = [];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) nls.push(i);
  const lineAt = (i) => { let lo = 0, hi = nls.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (nls[mid] < i) lo = mid + 1; else hi = mid; } return lo; };
  const ran = (path, at) => {
    const s = saved.get(norm(path));
    if (!s || s[1] > at) return null;
    // On a later line the runner must start a command, so prose ("the sh out.txt step") is not a run.
    return lineAt(at) === lineAt(s[1]) || startsCommand(text, at) ? s : null;
  };
  for (const r of text.matchAll(RUNNER_NAME)) {
    const t = runnerTarget(text, r.index + r[0].length);
    const s = t && ran(t[0], r.index);
    if (s) return matchAt(text, s[0], t[1]);
  }
  // Run as a command itself after chmod: `&& ./f`, `; /tmp/a`.
  // Each command word read once with its quote (a regex with two slash-accepting runs and a
  // backreference backtracked on an unclosed quote: Vercel 01M81D87JJVN1S12PFW96K6RQN).
  if (executable.size) {
    for (const m of text.matchAll(/(?:&&|;|\|\||\n)/g)) {
      let i = m.index + m[0].length;
      while (text[i] === " " || text[i] === "\t") i++;
      if (text.startsWith("sudo", i) && (text[i + 4] === " " || text[i + 4] === "\t")) { i += 4; while (text[i] === " " || text[i] === "\t") i++; }
      const q = text[i] === '"' || text[i] === "'" ? text[i] : "";
      let j = i + (q ? 1 : 0);
      const start = j;
      while (j < text.length && !RUN_WORD_STOP.has(text[j]) && text[j] !== q) j++;
      if (q && text[j] !== q) continue;
      const word = text.slice(start, j);
      if (!word.includes("/")) continue;
      // The word's own position: on a later line the "starts a command" test reads back from it.
      const s = executable.has(norm(word)) && ran(word, start);
      if (s) return matchAt(text, s[0], j + (q ? 1 : 0));
    }
  }
  return null;
}

// `python3 -c "$(curl …)"`, `bash -lc "$(curl …)"`, `php -r "`curl …`"`: an interpreter's
// inline-code flag around a command substitution of a download. Read back from each
// substitution over at most 160 characters of its line, by tokens (no backtracking).
const SUBST_DL = /(?:\$\(|`)\s*(?:curl|wget)\b/gi;
const INLINE_RUNNER = /^(?:[\w.~-]*\/)*(?:python[0-9.]*|node|perl|ruby|php|deno|bun|(?:ba|z|da|k)?sh)$/i;
const trimEndOf = (str, chars) => { let e = str.length; while (e > 0 && chars.includes(str[e - 1])) e--; return str.slice(0, e); };
function interpreterInlineDownload(text) {
  let ls = 0;
  let nextNl = text.indexOf("\n");
  for (const m of text.matchAll(SUBST_DL)) {
    // The line start, tracked forward with the next newline cached (a search per match was quadratic).
    while (nextNl !== -1 && nextNl < m.index) { ls = nextNl + 1; nextNl = text.indexOf("\n", ls); }
    const before = trimEndOf(text.slice(Math.max(ls, m.index - 160), m.index), "\"' \t");
    const toks = before.split(/\s+/);
    const flag = trimEndOf(toks.at(-1) || "", "\"'");
    if (!flag || !/^-[a-zA-Z]*[cer]$/.test(flag) && !/^-[a-zA-Z]*[cer]["']/.test(toks.at(-1) || "")) continue;
    // The runner: the nearest earlier token that names one, flags allowed between.
    for (let i = toks.length - 2; i >= 0 && i >= toks.length - 8; i--) {
      if (INLINE_RUNNER.test(toks[i].replace(/^["'`(]+/, ""))) {
        const start = text.indexOf(toks[i], Math.max(ls, m.index - 160));
        return matchAt(text, start, m.index + m[0].length);
      }
      if (!toks[i].startsWith("-")) break;
    }
  }
  return null;
}

// The wider reading of a later stage: a sticky regex at each pipe, whose cost is one word
// (the full stage parser at every pipe was quadratic on `| env | env …`, CI 22 Nov). Main's
// parser still reads the stage right after the download (pipedFrom), so nothing it found is lost.
// The shell's name is a whole word or a path's last part (`/bin/sh`), never a file's
// extension (`./install.sh` is a script, not a shell reading stdin).

const JS_EVAL_REMOTE = /\b(?:eval|Function)\s*\(\s*(?:await\s+)?(?:atob|Buffer\.from|fetch|require\(\s*["']child_process|\(await fetch)/;
const evalAsCallback = thenOnLine(String.raw`\bfetch\s*\(`, String.raw`\.then\(\s*(?:(?:globalThis|window|self)\.)?eval\s*\)`);

export const EXEC_PATTERNS = [
  {
    rule: "curl-pipe-shell", label: "download piped to a shell",
    // A shell stage anywhere later on the line, as base64-pipe-shell reads it:
    // `curl … | cat | sh`, `| tee f | bash` and `| gunzip | sh` still run the
    // download (Mythos A5, 12 Nov: only the stage right after the download was read).
    re: new RegExp(String.raw`\b(?:curl|wget|fetch|iwr)\b[^\n]*\|\s*${SHELL_DOC}`, "i"),
    // main's reading, plus a shell stage at any later pipe on the line (one word read per pipe).
    match: earliest(pipedFrom(/\b(?:curl|wget|fetch|iwr)\b/i, shellPipeReader), thenOnLine(String.raw`\b(?:curl|wget|fetch|iwr)\b`, stageParserReader, { skipOr: true, candidates: true })),
  },
  {
    rule: "curl-pipe-interpreter", label: "download piped to an interpreter",
    re: /\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php|deno|bun)\b/i,
    match: earliest(pipedFrom(/\b(?:curl|wget)\b/i, regexAtPipe(INTERPRETER)), thenOnLine(String.raw`\b(?:curl|wget)\b`, regexAtPipe(INTERPRETER), { skipOr: true, candidates: true })),
  },
  {
    rule: "download-then-run", label: "download saved to a file, then run",
    // The definition, for the rule list: matching is downloadThenRun (the same path, saved then run).
    re: /\b(?:curl|wget)\s[^\n]*(?:\s-[oO]|--output|>)/i,
    match: downloadThenRun,
  },
  // Process and command substitution: lib/rules/core/agent-exec.json.
  ...rulesOf("agent-exec", { pack: "core" }).map((r) => ({ rule: r.id, label: r.label, re: r.pattern })),
  // The signed pack's two forms miss `. <(curl …)` (its `\b\.` can't match a lone dot)
  // and an interpreter's -c or -e (Mythos A5). Added here, beside the pack; the pack
  // itself changes only with a maintainer's signature.
  { rule: "shell-process-substitution", label: "shell runs a download via process substitution", re: /(?:^|[\s;&|("'`])\.\s+<\(\s*(?:curl|wget)\b/i },
  { rule: "shell-command-substitution", label: "interpreter -c runs a download", re: /\b(?:python[0-9.]*|node|perl|ruby|php|deno|bun)\s+-[cer]\s+["']?\$\(\s*(?:curl|wget)\b/i, match: interpreterInlineDownload },
  {
    rule: "base64-pipe-shell", label: "decoded base64 piped to a shell",
    re: new RegExp(String.raw`base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*${SHELL_DOC}`, "i"),
    match: thenOnLine(String.raw`base64\s+(?:-d|--decode|-D)\b`, shellPipeReader),
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
    // One hit per rule: a rule may have a pack form and a JS form (shell-command-substitution).
    if (m && !out.some((h) => h.rule === p.rule)) out.push({ rule: p.rule, label: p.label, match: m[0], index: m.index });
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
