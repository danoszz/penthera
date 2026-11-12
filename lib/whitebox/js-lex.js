/**
 * A small JavaScript/TypeScript lexer for the code-sink rules: it tells code
 * from comments, strings, template literals and regular-expression literals,
 * and returns three copies of the source, each the same length as the input
 * with every line break kept, so an index or a line number means the same
 * thing in all of them:
 *
 *   plain  comments blanked; strings, templates and regex literals kept
 *   code   comments blanked; the contents of strings, templates (with their
 *          `${...}` parts) and regex literals blanked, delimiters kept
 *   expr   like code, but the code inside a template's `${...}` is kept: the
 *          names an expression uses, without the text of its strings
 *
 * Why a lexer and not two quote-tracking loops: a regex literal that contains
 * a quote (`/[\s\w:'",]*\/`) used to open a "string" that ran on to the next
 * matching quote, so a real call below it was masked as string content and
 * missed. A `/` starts a regex literal where an expression may start (after
 * `(`, `,`, `=`, an operator, `return`, `typeof`, ...), and is division after
 * a name, a number or a closing bracket. That is the rule JavaScript engines
 * use too, short of a full parse; the cases it gets wrong (a regex literal
 * right after a block's `}`) are rare in source code.
 *
 * Nothing here runs or evaluates the code.
 */

// After one of these words a `/` starts a regex literal, not a division.
const REGEX_AFTER_WORD = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
  "case", "do", "else", "yield", "await",
]);

const SP = 32, NL = 10, CR = 13, TAB = 9, LS = 0x2028, PS = 0x2029;
// JavaScript's line terminators: each ends a line comment and a regex literal.
// A string ends at LF and CR only; LS and PS are allowed inside strings since ES2019.
const isLineEnd = (c) => c === NL || c === CR || c === LS || c === PS;
const Q1 = 39, Q2 = 34, BT = 96, SL = 47, STAR = 42, BS = 92, DOLLAR = 36;
const LBR = 123, RBR = 125, LSQ = 91, RSQ = 93, RPAR = 41;
const isSpace = (c) => c === SP || c === NL || c === CR || c === TAB || c === 11 || c === 12 || c === 0xa0 || c === 0xfeff || c === 0x2028 || c === 0x2029;
const isIdent = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === DOLLAR || c > 127;
const isLetter = (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const decoder = new TextDecoder("utf-16le");
const toText = (u16) => decoder.decode(u16);

/**
 * Lex `src`. To lex a file in pieces (lexJsStream), pass the `state` the
 * previous piece returned: it carries what can cross a piece's end (template
 * nesting and text, an open block or line comment, an open string, the last
 * significant character and word for the regex-or-division rule), so each
 * piece is lexed exactly as the whole file would be.
 * @param {string} src
 * @param {object} [state] from the previous piece; omit for a whole file
 * @returns {{ code: string, plain: string, expr: string, state: object }}
 */
export function lexJs(src, state = null, opts = {}) {
  const n = src.length;
  // opts.stringLineSeps: collect where U+2028 or U+2029 sits inside a quoted
  // string (string content since ES2019, not a line end), for jsLineBreaks.
  const strSeps = opts.stringLineSeps ? [] : null;
  const noteSep = (j) => { if (strSeps && (s[j] === LS || s[j] === PS)) strSeps.push(j); };
  const plain = new Uint16Array(n);
  for (let k = 0; k < n; k++) plain[k] = src.charCodeAt(k);
  const s = plain.slice();
  const code = plain.slice();
  const expr = plain.slice();
  const sp = (c) => (isLineEnd(c) ? c : SP);
  // Inside a string, a template's text or a regex literal: hidden from code and expr.
  const mask = (k) => { const b = sp(s[k]); code[k] = b; expr[k] = b; };
  // A comment: hidden from all three.
  const blank = (k) => { const b = sp(s[k]); code[k] = b; expr[k] = b; plain[k] = b; };
  // Template nesting: each entry is the brace depth inside a `${ ... }` part.
  const tpl = state ? [...state.tpl] : [];
  // Code inside `${...}` is lexed (so nested quotes stay in step) and hidden from code only.
  const emitCode = (k) => { if (tpl.length) code[k] = sp(s[k]); };
  let inTemplateText = state?.inTemplateText || false;
  let i = 0;
  // Last significant code character, and where the word that ends there starts.
  let lastSig = state?.lastSig || 0;
  let wordStart = -1;
  // (position, state) pairs that failed regex-literal scans passed (see below).
  let failed = null;
  // The word that ended the previous piece, when lastSig is part of it.
  const prevWord = state?.lastWord || "";
  // What was open when the previous piece ended.
  let carryString = state?.inString || 0;     // a quote char
  let carryBlock = state?.inBlock || false;
  let carryLine = state?.inLineComment || false;
  let endString = 0, endBlock = false, endLine = false;

  const regexAllowed = () => {
    if (!lastSig) return true;
    if (lastSig === RPAR || lastSig === RSQ || lastSig === RBR) return false;
    if (isIdent(lastSig)) {
      if (wordStart < 0) return REGEX_AFTER_WORD.has(prevWord);
      let e = i - 1;
      while (e > wordStart && isSpace(s[e])) e--;
      return REGEX_AFTER_WORD.has(src.slice(wordStart, e + 1));
    }
    if (lastSig === Q1 || lastSig === Q2 || lastSig === BT) return false;
    return true;
  };

  // Finish what the previous piece left open.
  if (carryLine) {
    while (i < n && !isLineEnd(s[i])) { blank(i); i++; }
    if (i >= n) endLine = true;
  } else if (carryBlock) {
    const end = src.indexOf("*/");
    const stop = end === -1 ? n : end + 2;
    for (; i < stop; i++) blank(i);
    if (end === -1) endBlock = true;
  } else if (carryString) {
    const q = carryString;
    let j = 0;
    for (; j < n; j++) {
      const d = s[j];
      if (d === BS) { mask(j); if (j + 1 < n) mask(j + 1); j++; continue; }
      if (d === q || d === NL || d === CR) break;
      noteSep(j);
      mask(j);
    }
    if (j >= n) endString = q;
    else if (s[j] === q) { emitCode(j); j++; lastSig = q; }
    i = j;
  }

  while (i < n) {
    const c = s[i];
    if (inTemplateText) {
      if (c === BS) { mask(i); if (i + 1 < n) mask(i + 1); i += 2; continue; }
      if (c === BT) { inTemplateText = false; if (tpl.length) mask(i); lastSig = BT; i++; continue; }
      if (c === DOLLAR && s[i + 1] === LBR) { mask(i); mask(i + 1); tpl.push(0); inTemplateText = false; lastSig = LBR; i += 2; continue; }
      mask(i); i++; continue;
    }
    if (c === SL && s[i + 1] === SL) {
      while (i < n && !isLineEnd(s[i])) { blank(i); i++; }
      if (i >= n) endLine = true;
      continue;
    }
    if (c === SL && s[i + 1] === STAR) {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? n : end + 2;
      for (; i < stop; i++) blank(i);
      if (end === -1) endBlock = true;
      continue;
    }
    if (c === Q1 || c === Q2) {
      emitCode(i);
      let j = i + 1;
      for (; j < n; j++) {
        const d = s[j];
        if (d === BS) { mask(j); if (j + 1 < n) mask(j + 1); j++; continue; }
        if (d === c) break;
        // An unterminated string ends at the line break, LF or CR (a syntax error anyway).
        if (d === NL || d === CR) break;
        noteSep(j);
        mask(j);
      }
      if (j >= n) endString = c; // still open at the piece's end (an escaped line break, or a cut)
      if (j < n && s[j] === c) { emitCode(j); j++; }
      i = j; lastSig = c;
      continue;
    }
    if (c === BT) {
      if (tpl.length) mask(i);
      i++; inTemplateText = true;
      continue;
    }
    if (c === SL && regexAllowed()) {
      // Scan the literal: up to an unescaped `/` outside a character class, on one line.
      // A walk's future depends only on its position and whether it is inside a
      // class, so a failed walk marks every (position, state) it passed; a later
      // walk that reaches a marked pair fails the same way and stops there. Each
      // position is walked at most twice by failing scans: linear.
      const walk = (mark) => {
        let j = i + 1;
        let inClass = false;
        for (; j < n; j++) {
          const bit = inClass ? 2 : 1;
          if (failed && (failed[j] & bit)) return -1;
          if (mark) failed[j] |= bit;
          const d = s[j];
          if (isLineEnd(d)) return -1;
          if (d === BS) { j++; continue; }
          if (inClass) { if (d === RSQ) inClass = false; continue; }
          if (d === LSQ) inClass = true;
          else if (d === SL) return j;
        }
        return -1;
      };
      let j = walk(false);
      if (j === -1) { failed ||= new Uint8Array(n); walk(true); }
      if (j !== -1) {
        emitCode(i);
        for (let k = i + 1; k < j; k++) mask(k);
        emitCode(j);
        j++;
        while (j < n && isLetter(s[j])) { emitCode(j); j++; }
        i = j; lastSig = RPAR;
        continue;
      }
      // Not a well-formed literal: treat the slash as an operator.
    }
    if (tpl.length) {
      if (c === LBR) tpl[tpl.length - 1]++;
      else if (c === RBR) {
        if (tpl[tpl.length - 1] === 0) { tpl.pop(); mask(i); inTemplateText = true; i++; continue; }
        tpl[tpl.length - 1]--;
      }
    }
    emitCode(i);
    if (!isSpace(c)) {
      if (isIdent(c) && !(i > 0 && isIdent(s[i - 1]))) wordStart = i;
      lastSig = c;
    }
    i++;
  }
  // The word lastSig ends, for the next piece's regex-or-division rule.
  let lastWord = "";
  if (isIdent(lastSig)) {
    if (wordStart >= 0) {
      let e = n - 1;
      while (e > wordStart && isSpace(s[e])) e--;
      lastWord = src.slice(wordStart, e + 1);
    } else lastWord = prevWord;
  }
  const next = { tpl, inTemplateText, lastSig, lastWord, inString: endString, inBlock: endBlock, inLineComment: endLine };
  return { code: toText(code), plain: toText(plain), expr: toText(expr), state: next, stringLineSeps: strSeps };
}

/**
 * `src` with each JavaScript line break other than \n and the \r of \r\n
 * turned into \n, length unchanged, for code that splits lines on \n. As the
 * spec reads them: a lone CR, U+2028 and U+2029 end a line in code, comments
 * and template literals, but U+2028 and U+2029 inside a '…' or "…" string are
 * string content. Turning those into \n too ended the string early, so its
 * rest read as code: `"a<U+2028>//"; evil()` hid evil() in a comment
 * (Vercel, 2.3.2). One lexJs pass.
 */
export function jsLineBreaks(src) {
  const text = String(src ?? "");
  // CRLF alone changes nothing: lex only for a lone CR or U+2028/U+2029 (Mythos review of PR 281).
  if (!/\r(?!\n)|[\u2028\u2029]/.test(text)) return text;
  const keep = new Set(lexJs(text, null, { stringLineSeps: true }).stringLineSeps);
  let out = "";
  let at = 0;
  for (const m of text.matchAll(/\r(?!\n)|[\u2028\u2029]/g)) {
    if (keep.has(m.index)) continue;
    out += text.slice(at, m.index) + "\n";
    at = m.index + 1;
  }
  return out + text.slice(at);
}

/** Blank out comments (same length, line breaks kept), leaving strings and regex literals as they are. */
export function stripComments(src) {
  return lexJs(src).plain;
}

/** Blank out comments and the contents of strings, templates and regex literals (same length, delimiters kept). */
export function maskStrings(src) {
  return lexJs(src).code;
}

/**
 * Index of the bracket that closes the one at `open`, in masked code (strings
 * and comments already blanked), or -1 within `limit` characters.
 */
export function matchBracket(code, open, limit = Infinity) {
  const openCh = code[open];
  if (openCh !== "(" && openCh !== "[" && openCh !== "{") return -1;
  let depth = 0;
  const stop = Math.min(code.length, open + limit);
  for (let i = open; i < stop; i++) {
    const c = code.charCodeAt(i);
    if (c === 40 || c === LSQ || c === LBR) depth++;
    else if (c === RPAR || c === RSQ || c === RBR) { if (--depth === 0) return i; }
  }
  return -1;
}

/**
 * Every bracket pair in masked code at once: a function from the index of an
 * opening bracket to matchBracket(code, open, limit), in O(1). One pass with a
 * stack; any closing bracket closes the innermost open one, as matchBracket
 * counts. Calling matchBracket for each of many nested functions read the
 * same text again per level (quadratic in the depth).
 */
export function bracketPairs(code) {
  const pair = new Int32Array(code.length).fill(-1);
  const stack = [];
  for (let i = 0; i < code.length; i++) {
    const c = code.charCodeAt(i);
    if (c === 40 || c === LSQ || c === LBR) stack.push(i);
    else if ((c === RPAR || c === RSQ || c === RBR) && stack.length) pair[stack.pop()] = i;
  }
  return (open, limit = Infinity) => {
    const close = open >= 0 && open < pair.length ? pair[open] : -1;
    return close !== -1 && close - open < limit ? close : -1;
  };
}

/** Split an argument list (masked and plain copies of the same text) at top-level commas; returns plain pieces. */
export function splitTopLevel(maskedText, plainText) {
  const out = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < maskedText.length; i++) {
    const c = maskedText[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) { out.push(plainText.slice(from, i)); from = i + 1; }
  }
  const last = plainText.slice(from);
  if (last.trim() || out.length) out.push(last);
  return out;
}

const isLineEndCh = (ch) => isLineEnd(ch.charCodeAt(0));

/**
 * The comments of `source` a pattern match may be dropped in: [start, end) spans,
 * from the lexer's blanking (lexJs `plain`). A comment counts only when no `/`
 * comes before its opener on the same line. A regex literal the lexer took for a
 * division can open a false comment (`}\n/a\/*\/.test(s); el.innerHTML = x`), and
 * that needs the regex's own `/` earlier on the line, since a regex literal can't
 * span lines; so a false comment never counts, and a match in it is kept.
 * One pass, linear in the file.
 */
export function droppableComments(source, plain) {
  const spans = [];
  let slashBefore = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (isLineEndCh(c)) { slashBefore = false; continue; }
    if (c !== "/") continue;
    if (plain[i] === "/") { slashBefore = true; continue; }
    // A `/` the lexer blanked opens a comment.
    let end;
    if (source[i + 1] === "*") {
      const close = source.indexOf("*/", i + 2);
      end = close === -1 ? source.length : close + 2;
    } else {
      end = i;
      while (end < source.length && !isLineEndCh(source[end])) end++;
    }
    if (!slashBefore) spans.push([i, end]);
    for (let k = i; k < end; k++) if (isLineEndCh(source[k])) { slashBefore = false; break; }
    i = end - 1;
  }
  return spans;
}

/**
 * A test for patterns that should not fire on a word in a comment: `has(re)`
 * (re global) is true when re matches the code with comments blanked, or the raw
 * text anywhere but inside a comment that counts (droppableComments). So the
 * old raw-text check stays a safety net (bypass checklist rows 16, 18), strings
 * are never masked (`el["innerHTML"] = x` still matches), and only a match that
 * sits wholly inside a real comment is dropped. If the lexer fails, the raw text
 * is read as before.
 */
export function codeMatcher(source) {
  let plain;
  try { ({ plain } = lexJs(source)); } catch { plain = null; }
  if (plain === null) return { has: (re) => { re.lastIndex = 0; return re.test(source); } };
  let spans = null;
  return {
    has(re) {
      re.lastIndex = 0;
      if (re.test(plain)) return true;
      spans ||= droppableComments(source, plain);
      let j = 0;
      for (const m of source.matchAll(re)) {
        const end = m.index + m[0].length;
        while (j < spans.length && spans[j][1] <= m.index) j++;
        if (!(j < spans.length && spans[j][0] <= m.index && end <= spans[j][1])) return true;
      }
      return false;
    },
  };
}
