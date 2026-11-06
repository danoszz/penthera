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

const SP = 32, NL = 10, CR = 13, TAB = 9;
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
export function lexJs(src, state = null) {
  const n = src.length;
  const plain = new Uint16Array(n);
  for (let k = 0; k < n; k++) plain[k] = src.charCodeAt(k);
  const s = plain.slice();
  const code = plain.slice();
  const expr = plain.slice();
  const sp = (c) => (c === NL || c === CR ? c : SP);
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
    while (i < n && s[i] !== NL) { blank(i); i++; }
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
      if (d === q || d === NL) break;
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
      while (i < n && s[i] !== NL) { blank(i); i++; }
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
        // An unterminated string ends at the line break (it is a syntax error anyway).
        if (d === NL) break;
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
      let j = i + 1;
      let inClass = false;
      let ok = false;
      for (; j < n; j++) {
        const d = s[j];
        if (d === NL) break;
        if (d === BS) { j++; continue; }
        if (inClass) { if (d === RSQ) inClass = false; continue; }
        if (d === LSQ) inClass = true;
        else if (d === SL) { ok = true; break; }
      }
      if (ok) {
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
  return { code: toText(code), plain: toText(plain), expr: toText(expr), state: next };
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
