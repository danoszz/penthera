/**
 * String helpers that run in linear time on any input. The scanners read text
 * an attacker writes; a regex such as /\/+$/ or /\?.*$/ restarts at every
 * candidate position and can take quadratic time on a crafted string
 * ("////…x", "????…"). These do the same jobs with single scans.
 * eslint-plugin-regexp (no-super-linear-backtracking, no-super-linear-move)
 * keeps new regexes linear; see eslint.config.js.
 */

/** `s` without any run of the characters in `chars` at its end (like s.replace(/[chars]+$/, "")). */
export function trimEndChars(s, chars) {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return s.slice(0, end);
}

/** `s` without any run of the characters in `chars` at its start (like s.replace(/^[chars]+/, "")). */
export function trimStartChars(s, chars) {
  let start = 0;
  while (start < s.length && chars.includes(s[start])) start++;
  return s.slice(start);
}

/** `s` up to the first of any character in `chars` (like s.replace(/[chars].*$/s, "")). */
export function cutAtFirst(s, chars) {
  let i = 0;
  while (i < s.length && !chars.includes(s[i])) i++;
  return s.slice(0, i);
}

/**
 * For `a as b` lists (imports, exports): the name before ` as ` (`which:
 * "first"`) or after it (`"last"`). Same as s.trim().split(/\s+as\s+/)[0 or
 * last] on well-formed names, in one scan.
 */
export function asName(s, which = "last") {
  const words = s.trim().split(/\s+/);
  const at = words.indexOf("as");
  if (at <= 0 || at === words.length - 1) return s.trim();
  return which === "first" ? words.slice(0, at).join(" ") : words.slice(at + 1).join(" ");
}

/**
 * A function from a character index to its 1-based line in `text`: line starts
 * computed once, then a binary search. Counting lines from the start for each
 * hit (text.slice(0, i).split("\n").length) is quadratic in the hits.
 */
export function lineIndex(text) {
  const starts = [0];
  for (let k = text.indexOf("\n"); k !== -1; k = text.indexOf("\n", k + 1)) starts.push(k + 1);
  return (i) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= i) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
}

const IDENT = /(?<![\w$.])[A-Za-z_$][\w$]*/g;

/**
 * Does `text` use one of `names` as a whole identifier, not as a property
 * after a dot? The same test as /(?<![\w$.])(?:a|b|…)(?![\w$])/ for names
 * that are plain identifiers (the only kind the callers collect), in one pass
 * over the identifiers with a Set lookup each. An alternation of the names
 * tried every name at every position (50,000 names, 50,000 tries per
 * character), and one RegExp per name was worse. `names` is read live.
 */
export function mentions(text, names) {
  if (!names.size) return false;
  const re = new RegExp(IDENT); // its own lastIndex
  for (let m = re.exec(text); m; m = re.exec(text)) if (names.has(m[0])) return true;
  return false;
}

/**
 * A glob matcher that runs in O(pattern x subject) time. Globs turned into
 * regexes (`*` as `.*`) backtrack on a pattern such as `*a*a*a…b`: the time
 * grows with the subject's length to the power of the number of stars.
 * `tokens` is the glob, parsed by the caller, as a list of:
 *   { lit: "c" }        one literal character
 *   { star: "any" }     .*      any characters except a line break
 *   { star: "seg" }     [^/]*   any characters except "/"
 *   { one: "seg" }      [^/]    one character except "/"
 *   { plus: "seg" }     [^/]+
 *   { dirs: true }      (?:.*\/)?  nothing, or anything that ends in "/"
 *   { maybe: { lit } }  c?      the character or nothing
 * The whole subject must match (as ^…$). It is the same language as the
 * regex built from the same parts, matched with a Thompson simulation.
 */
export function globMatcher(tokens, { ignoreCase = false } = {}) {
  const fold = (s) => (ignoreCase ? s.toLowerCase() : s);
  const anyCh = (c) => c !== "\n" && c !== "\r" && c !== "\u2028" && c !== "\u2029";
  const segCh = (c) => c !== "/"; // [^/] takes a line break, "." does not
  // Nodes: { test, next } consume one character; { split: [a, b] } is a choice; { end }.
  const nodes = [];
  const node = (n) => (nodes.push(n), nodes.length - 1);
  // Built back to front, so each part knows where it goes next.
  let next = node({ end: true });
  for (let k = tokens.length - 1; k >= 0; k--) {
    const t = tokens[k];
    if (t.lit !== undefined) { const c = fold(t.lit); next = node({ test: (x) => x === c, next }); }
    else if (t.maybe) { const c = fold(t.maybe.lit); next = node({ split: [node({ test: (x) => x === c, next }), next] }); }
    else if (t.one) next = node({ test: segCh, next });
    else if (t.star || t.plus) {
      const test = t.star === "any" ? anyCh : segCh;
      const loop = node({ split: null });
      const ch = node({ test, next: loop });
      nodes[loop].split = [ch, next];
      next = t.plus ? node({ test, next: loop }) : loop;
    } else if (t.dirs) {
      // (?:.*/)?: skip it, or any characters, then "/".
      const slash = node({ test: (x) => x === "/", next });
      const loop = node({ split: null });
      const ch = node({ test: anyCh, next: loop });
      nodes[loop].split = [ch, slash];
      next = node({ split: [loop, next] });
    }
  }
  const start = next;
  const add = (set, seen, i) => {
    if (seen[i]) return;
    seen[i] = 1;
    const n = nodes[i];
    if (n.split) { add(set, seen, n.split[0]); add(set, seen, n.split[1]); } else set.push(i);
  };
  return {
    test(subject) {
      const s = fold(String(subject));
      let cur = [];
      add(cur, new Uint8Array(nodes.length), start);
      for (let p = 0; p < s.length && cur.length; p++) {
        const c = s[p];
        const nxt = [];
        const seen = new Uint8Array(nodes.length);
        for (const i of cur) { const n = nodes[i]; if (n.test && n.test(c)) add(nxt, seen, n.next); }
        cur = nxt;
      }
      return cur.some((i) => nodes[i].end);
    },
  };
}

/**
 * Lines as Python's str.splitlines() makes them: at \n, \r, \r\n, \v, \f,
 * \x1c-\x1e, \x85, U+2028 and U+2029. pip reads requirements files this way,
 * and importlib RECORD and installed-files.txt; a parser that split on \n
 * alone read `requests==2.31.0\rlitellm==1.107.0` as one line and missed the
 * second pin (Red Team E23, 2.3.2).
 */
export function pythonLines(text) {
  return String(text).split(/\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/);
}

/**
 * The text with each line break the language accepts, other than \n and the
 * \r of \r\n, turned into \n, length unchanged, so code split on \n and lines
 * counted on \n see the lines the interpreter sees. `lang`: "python" (a lone
 * \r, as Python's universal newlines read it), "js" (also U+2028 and U+2029),
 * "email" (a lone \r, as the email parser that reads METADATA does).
 */
export function lfLineBreaks(text, lang) {
  const s = String(text);
  return lang === "js" ? s.replace(/\r(?!\n)|[\u2028\u2029]/g, "\n") : s.replace(/\r(?!\n)/g, "\n");
}
