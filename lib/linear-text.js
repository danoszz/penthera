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
