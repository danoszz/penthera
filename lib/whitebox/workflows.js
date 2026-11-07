/**
 * GitHub Actions workflow checks: the CI files GitHub runs, at
 * <repo>/.github/workflows/*.yml.
 *
 * Three rules, from GitHub's own guidance on securing workflows (GitHub
 * Security Lab, "Keeping your GitHub Actions and workflows secure", parts 1
 * and 2) and the Actions security hardening docs:
 *   - gha-pwn-request: a pull_request_target, workflow_run, issue_comment or
 *     issues workflow checks out or fetches the pull request's code. That code
 *     then runs with the base repository's token and secrets.
 *   - gha-script-injection: text an outsider controls (a PR title, an issue
 *     body, a branch name) is expanded with ${{ }} inside a `run:` script or
 *     an actions/github-script `script:`, where it becomes code.
 *   - gha-unpinned-action: a third-party action referenced by a tag or
 *     branch, which its owner can move, instead of a full commit SHA.
 * A fourth, gha-workflow-unchecked, reports a workflow it can't read.
 *
 * The workflow is parsed as YAML (the vendored parser), so quotes, escapes,
 * block scalars, flow style, anchors and line endings mean what they mean to
 * GitHub. Expressions are compared lowercased, with ['x'] read as .x. Nothing
 * runs; each finding points to a line.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync } from "node:fs";
import { join } from "node:path";
import { LineCounter, isAlias, isMap, isScalar, isSeq, parseDocument, visit } from "../vendor/yaml/index.js";

export const WORKFLOW_RULES = {
  "gha-pwn-request": "config",
  "gha-script-injection": "injection",
  "gha-unpinned-action": "config",
  "gha-workflow-unchecked": "config",
};

// Triggers whose runs get the base repository's secrets while an outsider
// controls the event (a fork's PR, a comment, an issue).
const PRIVILEGED = new Set(["pull_request_target", "workflow_run", "issue_comment", "issues"]);
// A context path that is the PR's own code.
const HEAD_REF = /github\.event\.pull_request\.(head\.(sha|ref|repo)|merge_commit_sha)|github\.head_ref|github\.event\.workflow_run\.(head_sha|head_branch|head_commit|head_repository|pull_requests)/;
// A context path an outsider can write (GitHub's "untrusted input" list)...
const UNTRUSTED = /\b(github\.head_ref|github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|pages|head_commit|commits|workflow_run)\b[\w.[\]*]{0,80}?\.(?:title|body|head_ref|ref|label|message|name|email|default_branch|page_name|head_branch))\b/;
// ...unless it goes through a part maintainers own: the base branch, the
// repository, labels, milestones, people.
const MAINTAINER_OWNED = /\.(base|repository|labels|milestone|assignees?|sender|organization|requested_reviewers?|requested_teams?)\.|^github\.event\.label\./;
// A whole outsider-written object dumped as text: toJSON(github), toJSON(github.event.issue).
const DUMP = /\btojson\(\s*github(\.event(\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|head_commit|commits|workflow_run))?)?\s*\)/;
// More aliases than any real workflow uses: resolving each walks the document.
const MAX_ALIASES = 100;
const MAX_VISITS = 200_000;

/**
 * Every ${{ }} in a string, as GitHub reads it, in one forward pass: an
 * expression ends at the first }} outside a '...' string ('' inside a string
 * is a quote). One still open at the end of the text runs to the end, so the
 * rules check more, never less. This is the only place that finds expression
 * boundaries; every rule below uses it.
 */
export function exprSpans(text) {
  const spans = [];
  for (let at = text.indexOf("${{"); at !== -1; at = text.indexOf("${{", spans.at(-1).close + 2)) {
    let quoted = false;
    let j = at + 3;
    for (; j < text.length; j++) {
      if (text[j] === "'") quoted = !quoted;
      else if (!quoted && text[j] === "}" && text[j + 1] === "}") break;
    }
    if (j >= text.length) { spans.push({ start: at, close: text.length, open: true }); break; }
    spans.push({ start: at, close: j, open: false });
  }
  return spans;
}

/** Each ${{ }} in a string, normalized: lowercase, ['x'] as .x, no space around dots. */
export function expressions(text) {
  return exprSpans(text).map(({ start, close }) => ({ inner: normalize(text.slice(start + 3, close)), offset: start }));
}

/** One expression's text, normalized: lowercase, ['x'] as .x, no space around dots. */
function normalize(inner) {
  return inner.toLowerCase().replace(/\[\s*(['"])([\w-]*)\1\s*\]/g, ".$2").replace(/\s+/g, " ").replace(/ ?\. ?/g, ".");
}

/**
 * A GitHub expression as tokens: 'strings' (with '' inside), operators,
 * brackets, and everything else as words. One pass. Text inside a string is
 * never an operator, so format('a > {0}', x) has no comparison in it.
 */
export function tokenize(expr) {
  const out = [];
  for (let i = 0; i < expr.length;) {
    const c = expr[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { i++; continue; }
    if (c === "'") {
      let j = i + 1;
      for (; j < expr.length; j++) if (expr[j] === "'") { if (expr[j + 1] === "'") j++; else break; }
      out.push({ t: "str", v: expr.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    const two = expr.slice(i, i + 2);
    if (["==", "!=", "<=", ">=", "&&", "||"].includes(two)) { out.push({ t: "op", v: two }); i += 2; continue; }
    if ("<>!(),[]".includes(c)) { out.push({ t: "op", v: c }); i++; continue; }
    let j = i;
    while (j < expr.length && !" \t\n\r'<>!=&|(),[]".includes(expr[j])) j++;
    if (j === i) j++;
    out.push({ t: "word", v: expr.slice(i, j) });
    i = j;
  }
  return out;
}

/** The expression split at its top-level `op` (outside brackets and strings), or null if there is none. */
function splitTop(toks, op) {
  const parts = [[]];
  let depth = 0;
  for (const k of toks) {
    if (k.t === "op" && (k.v === "(" || k.v === "[")) depth++;
    if (k.t === "op" && (k.v === ")" || k.v === "]")) depth--;
    if (depth === 0 && k.t === "op" && k.v === op) parts.push([]);
    else parts.at(-1).push(k);
  }
  return parts;
}

/** Strip brackets that wrap the whole expression: ((a == b)) is a == b. One pass. */
function unwrap(toks) {
  const match = new Array(toks.length);
  const open = [];
  for (let i = 0; i < toks.length; i++) {
    if (toks[i].v === "(") open.push(i);
    else if (toks[i].v === ")" && open.length) match[open.pop()] = i;
  }
  let lo = 0;
  let hi = toks.length - 1;
  while (lo < hi && toks[lo].v === "(" && match[lo] === hi) { lo++; hi--; }
  return toks.slice(lo, hi + 1);
}

/**
 * True only when the whole expression is sure to yield true or false: a
 * top-level comparison, a negation, or contains/startsWith/endsWith(...),
 * with no top-level && or || (which can return an operand's own text).
 */
function yieldsBoolean(inner) {
  const toks = unwrap(tokenize(inner));
  if (!toks.length || splitTop(toks, "&&").length > 1 || splitTop(toks, "||").length > 1) return false;
  if (["==", "!=", "<=", ">=", "<", ">"].some((op) => splitTop(toks, op).length > 1)) return true;
  if (toks[0].v === "!") return true;
  const call = toks[0].t === "word" && ["contains", "startswith", "endswith"].includes(toks[0].v) && toks[1]?.v === "(";
  return call && unwrap(toks.slice(1)).length === toks.length - 3;
}

/**
 * True only when a job or step `if:` requires `wanted` on every path: it is
 * one of the conditions joined by top-level &&, with no top-level ||.
 */
export function requires(condition, wanted) {
  if (!condition) return false;
  // Text outside ${{ }} (a space, a newline from a block scalar, a second
  // expression) makes GitHub build a string from it, which is always true.
  let expr = condition;
  if (condition.includes("${{")) {
    const spans = exprSpans(condition);
    const only = spans.length === 1 && spans[0];
    if (!only || only.open || only.start !== 0 || only.close !== condition.length - 2) return false;
    expr = condition.slice(3, only.close);
  }
  const toks = unwrap(tokenize(expr.toLowerCase()));
  if (splitTop(toks, "||").length > 1) return false;
  return splitTop(toks, "&&").some((part) => wanted(unwrap(part).map((k) => k.v).join(" ")));
}
const SAME_REPO = (c) => c === "github.event.pull_request.head.repo.full_name == github.repository" || c === "github.repository == github.event.pull_request.head.repo.full_name";
const MERGED = (c) => c === "github.event.pull_request.merged" || c === "github.event.pull_request.merged == true" || c === "true == github.event.pull_request.merged";

/**
 * What one normalized expression carries into the text: untrusted text (the
 * path that brings it) and whether it names the PR's code. `env` maps env
 * names to what their own values carry, so ${{ env.T }} counts as its source.
 * Only an expression that surely yields true or false carries no text.
 */
function carries(inner, env) {
  let untrusted = null;
  let head = false;
  for (const [path] of inner.matchAll(/\bgithub(\.[\w*-]+)+/g)) {
    if (HEAD_REF.test(path)) head = true;
    if (!untrusted && UNTRUSTED.test(path) && !MAINTAINER_OWNED.test(path)) untrusted = path;
  }
  for (const [, name] of inner.matchAll(/\benv\.([\w-]+)/g)) {
    const from = env.get(name);
    if (!from) continue;
    if (from.head) head = true;
    if (!untrusted && from.untrusted) untrusted = `env.${name} (${from.untrusted})`;
  }
  if (!untrusted && DUMP.test(inner)) untrusted = inner.match(DUMP)[0];
  return { untrusted: untrusted && yieldsBoolean(inner) ? null : untrusted, head };
}

/** exprSpans by start offset, for lookups. */
const spanMap = (text) => new Map(exprSpans(text).map((sp) => [sp.start, sp]));

/**
 * Every offset of "pull/" in a text, found once, so each line can take its own
 * share without searching the rest of the script again.
 */
function pullOffsets(text) {
  const out = [];
  for (let at = text.indexOf("pull/"); at !== -1; at = text.indexOf("pull/", at + 5)) out.push(at);
  return out;
}

/**
 * True when the "pull/" at `at` names a PR's code as pull/<number or ${{ }}>/
 * head or /merge. Expression ends come from exprSpans over the whole text
 * (quote-aware, one pass), so a '}}' inside a string can't end one early and an
 * expression may run onto the next line. Several expressions in a row count as
 * one ref. Two readings, either one counting (check more, never less): closed
 * expressions end where exprSpans says, and plain text ends at the next / or
 * space (an unclosed or odd ${{ included).
 */
function pullAt(text, ends, at) {
  if (at > 0 && /\w/.test(text[at - 1])) return false;
  const suffix = (end) => /^\/(head|merge)(\W|$)/.test(text.slice(end, end + 7));
  let end = at + 5;
  for (let sp = ends.get(end); sp && !sp.open; sp = ends.get(end)) end = sp.close + 2;
  if (end > at + 5 && suffix(end)) return true;
  end = at + 5;
  while (end < text.length && text[end] !== "/" && !/\s/.test(text[end])) end++;
  return end > at + 5 && suffix(end);
}

/** pullAt for every "pull/" in a text: true when any names a PR's code. */
export function pullRef(text) {
  const ends = spanMap(text);
  return pullOffsets(text).some((at) => pullAt(text, ends, at));
}

/** Lowercase A-Z only, so the text keeps its length and every offset stays valid. */
const asciiLower = (s) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

const FETCHING_RE = /^(fetch|pull|clone|checkout|switch|reset)\b/;

/**
 * True when a line runs git fetch, pull, clone, checkout, switch or reset. A
 * superset of the old regex (R12): that regex, or the same read token by
 * token, which adds global options (git -C dir fetch, git -c k=v fetch, a
 * quoted -c value), a path to git (/usr/bin/git) and shell punctuation around
 * it (;git, $(git, (git, &&git).
 */
function gitFetches(l) {
  if (/\bgit\s+(fetch|pull|clone|checkout|switch|reset)\b/.test(l)) return true;
  // Not on $: a value like ./$DIR is one shell word, and $(git splits at (.
  const t = l.split(/[\s;&|()`<>]+/);
  for (let i = 0; i < t.length; i++) {
    // git by name or path, or a shell variable in command position ($GIT,
    // ${GIT}): a variable can hold git, so with a fetch subcommand after it, it counts.
    if (t[i].replace(/^.*\//, "") !== "git" && !/^\$\{?\w+\}?$/.test(t[i])) continue;
    let j = i + 1;
    while (j < t.length && t[j].startsWith("-")) {
      const takesValue = ["-c", "-C", "--git-dir", "--work-tree", "--namespace"].includes(t[j]);
      j++;
      if (takesValue && j < t.length) {
        // A quoted value can hold spaces: skip to the token that closes it, at
        // most 16 tokens on, so unclosed quotes can't make every git rescan.
        const q = /["']/.exec(t[j])?.[0];
        if (q && t[j].split(q).length % 2 === 0) {
          const stop = Math.min(t.length, j + 16);
          for (j++; j < stop && !t[j].includes(q); j++);
        }
        j++;
      }
    }
    if (FETCHING_RE.test(t[j] || "")) return true;
  }
  return false;
}

/**
 * The env-free part of the run-script fetch check, in one pass over the
 * script: `literal` when a git or gh line fetches a PR (gh pr checkout,
 * refs/pull/, pull/<ref>/head), and, across all git fetch-like lines, the
 * expressions on them (from the whole script's spans, each normalized once,
 * so one that starts on the line before counts) and the shell variables they
 * read ($SHA, ${SHA}), for the per-env head-ref check. A line ending in \
 * continues on the next.
 */
function literalFetch(script) {
  const raw = script.replace(/\\\r?\n/g, "  ");
  // A-Z only: toLowerCase() lengthens some characters (U+0130 becomes two
  // code units), which would put line offsets out of step with expression
  // offsets. Everything matched here is ASCII, so one coordinate system.
  const text = asciiLower(raw);
  const spans = exprSpans(raw);
  const ends = new Map(spans.map((sp) => [sp.start, sp]));
  const pulls = pullOffsets(text);
  const used = new Set();
  const vars = new Set();
  let k = 0;
  let s0 = 0;
  for (let from = 0; from <= text.length;) {
    let to = text.indexOf("\n", from);
    if (to === -1) to = text.length;
    const l = text.slice(from, to);
    while (k < pulls.length && pulls[k] < from) k++;
    while (s0 < spans.length && spans[s0].close < from) s0++;
    if (/\b(git|gh)\b/.test(l)) {
      let hit = /\bgh\s+pr\s+checkout\b/.test(l) || /refs\/pull\//.test(l);
      for (let j = k; !hit && j < pulls.length && pulls[j] < to; j++) hit = pullAt(text, ends, pulls[j]);
      if (hit) return { literal: true, exprs: [], vars: [] };
      if (gitFetches(l)) {
        for (let j = s0; j < spans.length && spans[j].start < to; j++) used.add(j);
        for (const m of raw.slice(from, to).matchAll(/\$\{?([A-Za-z_]\w*)/g)) vars.add(m[1].toLowerCase());
      }
    }
    from = to + 1;
  }
  const exprs = [...used].map((j) => normalize(raw.slice(spans[j].start + 3, spans[j].close)));
  return { literal: false, exprs, vars: [...vars] };
}

class Unreadable extends Error {}

/** Findings for one workflow's text; `file` is its path relative to the repo. */
export function checkWorkflow(text, file) {
  // YAML 1.2 breaks lines only at CR and LF; GitHub's parser also at these.
  if (/[\x85\u2028\u2029]/.test(text)) return [unchecked(file, "uses a Unicode line break (U+0085, U+2028 or U+2029), which parsers read differently")];
  const lineCounter = new LineCounter();
  // The core schema keeps `on` a string even under a %YAML 1.1 directive, as GitHub reads it.
  // Duplicate keys are checked below, only on the keys read: the parser's own check is quadratic.
  const doc = parseDocument(text, { lineCounter, uniqueKeys: false, prettyErrors: false, schema: "core" });
  if (doc.errors.length) return [unchecked(file, `can't be parsed as YAML (${doc.errors[0].code})`)];
  // Every alias resolved once, in one pass in document order (an alias means the
  // nearest anchor before it). The parser's own resolve() walks the whole
  // document on each call, which a padded workflow turns into billions of visits.
  const anchors = new Map();
  const targets = new Map();
  let aliases = 0;
  visit(doc, {
    Node: (_key, node) => {
      if (isAlias(node)) {
        if (++aliases > MAX_ALIASES) return visit.BREAK;
        targets.set(node, anchors.get(node.source));
      } else if (node.anchor) anchors.set(node.anchor, node);
    },
  });
  if (aliases > MAX_ALIASES) return [unchecked(file, `has more than ${MAX_ALIASES} YAML aliases`)];
  // Every node read, through aliases too, counts toward one budget.
  let visits = 0;
  const deref = (n) => {
    if (++visits > MAX_VISITS) throw new Unreadable("too many nodes, through aliases");
    return isAlias(n) ? targets.get(n) : n;
  };
  const get = (map, key) => {
    map = deref(map);
    if (!isMap(map)) return undefined;
    let found;
    for (const pair of map.items) {
      const k = deref(pair.key);
      if (!isScalar(k) || String(k.value) !== key) continue;
      // Two values for one key: which one counts is up to the parser, so don't guess.
      if (found !== undefined) throw new Unreadable(`a duplicate \`${key}:\` key`);
      found = deref(pair.value);
    }
    return found;
  };
  const items = (n) => { n = deref(n); return isSeq(n) ? n.items.map(deref) : []; };
  const entries = (n) => { n = deref(n); return isMap(n) ? n.items.map((p) => [deref(p.key), deref(p.value)]) : []; };
  const str = (n) => (isScalar(n) && n.value !== null && typeof n.value !== "object" ? String(n.value) : null);
  const lineOf = (n, offsetInValue = 0) => {
    const start = lineCounter.linePos(n.range[0]).line;
    if (!/^BLOCK/.test(n.type || "")) return start;
    return start + 1 + (String(n.value).slice(0, offsetInValue).match(/\n/g) || []).length;
  };
  /** The env scope a map's `env:` adds on top of its parent's. */
  /**
   * The env scope a map's `env:` adds on top of its parent's, as a chain (a
   * lookup walks at most workflow, job and step), never a copy: copying the
   * parent for every step was quadratic in the number of env entries.
   */
  const envScope = (node, parent) => {
    const own = new Map();
    for (const [k, v] of entries(get(node, "env"))) {
      const name = str(k)?.toLowerCase();
      const value = str(v);
      if (!name || value === null) continue;
      const c = { untrusted: null, head: false };
      for (const e of expressions(value)) {
        const r = carries(e.inner, parent);
        c.untrusted ||= r.untrusted;
        c.head ||= r.head;
      }
      own.set(name, c);
    }
    if (!own.size) return parent;
    return { get: (name) => own.get(name) ?? parent.get(name) };
  };
  const condition = (node) => str(get(node, "if"));

  try {
    const findings = [];
    const fetchCache = new Map();
    const on = get(doc.contents, "on");
    const triggers = str(on) !== null ? [str(on)] : isSeq(on) ? items(on).map(str) : entries(on).map(([k]) => str(k));
    const privileged = triggers.some((t) => t !== null && PRIVILEGED.has(t.trim()));
    const workflowEnv = envScope(doc.contents, new Map());
    // A job or a step that aliases reuse is evaluated once per job: its findings
    // are kept and reported again, never recomputed (2,500 reads became one).
    const jobCache = new Map();

    for (const [, job] of entries(get(doc.contents, "jobs"))) {
      if (jobCache.has(job)) { findings.push(...jobCache.get(job)); continue; }
      const jobStart = findings.length;
      const stepCache = new Map();
      const jobUses = get(job, "uses");
      if (str(jobUses) !== null) unpinned(jobUses);
      const jobEnv = envScope(job, workflowEnv);
      const jobSameRepo = requires(condition(job), SAME_REPO);
      const jobMerged = requires(condition(job), MERGED);
      for (const step of items(get(job, "steps"))) {
        if (stepCache.has(step)) { findings.push(...stepCache.get(step)); continue; }
        const stepStart = findings.length;
        const env = envScope(step, jobEnv);
        const usesNode = get(step, "uses");
        const uses = str(usesNode)?.trim().toLowerCase() ?? "";
        const withNode = get(step, "with");
        if (usesNode && str(usesNode) !== null) unpinned(usesNode);
        // Only a condition every path must pass counts: a fork's PR can't pass a
        // same-repository check, and after the merge the merge commit is the base's code.
        const sameRepo = jobSameRepo || requires(condition(step), SAME_REPO);
        const merged = jobMerged || requires(condition(step), MERGED);

        // gha-pwn-request: a checkout of the PR head, or a script that fetches it.
        if (privileged && uses.startsWith("actions/checkout@")) {
          for (const key of ["ref", "repository"]) {
            const node = get(withNode, key);
            const value = str(node);
            if (value === null) continue;
            const exprs = expressions(value);
            const heads = exprs.filter((e) => carries(e.inner, env).head);
            // After the merge, the merge commit is the base branch's own code.
            const onlyMerged = merged && heads.length > 0 && heads.every((e) => e.inner.trim() === "github.event.pull_request.merge_commit_sha");
            if ((key === "ref" && /refs\/pull\//i.test(value)) || (heads.length && !onlyMerged)) {
              pwn(node, `checks out the pull request's ${key === "ref" ? "code" : "fork"} (line ${lineOf(node)})`, sameRepo);
              break;
            }
          }
        }
        const run = get(step, "run");
        const script = str(run);
        if (privileged && script !== null) {
          // A line ending in \ continues on the next, as the shell reads it, and an
          // expression can span lines, so boundaries come from the whole script.
          // The literal checks don't depend on env, so a script that aliases
          // reuse across jobs is read once; only the head-ref check runs per env.
          if (!fetchCache.has(run)) fetchCache.set(run, literalFetch(script));
          const { literal, exprs, vars } = fetchCache.get(run);
          const fetches = literal || exprs.some((inner) => carries(inner, env).head) || vars.some((v) => env.get(v)?.head);
          if (fetches) pwn(run, `fetches the pull request's code in a script (line ${lineOf(run)})`, sameRepo);
        }

        // gha-script-injection: untrusted ${{ }} in a run: script or a github-script script:.
        if (script !== null) inject(run, script, "a `run:` script", env);
        if (uses.startsWith("actions/github-script@")) {
          const node = get(withNode, "script");
          if (str(node) !== null) inject(node, str(node), "an actions/github-script `script:`", env);
        }
        stepCache.set(step, findings.slice(stepStart));
      }
      jobCache.set(job, findings.slice(jobStart));
    }
    // An aliased step is read once per job that reuses it; report each line once,
    // keeping its most severe finding (an unguarded job outranks a guarded one).
    const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const best = new Map();
    for (const f of findings) {
      const key = `${f.templateId}:${f.line}`;
      if (!best.has(key) || RANK[f.severity] > RANK[best.get(key).severity]) best.set(key, f);
    }
    return [...best.values()];

    function pwn(node, what, guarded) {
      findings.push(finding("gha-pwn-request", guarded ? "medium" : "high", file, lineOf(node),
        "A privileged workflow runs the pull request's code",
        `\`${file}\` runs on a privileged trigger (pull_request_target, workflow_run, issue_comment or issues) and ${what}. Anything that code runs next (a build, a test, an install script) runs with this repository's token and secrets, so a fork can take them.${guarded ? " An `if:` limits it to pull requests from this repository, so forks can't reach it: medium, not high." : ""}`,
        "Use the plain pull_request trigger for jobs that build or test PR code. If you need a privileged trigger (to label or comment), don't check out the PR's code in it, or read it only as data and never run it.",
      ));
    }
    function inject(node, text, where, env) {
      for (const e of expressions(text)) {
        const { untrusted } = carries(e.inner, env);
        if (!untrusted) continue;
        const line = lineOf(node, e.offset);
        findings.push(finding("gha-script-injection", "high", file, line,
          "Untrusted text is expanded inside a workflow's script",
          `\`${file}\` line ${line} puts \`${untrusted}\` straight into ${where}. Whoever writes that text (a PR title, an issue body, a branch name) can end the string and run their own code in CI.`,
          "Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script, quoted, never ${{ env.TITLE }}. Then the shell treats it as data.",
        ));
        return;
      }
    }
    function unpinned(node) {
      const ref = str(node).trim();
      if (!ref || ref.startsWith("./") || ref.startsWith("docker://")) return;
      const at = ref.lastIndexOf("@");
      if (at < 0 || /^[0-9a-f]{40}$/.test(ref.slice(at + 1))) return;
      const owner = ref.split("/")[0].toLowerCase();
      const firstParty = owner === "actions" || owner === "github";
      const line = lineOf(node);
      findings.push(finding("gha-unpinned-action", firstParty ? "low" : "medium", file, line,
        `Action \`${ref}\` is pinned to a tag, not a commit`,
        `\`${file}\` line ${line} uses \`${ref}\`. A tag or branch can be moved to new code by whoever controls that action${firstParty ? "" : ", a third party"}, and the next run uses it with this workflow's permissions.`,
        "Pin the action to its full commit SHA and keep the tag as a comment (uses: owner/action@<40-char sha> # v1.2.3). Dependabot can keep the SHA up to date.",
      ));
    }
  } catch (e) {
    if (e instanceof Unreadable) return [unchecked(file, `can't be checked (${e.message})`)];
    throw e;
  }
}

function unchecked(file, why) {
  return finding("gha-workflow-unchecked", "high", file, 1,
    "A workflow Penthera couldn't check",
    `\`${file}\` ${why}. Penthera reports it instead of passing it unread.`,
    "Read the workflow by hand. If GitHub runs it, simplify it so it parses as plain YAML.",
  );
}

function finding(rule, severity, file, line, title, description, remediation) {
  return {
    severity, title, description, remediation,
    url: file, file, line,
    templateId: rule,
    category: WORKFLOW_RULES[rule],
    source: "static-analysis",
    confidence: rule === "gha-unpinned-action" ? "confirmed" : "likely",
  };
}

// A real workflow is a few KB. A larger one is reported, not skipped: padding
// a workflow past the cap must not hide it.
export const MAX_WORKFLOW_BYTES = 256 * 1024;
const TOO_LARGE = Symbol("too large");

/** A real directory, not a symlink a scanned repo planted. */
function isRealDir(path) {
  try { return lstatSync(path).isDirectory(); } catch { return false; }
}

/**
 * Read a workflow only if it's a regular file under the size cap; TOO_LARGE
 * when it's over. The repo is
 * untrusted: a symlink can point at /dev/zero or outside the repo, and a FIFO
 * would block the read. O_NOFOLLOW refuses a link swapped in after the check,
 * O_NONBLOCK stops a FIFO from blocking open, and fstat checks what was opened.
 */
function readWorkflow(path) {
  let fd;
  try {
    if (!lstatSync(path).isFile()) return null;
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    if (st.size > MAX_WORKFLOW_BYTES) return TOO_LARGE;
    const buf = Buffer.alloc(st.size);
    const n = readSync(fd, buf, 0, st.size, 0);
    return buf.subarray(0, n).toString("utf-8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Every workflow GitHub would run for this repo. */
export function scanWorkflows(repoPath) {
  const github = join(repoPath, ".github");
  const dir = join(github, "workflows");
  if (!isRealDir(github) || !isRealDir(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    const file = `.github/workflows/${name}`;
    const text = readWorkflow(join(dir, name));
    if (text === TOO_LARGE) {
      out.push(unchecked(file, `is over ${MAX_WORKFLOW_BYTES / 1024} KB, far larger than a real workflow`));
      continue;
    }
    if (text === null) continue;
    out.push(...checkWorkflow(text, file));
  }
  return out;
}
