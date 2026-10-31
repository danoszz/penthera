/**
 * /research: one page with every study, result, case study and post, newest
 * first, built from the repo at build time. Nothing on it is typed twice:
 *
 *   studies       docs/research/prereg/*.md: the title, the Status row (or
 *                 line) and the date written. A status that says "not
 *                 registered" or "draft" is always Draft, whatever else it says.
 *   results       the result files the studies point at (RESULTS below). Each
 *                 headline names the sentences in its source that back it;
 *                 the build fails when a sentence is not there, so a headline
 *                 can only restate what the repo already publishes.
 *   case studies  docs/research/*.md notes (CASE_STUDIES below), same check.
 *   posts         the approved blog posts (site/blog.mjs).
 *   featured      the public benchmark, from bench/public/published.json, with
 *                 each rank in the interval wording of site/benchmarks.mjs.
 *
 *   /research       the page
 *   /research.md    the same list as Markdown, for agents
 *
 * The whole list is in the HTML. One small script (site/research.js) adds the
 * search, the type and status filters and "Show all": it hides entries only
 * after it runs, so crawlers, agents and readers without JavaScript see every
 * entry. No tracking, no storage; a filtered view lives in the URL query.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ldScript, siteFooter } from "./frame.mjs";
import { benchmarkViews, fieldTools, n2, ord, tiedPhrase } from "./benchmarks.mjs";

const REPO = "https://github.com/danoszz/penthera";
const BLOB = `${REPO}/blob/main`;
const AUTHOR = { "@type": "Person", name: "Daan van der Zwaag", url: "https://daanvanderzwaag.com" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const shortDate = (d) => (d ? new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "Undated");
const longDate = (d) => new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

/** The page's one sentence of purpose. */
export const PURPOSE = "Rules decide. Every study is registered before it runs, and every change is dated, so you can repeat it and challenge it.";

/** The entry types and study statuses, in the words the page uses. */
export const TYPES = ["Study", "Result", "Case study", "Post"];
export const STATUSES = ["Registered", "Running", "Result", "Draft"];

/** The filter chips: label, the entry type it matches, its URL value. */
export const FILTERS = [
  { label: "Studies", type: "Study", key: "study" },
  { label: "Results", type: "Result", key: "result" },
  { label: "Case studies", type: "Case study", key: "case-study" },
  { label: "Posts", type: "Post", key: "post" },
];
/**
 * Whether an entry is in a filter. "Results" holds every entry with a result:
 * a result published on its own, and a study whose status is Result.
 */
export const inFilter = (e, f) => e.type === f.type || (f.type === "Result" && e.status === "Result");

/** How many entries the page shows before "Show all" (the script applies it). */
export const FIRST = 6;

/**
 * A study's status from its Status text. Draft wins: a study that says it is
 * not registered is never shown as Registered or Result.
 */
export function studyStatus(text, hasResult = false) {
  const s = String(text || "");
  if (!s.trim() || /not registered|\bdraft\b/i.test(s)) return "Draft";
  if (hasResult) return "Result";
  if (/\brunning\b|\bin progress\b/i.test(s)) return "Running";
  if (/\bregistered\b|\bcompleted\b/i.test(s)) return "Registered";
  return "Draft";
}

/** Plain text of a Markdown fragment: no emphasis, code ticks or links. */
const plain = (s) => s.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/\*\*|__|`/g, "").replace(/\s+/g, " ").trim();
/** Whitespace-normalized text, for matching the sentences a headline rests on. */
const flat = (s) => s.replace(/\s+/g, " ");

/** The date a file last changed in git (YYYY-MM-DD), or null. */
function lastChanged(root, file) {
  try {
    return execFileSync("git", ["log", "-1", "--format=%cs", "--", file], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    return null;
  }
}

/** One pre-registration: id, title, status text, date written. */
export function parsePrereg(md, file) {
  const src = md.replace(/\r\n/g, "\n");
  const id = /(E\d+[a-z]?)-/.exec(file.split("/").pop())?.[1];
  if (!id) throw new Error(`${file}: the file name does not start with an experiment id (E<n>-)`);
  const h1 = /^# (.+)$/m.exec(src)?.[1];
  if (!h1) throw new Error(`${file}: no # title`);
  const title = h1.replace(/\s*\((?:pre-registration|amendment)[^)]*\)\s*$/i, "").trim();
  const row = (name) => new RegExp(`^\\|\\s*${name}\\s*\\|\\s*(.+?)\\s*\\|\\s*$`, "mi").exec(src)?.[1];
  const status = row("Status") ?? /^Status:\s*([\s\S]+?)(?:\n\n|$)/m.exec(src)?.[1] ?? "";
  const written = /(\d{4}-\d{2}-\d{2})/.exec(row("Date written") || "")?.[1] || null;
  return { id, title, status: plain(status), written };
}

/**
 * What each study asks, in one or two lines. A study not listed here is
 * summarized by its title alone, so a new pre-registration still appears.
 */
const SUMMARIES = {
  E1: "How accurate is Penthera's static analysis on real web apps and agent setups its authors did not write? Precision and recall per category, each with a 95% interval.",
  E8: "When an AI coding agent gets benign tasks, some of which cannot be solved, do an AGENTS.md block and protected judges change how often it tampers with the checks?",
  E10: "What share of Penthera's findings are correct on deliberately vulnerable apps, and what share of their documented bugs does it find?",
  E11: "One public benchmark per capability, with answer keys we had no hand in: secrets on Samsung CredData, code sinks on SecBench.js, malicious packages on DataDog's dataset.",
  E11b: "Tune on a dev half, then score a sealed test half once. Only the test half's numbers are published as the after.",
  E14: "Does one report from Penthera and the free tools find more than Penthera alone, without losing more than a fixed margin of precision? The answer sets the default for --giants.",
  E15: "Can a static, rule-based check find instructions planted in skills, rule files and MCP tool descriptions, without flagging normal ones?",
  E17: "Does Penthera make no network calls at run time, give the same result twice, and the same result with the network blocked?",
  E20: "How do the most visited sites, and recent startups, score on the live check's passive front-door checks? Aggregates only.",
  E21: "Would Penthera's free, offline rules flag known server-side bugs in open-source code before they were exploited? Vulnerable and fixed commits, scanned locally. No AI model is run.",
};

/**
 * Studies with a result: the headline, where the result is, and the sentences
 * in that file the headline rests on (checked at build time). E11b's headline
 * is built from published.json instead.
 */
const RESULTS = {
  E11: {
    headline: "E11: Penthera 1.9.0 missed all five registered targets on the three public datasets",
    href: "bench/public/RESULTS.md#summary",
    evidence: ["| H1 | Secret precision above 0.70 |", "Not supported (npm fails; PyPI alone would pass)", "Not supported (PyPI's upper bound is 0.12; npm alone would pass)"],
  },
  E14: {
    headline: "E14: merging the free tools found more secrets but cost more than 0.02 precision, so --giants keeps Penthera-first",
    href: "bench/public/RESULTS.md#e14-step-2-the-sealed-test-half-scored-once-2026-10-28",
    evidence: ["H1 holds; H2 fails, with the whole interval below −0.02.", "`--giants` keeps Penthera-first as its default."],
  },
  E17: {
    headline: "E17: the registered run on macOS and Ubuntu made no outside connection and gave the same result, for every command in scope",
    summary: "URL scans are covered only with --offline: without it, a URL scan downloads the Retire.js database. git runs outside the guard.",
    href: "bench/offline/RESULTS.md#registered-run-28-oct-2026",
    evidence: ["H1 holds for every command in scope", "on either platform", "URL scans are covered only with `--offline`.", "`git` is not guarded.", "no network at run time, and the same result every time, also with the network unplugged. Tested on macOS and Ubuntu (E17)."],
    // A later run of the same study: a dated note on the study, not an entry of its own.
    notes: [
      {
        date: "2026-10-29", text: "Re-run 29 Oct with the exact-path normaliser: verdict unchanged.",
        href: "bench/offline/RESULTS.md#deviation-the-normaliser-29-oct-2026",
        evidence: ["The verdict did not change.", "the pattern removed three fields that are analysis output", "Ubuntu (GitHub Actions, Node 22", "the same result."],
      },
    ],
  },
};

/**
 * Results published on their own date, apart from a study (a run of a study
 * goes in its RESULTS notes instead, so each study appears once).
 * @type {{ date: string, study: string, headline: string, summary: string, href: string, evidence: string[] }[]}
 */
const RESULT_ENTRIES = [];

/** Case studies in docs/research/: dated, with the sentences each headline rests on. */
const CASE_STUDIES = [
  {
    file: "docs/research/case-study-php-2026-10.md", date: "2026-10-21",
    headline: "PHP's 21 Oct flaws: Penthera checks the version a site shows, and says when it cannot tell",
    summary: "Released in 1.8.0. A hidden version is never reported as safe, and the fixed versions match the ones in OpenAI's own checker.",
    evidence: ["When Penthera sees PHP but no version, it says it cannot tell.", "It never reports the site as safe.", "Its fixed versions match the ones Penthera copied from php-src", "Released in 1.8.0"],
  },
  {
    file: "docs/research/agent-incidents-2026.md", date: "2026-10-20",
    headline: "2026 agent incidents: six gaps for Penthera, from verifier integrity to agent sandboxes",
    summary: "Agents under evaluation reached real systems they were never meant to touch. Each lesson ends in an action, and the draft study E8 tests one of them.",
    evidence: ["Each answer ends in an action we can take.", "Verifier integrity for model-written fixes.", "Agent sandbox audit.", "reached real systems they were never meant to touch"],
  },
  {
    file: "docs/research/emudhra-weak-keys-2026-10.md", date: "2026-10-22",
    headline: "eMudhra's broken CA keys show in the public key, and the TLS check now looks for them",
    summary: "Each private key was an integer below 256, so a passive handshake is enough to find it. A match is proof, so the finding is confirmed.",
    evidence: ["The check it proposes ships in `lib/tls.js`.", "every private key is an integer below 256", "A match is proof, so the finding is `confirmed`.", "**Passive.**"],
  },
  {
    file: "docs/research/gitlab-version-exposure-2026-10.md", date: "2026-10-22",
    headline: "GitLab's critical patch: a passive scan cannot read a self-managed GitLab's version",
    summary: "Asset fingerprinting is ruled out. The note proposes a rule that reads the version from the repository instead; no rule shipped.",
    evidence: ["a passive black-box scan does not get a version, by design", "Proposes a repo-evidence rule; no rule shipped.", "## Why asset fingerprinting is out"],
  },
];

/** Check that every sentence a headline rests on is in its source file. */
function backed(root, file, evidence) {
  const path = join(root, file.split("#")[0]);
  if (!existsSync(path)) throw new Error(`research: ${file} does not exist`);
  const text = flat(readFileSync(path, "utf8"));
  for (const e of evidence) if (!text.includes(flat(e))) throw new Error(`research: ${file.split("#")[0]} does not say "${e}"`);
}

/** "2nd of 10" plus the interval wording when the rank interval spans more than one place. */
export const rankText = (v) => `${ord(v.us.rank)} of ${v.b.of}${tiedPhrase(v.iv)}`;

/** Short names for the four benchmarks, for headlines. */
const SHORT = { secrets: "secrets", npm: "npm malware", pypi: "PyPI malware", library: "JS injection" };

/** "a", "a and b", "a, b and c". */
const andList = (xs) => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);

/**
 * The E11b headline, from published.json, short: each rank as its interval
 * ("tied 1st to 3rd", the words of tiedPhrase) or, when the interval is one
 * place, the rank itself. Benchmarks with the same wording share it, and a
 * shared last word is said once: "tied 1st to 3rd on npm and PyPI malware".
 * The full "2nd of 10" ranks are on the featured card and /benchmarks.
 */
export function e11bHeadline(pub) {
  const groups = [];
  for (const v of benchmarkViews(pub)) {
    const rank = tiedPhrase(v.iv).replace(/^, /, "") || ord(v.us.rank);
    const name = SHORT[v.key] || v.c.label.toLowerCase();
    const last = groups.at(-1);
    if (last?.rank === rank) last.names.push(name);
    else groups.push({ rank, names: [name] });
  }
  const said = groups.map(({ rank, names }) => {
    const tail = names[0].split(" ").at(-1);
    const shared = names.length > 1 && names.every((n) => n.includes(" ") && n.endsWith(` ${tail}`));
    return `${rank} on ${shared ? `${andList(names.map((n) => n.slice(0, -tail.length - 1)))} ${tail}` : andList(names)}`;
  });
  return `E11b: ${said.join(", ")}`;
}

/**
 * Every entry, newest first.
 * @param {{ root: string, pub?: object|null, posts?: object[], preregDir?: string }} o
 *   posts: the approved posts only (drafts never reach the site)
 * @returns {{ date: string|null, type: string, status?: string, id?: string, title: string, headline?: string, summary: string, href: string, source?: string }[]}
 */
export function researchEntries({ root, pub = null, posts = [], preregDir = join(root, "docs", "research", "prereg") }) {
  const out = [];
  const files = existsSync(preregDir) ? readdirSync(preregDir).filter((f) => /^E\d+[a-z]?-.+\.md$/.test(f)).sort() : [];
  for (const f of files) {
    const rel = `docs/research/prereg/${f}`;
    const p = parsePrereg(readFileSync(join(preregDir, f), "utf8"), rel);
    let r = RESULTS[p.id];
    if (p.id === "E11b" && pub?.benchmarks) r = { headline: e11bHeadline(pub), href: "/benchmarks" };
    if (r?.evidence) backed(root, r.href, r.evidence);
    for (const n of r?.notes || []) backed(root, n.href, n.evidence);
    const status = studyStatus(p.status, Boolean(r));
    out.push({
      date: p.written || lastChanged(root, rel),
      type: "Study",
      status,
      id: p.id,
      title: p.title,
      // A headline only for a result; a draft never shows one.
      ...(status === "Result" ? {
        headline: r.headline,
        result: r.href.startsWith("/") ? r.href : `${BLOB}/${r.href}`,
        ...(r.notes ? { notes: r.notes.map((n) => ({ date: n.date, text: n.text, href: `${BLOB}/${n.href}` })) } : {}),
      } : {}),
      summary: (status === "Result" && r.summary) || SUMMARIES[p.id] || p.title,
      href: `${BLOB}/${rel}`,
      source: rel,
    });
  }
  for (const r of RESULT_ENTRIES) {
    backed(root, r.href, r.evidence);
    out.push({ date: r.date, type: "Result", id: r.study, title: r.headline, headline: r.headline, summary: r.summary, href: `${BLOB}/${r.href}`, source: r.href.split("#")[0] });
  }
  for (const c of CASE_STUDIES) {
    backed(root, c.file, c.evidence);
    out.push({ date: c.date, type: "Case study", title: c.headline, headline: c.headline, summary: c.summary, href: `${BLOB}/${c.file}`, source: c.file });
  }
  for (const p of posts) {
    if (!p.approved) continue;
    out.push({ date: p.date, type: "Post", title: p.title, headline: p.title, summary: p.description, href: `/blog/${p.slug}` });
  }
  for (const e of out) if (e.date && !DAY.test(e.date)) throw new Error(`research: ${e.title} has a malformed date ${e.date}`);
  // Newest first; undated last; on the same day results, then studies, case studies and posts, then by title.
  const rank = (t) => ["Result", "Study", "Case study", "Post"].indexOf(t);
  return out.sort((a, z) => (z.date || "").localeCompare(a.date || "") || rank(a.type) - rank(z.type) || a.title.localeCompare(z.title));
}

// ── HTML ────────────────────────────────────────────────────────────────────

const statusClass = (s) => `rs-status is-${s.toLowerCase()}`;

/** The featured card: the public benchmark, each rank with its interval. */
export function featured(pub) {
  if (!pub?.benchmarks) return "";
  const views = benchmarkViews(pub);
  const rows = views.map((v) => `          <li class="rs-rank-row">
            <p class="rs-rank-k">${esc(v.c.label)} <span>${esc(v.c.dataset.short)}</span></p>
            <p class="rs-rank"><span class="rs-place">${ord(v.us.rank)}</span> of ${v.b.of}${esc(tiedPhrase(v.iv))}</p>
            <p class="rs-rank-v">${esc(v.c.scoreName)} ${n2(v.us.score)}</p>
          </li>`).join("\n");
  return `    <section class="rs-feature band band-blue" aria-labelledby="rs-feature-title">
      <p class="rs-feature-k"><span>Featured</span><span>Public benchmark</span><time datetime="${pub.date}">${longDate(pub.date)}</time></p>
      <h2 id="rs-feature-title"><a href="/benchmarks">Penthera and ${fieldTools(pub)} free security tools, on four public benchmarks</a></h2>
      <p class="rs-feature-lede">Four public datasets other people built, each split in half before any tuning, and scored once on the sealed half. Penthera's rank on each:</p>
      <ol class="rs-ranks">
${rows}
      </ol>
      <p class="rs-feature-note">Where a range follows the rank, Penthera's rank fell in that range in 95% of bootstrap redraws.</p>
      <p class="rs-feature-cta"><a class="btn btn-steel" href="/benchmarks">Every tool, interval and limit</a></p>
    </section>`;
}

/** The page's structured data, the same on /research however it is drawn. */
export const researchLd = (entries, { url, origin, description }) => ldScript([
    {
      "@type": "CollectionPage", "@id": `${url}#page`, url, name: "Penthera research", description, author: AUTHOR,
      isPartOf: { "@type": "WebSite", "@id": `${origin}/#website`, url: `${origin}/`, name: "Penthera" },
      mainEntity: {
        "@type": "ItemList", itemListOrder: "https://schema.org/ItemListOrderDescending", numberOfItems: entries.length,
        itemListElement: entries.map((e, i) => ({ "@type": "ListItem", position: i + 1, name: e.headline || e.title, url: e.href.startsWith("/") ? `${origin}${e.href}` : e.href })),
      },
    },
    { "@type": "BreadcrumbList", itemListElement: [["Penthera", "/"], ["Research", "/research"]].map(([n, p], i) => ({ "@type": "ListItem", position: i + 1, name: n, item: `${origin}${p}` })) },
  ]);

/** Escape, and keep a flag such as --giants on one line. */
const text = (s) => esc(s).replace(/(--[a-z][\w-]*)/g, '<span class="nowrap">$1</span>');

function item(e) {
  const tags = `<span class="rs-type">${esc(e.type)}${e.id ? ` · <span class="rs-id">${esc(e.id)}</span>` : ""}</span>${e.status ? `<span class="${statusClass(e.status)}">${esc(e.status)}</span>` : ""}`;
  const head = e.headline || e.title;
  const more = e.type === "Study" && e.result ? ` <a class="rs-more" href="${esc(e.result)}">Read the result</a>` : "";
  const sub = e.type === "Study" && e.headline ? `<p class="rs-sub">${esc(e.title)}</p>` : "";
  const notes = (e.notes || []).map((n) => `<p class="rs-note">${esc(n.text)} <a class="rs-more" href="${esc(n.href)}">Read the re-run</a></p>`).join("");
  const filters = FILTERS.filter((f) => inFilter(e, f)).map((f) => f.key).join(" ");
  return `      <li class="rs-item" data-type="${esc(e.type)}" data-filters="${filters}"${e.status ? ` data-status="${esc(e.status)}"` : ""}>
        <p class="rs-date">${e.date ? `<time datetime="${e.date}">${shortDate(e.date)}</time>` : "Undated"}</p>
        <div class="rs-body">
          <p class="rs-tags">${tags}</p>
          <h3><a href="${esc(e.href)}">${text(head)}</a></h3>
          ${sub}<p class="rs-sum">${text(e.summary)}${more}</p>${notes}
        </div>
      </li>`;
}

/** /research as HTML. */
/**
 * The search, the filter chips and the result count. Marked data-js, so the
 * stylesheet hides them until a script runs; the list itself never depends on
 * them.
 */
function tools(entries) {
  const chip = (attr, value, label, n, on = false) => `<button type="button" class="rs-chip" ${attr}="${value}" aria-pressed="${on}">${esc(label)} <span class="rs-n">${n}</span></button>`;
  const types = FILTERS.map((f) => [f, entries.filter((e) => inFilter(e, f)).length]).filter(([, n]) => n);
  const studies = entries.filter((e) => e.type === "Study");
  const statuses = STATUSES.map((s) => [s, studies.filter((e) => e.status === s).length]).filter(([, n]) => n);
  return `    <div class="rs-tools" id="rs-tools" data-js data-first="${FIRST}">
      <form class="rs-search" role="search" action="/research" method="get">
        <label for="rs-q">Search titles, summaries and study IDs</label>
        <div class="rs-field">
          <input id="rs-q" name="q" type="search" autocomplete="off" spellcheck="false" placeholder="E17, secrets, malware" aria-describedby="rs-count">
          <button type="button" class="rs-clear" hidden>Clear</button>
        </div>
      </form>
      <div class="rs-chips" role="group" aria-label="Filter by type">
        ${[chip("data-filter", "", "All", entries.length, true), ...types.map(([f, n]) => chip("data-filter", f.key, f.label, n))].join("\n        ")}
      </div>
      <div class="rs-chips rs-chips-status" role="group" aria-label="Filter studies by status" hidden>
        <span class="rs-chips-k" aria-hidden="true">Status</span>
        ${[chip("data-status", "", "Any status", studies.length, true), ...statuses.map(([s, n]) => chip("data-status", s.toLowerCase(), s, n))].join("\n        ")}
      </div>
      <p class="rs-count" id="rs-count" aria-live="polite"></p>
    </div>`;
}

export function researchHtml(entries, { origin, pub = null, styles = "/styles.css", theme = "/theme.js", script = "/research.js", foot = siteFooter() }) {
  const url = `${origin}/research`;
  const count = (t) => entries.filter((e) => e.type === t).length;
  const tally = TYPES.map((t) => [t, count(t)]).filter(([, n]) => n).map(([t, n]) => `${n} ${({ Study: ["study", "studies"], Result: ["result", "results"], "Case study": ["case study", "case studies"], Post: ["post", "posts"] })[t][n === 1 ? 0 : 1]}`).join(" · ");
  const description = "Penthera's research: every study registered before it runs, its status and result, the case studies and posts, newest first, each dated.";
  const ld = researchLd(entries, { url, origin, description });
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Research: studies, results and case studies · Penthera</title>
  <meta name="description" content="${esc(description)}">
  <meta name="color-scheme" content="dark light">
  <link rel="canonical" href="${url}">
  <link rel="alternate" type="text/markdown" href="/research.md">
  <meta property="og:site_name" content="Penthera">
  <meta property="og:title" content="Penthera research">
  <meta property="og:description" content="${esc(description)}">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${url}">
  <meta property="og:image" content="${origin}/media/social/og-plain.png">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="${styles}">
  <script src="${theme}"></script>
  <script src="${script}" defer></script>
  ${ld}
</head>
<body>
  <main class="terms land bm rs" id="main">
    <nav class="eyebrow" aria-label="Breadcrumb"><a href="/">Penthera</a> · Research</nav>
    <h1>Research</h1>
    <p class="rs-purpose">${esc(PURPOSE)}</p>
    <p class="rs-tally">${esc(tally)}. Statuses: Registered, Running, Result, Draft. A draft is not registered.</p>
${featured(pub)}
    <h2 class="rs-list-title" id="rs-list">Every study, result and note, newest first</h2>
${tools(entries)}
    <ol class="rs-list" id="rs-items" aria-labelledby="rs-list">
${entries.map(item).join("\n")}
    </ol>
    <p class="rs-none" hidden>Nothing matches. <button type="button" class="rs-reset">Clear the search and filters</button></p>
    <p class="rs-all" data-js hidden><button type="button" class="btn btn-steel" aria-controls="rs-items">Show all ${entries.length}</button></p>
    <p class="rs-how">A study is registered by the commit that merges its protocol, and the protocol lists any data seen before that. Changes after that are logged in its deviations section, with the date and the reason. Everything here is read from <a href="${REPO}/tree/main/docs/research">docs/research</a>, <a href="${REPO}/tree/main/bench">bench</a> and the blog when the site is built.</p>
  </main>
  ${foot}
</body>
</html>
`;
}

/** /research as Markdown, for agents. */
export function researchMarkdown(entries, { origin, pub = null }) {
  const abs = (h) => (h.startsWith("/") ? `${origin}${h}` : h);
  const bench = pub?.benchmarks
    ? `## Featured: the public benchmark (${pub.date})\n\nPenthera and ${fieldTools(pub)} free security tools, scored once on the sealed half of four public datasets ([all four](${origin}/benchmarks.md)):\n\n${benchmarkViews(pub).map((v) => `- ${v.c.label}, ${v.c.dataset.short}: ${rankText(v)}, ${v.c.scoreName} ${n2(v.us.score)}`).join("\n")}\n\nWhere a range follows the rank, Penthera's rank fell in that range in 95% of bootstrap redraws.\n\n`
    : "";
  const extra = (e) => `${e.result ? ` [Result](${abs(e.result)}).` : ""}${(e.notes || []).map((n) => ` ${n.text} [Re-run](${n.href}).`).join("")}`;
  const line = (e) => `- ${e.date || "Undated"} · ${e.type}${e.id ? ` ${e.id}` : ""}${e.status ? ` · ${e.status}` : ""}: [${e.headline || e.title}](${abs(e.href)}). ${e.summary}${extra(e)}`;
  return `# Penthera research

> ${PURPOSE}

${bench}## Every study, result and note, newest first

${entries.map(line).join("\n")}

Statuses: Registered, Running, Result, Draft. A draft is not registered.
`;
}
