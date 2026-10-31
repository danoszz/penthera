/**
 * /benchmarks and one page per public benchmark (E11b), generated from
 * bench/public/published.json at build time, so every number on them is a
 * number in that file. Each page shows every tool: ranks, scores, 95%
 * intervals, counts, the tools that were not ranked and why, and where
 * another tool does better than Penthera.
 *
 *   /benchmarks                  the hub: the four rankings, method, date
 *   /benchmarks/<slug>           one benchmark, every tool
 *   /benchmarks.md, /benchmarks/<slug>.md   the same, as Markdown for agents
 *
 * Each HTML page carries schema.org Dataset and BreadcrumbList JSON-LD. The
 * prose here holds no numbers: the limits are words, and anything counted is
 * read from the file.
 */
import { hubChips, mosaic } from "./news.mjs";
import { paperPage } from "./blog.mjs";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ldScript, siteFooter } from "./frame.mjs";

const REPO = "https://github.com/danoszz/penthera";
const BLOB = `${REPO}/blob/main`;
const RAW = "https://raw.githubusercontent.com/danoszz/penthera/main/bench/public/published.json";
const PROTOCOL = `${BLOB}/docs/research/prereg/E11b-improvement-study.md`;
const AUTHOR = { "@type": "Person", name: "Daan van der Zwaag", url: "https://daanvanderzwaag.com" };

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
export const n2 = (x) => (x == null ? "n/a" : x.toFixed(2));
export const ord = (n) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? "th" : ["th", "st", "nd", "rd"][n % 10] || "th"}`;
const kn = (a) => `${a[0].toLocaleString("en-US")}/${a[1].toLocaleString("en-US")}`;
const ci = (c) => (c ? `[${n2(c[0])}, ${n2(c[1])}]` : "");
const longDate = (d) => new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
const name = (r) => `${r.tool} ${r.version}`;
/** In a sentence: Penthera with its version, other tools by name (their versions are in the table). */
const said = (r) => (r.kind.startsWith("penthera") ? name(r) : r.tool);

/**
 * How sure Penthera's rank is: the 95% interval of its rank over bootstrap
 * redraws (bench/public/rank-intervals.json, exploratory). A point rank is
 * printed with its interval wherever the interval is wider than one place.
 */
export const RANK_INTERVALS = JSON.parse(readFileSync(new URL("../bench/public/rank-intervals.json", import.meta.url), "utf8"));
/** ", tied 1st to 3rd" when the interval spans more than one place; "" when it is one place or unknown. */
export const tiedPhrase = (iv) => (iv && iv.rank[0] !== iv.rank[1] ? `, tied ${ord(iv.rank[0])} to ${ord(iv.rank[1])}` : "");
/** The one-sentence explanation of a rank interval, for a page's notes. */
export function intervalNote(iv) {
  if (!iv) return null;
  const [lo, hi] = iv.rank;
  const how = iv.resample === "items" ? `the test bugs were resampled ${iv.replicates.toLocaleString("en-US")} times, the same draw for every tool` : `each tool's counts were redrawn ${iv.replicates.toLocaleString("en-US")} times`;
  const span = lo === hi ? `Penthera ranked ${ord(lo)} in at least 95% of the draws` : `Penthera's rank fell between ${ord(lo)} and ${ord(hi)} in 95% of the draws`;
  const first = Math.round(iv.first * 100) ? `, and it alone came out first in ${Math.round(iv.first * 100)}%` : "";
  return `How sure the rank is: ${how}. ${span}${first}. This analysis is exploratory: it was done after the registered ranking.`;
}

/** A score below this is barely a contest; the notes name the ranked tools under it. */
export const WEAK = 0.1;
/** The other ranked tools scoring below WEAK: { tools, of }, or null when there are none. */
export function weakField(b) {
  const others = b.rows.filter((r) => r.rank != null && !r.excluded && r.kind !== "penthera");
  const tools = others.filter((r) => r.score < WEAK).map((r) => r.tool);
  return tools.length ? { tools, of: others.length } : null;
}
/** The prevalence the flag share assumes: 1 malicious package in 1,000. */
export const PREVALENCE = 1 / 1000;
/** The share of Penthera's malware flags that would be right at PREVALENCE, measured and at the top of the false-alarm interval. */
export function flagShare(us) {
  if (!us?.benignCI) return null;
  const right = (fa) => (us.r * PREVALENCE) / (us.r * PREVALENCE + fa * (1 - PREVALENCE));
  return { measured: us.fa ? right(us.fa) : null, worst: right(us.benignCI[1]) };
}
const pc1 = (x) => `${(x * 100).toFixed(1)}%`;
/** The exploratory re-analysis (bench/public/reanalysis.mjs): recall over every true row. */
export const REANALYSIS = JSON.parse(readFileSync(new URL("../bench/public/reanalysis.json", import.meta.url), "utf8"));
/** Penthera's recall over every true CredData row, and its place by F1 over those rows among the ranked tools. */
export function scopeFreeSecrets(re = REANALYSIS) {
  const rows = re.scopeFree.secrets.filter((r) => r.all && !r.excluded && (r.kind === "penthera" || r.kind === "tool"));
  const us = rows.find((r) => r.kind === "penthera");
  if (!us) return null;
  return { recall: us.all[0] / us.all[1], place: 1 + rows.filter((r) => r.f1All > us.f1All).length, of: rows.length };
}
/** The two notes as sentences, for a page: who is barely in the contest, and what a flag means. Exploratory. */
export function fieldNotes(key, b) {
  const out = [], w = weakField(b), f = flagShare(b.rows.find((r) => r.kind === "penthera"));
  if (w) out.push(`${w.tools.length} of the ${w.of} other ranked tools ${w.tools.length === 1 ? "scores" : "score"} below ${n2(WEAK)}: ${w.tools.join(", ")}.`);
  const s = key === "secrets" ? scopeFreeSecrets() : null;
  if (s) out.push(`Counted over every true credential row, not only the in-scope ones, Penthera's recall is ${n2(s.recall)} and it would place ${ord(s.place)} by F1. The registered ranking counts in-scope rows. This is exploratory: it was done after the registered ranking.`);
  if (f && (key === "npm" || key === "pypi")) {
    const at = `If 1 package in ${(1 / PREVALENCE).toLocaleString("en-US")} were malicious`;
    out.push(f.measured == null
      ? `${at}, about ${pc1(f.worst)} of Penthera's flags would be right at the top of its false-alarm interval. It raised no false alarm on this sample, so only that upper figure means anything.`
      : `${at}, about ${pc1(f.measured)} of Penthera's flags would be right at its measured false-alarm rate, and ${pc1(f.worst)} at the top of the interval.`);
  }
  return out;
}

/**
 * What each benchmark page says around the numbers. Words only: a test fails
 * if a digit appears here, so no number can be typed by hand.
 */
export const BENCHMARKS = {
  secrets: {
    slug: "secrets",
    label: "Leaked secrets",
    title: (b) => `Secret scanner benchmark: ${b.of} free tools on Samsung CredData`,
    h1: (b) => `Free secret scanners on Samsung CredData: ${b.of} tools ranked`,
    question: "Which free secret scanner finds the most leaked secrets on CredData?",
    dataset: { name: "Samsung CredData", short: "Samsung CredData", url: "https://github.com/Samsung/CredData" },
    scoreName: "F1",
    variables: ["Precision", "Recall", "F1 score"],
    keywords: ["secret scanner benchmark", "secret detection", "gitleaks", "trufflehog", "CredData"],
    sample: (b) => `the sealed test half of Samsung CredData (${b.n.toLocaleString("en-US")} labelled secrets)`,
    // [column heading, cell, the measure's value for "where another tool does better", higher is better]
    cols: [
      ["Precision", (r) => `${n2(r.p)} ${ci(r.precisionCI)} <span class="bm-kn">${kn(r.precision)}</span>`, (r) => r.p, true],
      ["Recall", (r) => `${n2(r.r)} ${ci(r.recallCI)} <span class="bm-kn">${kn(r.recall)}</span>`, (r) => r.r, true],
    ],
    limits: [
      "CredData replaces each real secret with random characters of the same shape. That favours pattern rules over tools that check a key with its provider.",
      "trufflehog ran with verification off: verifying calls each provider's API, and every tool ran offline. Checking a key with its provider is its main feature, so its score here undersells it.",
      "CredData's labels lean partly on other scanners' output, and it is split by file, so most repositories have files on both halves.",
    ],
  },
  npm: {
    slug: "npm-malware",
    label: "Malicious npm packages",
    nav: "Malicious npm",
    title: (b) => `npm malware detector benchmark: ${b.of} free tools on DataDog's dataset`,
    h1: (b) => `Free npm malware detectors on DataDog's dataset: ${b.of} tools ranked`,
    question: "Which free tool catches the most malicious npm packages, with the fewest false alarms?",
    dataset: { name: "DataDog malicious software packages dataset", short: "DataDog's dataset", url: "https://github.com/DataDog/malicious-software-packages-dataset" },
    scoreName: "caught minus false alarms",
    variables: ["Share of malicious packages caught", "Share of benign packages flagged (false alarms)", "Youden's J (caught minus false alarms)"],
    keywords: ["npm malware scanner", "malicious npm packages", "GuardDog", "supply chain security"],
    sample: (b, us) => `a sealed half of DataDog's malicious npm packages (${us.detect[1]} with a payload) and ${us.benign[1]} popular benign packages`,
    cols: malwareCols(),
    limits: [
      "GuardDog's authors helped build this dataset, so GuardDog's catch rate is inflated by construction.",
      "osv-scanner looks packages up in a list of reports. It is shown, not ranked: a lookup of known packages is not detection.",
      "The benign side is popular packages, which are the easiest to keep quiet on. Your dependencies may be less tidy.",
    ],
  },
  pypi: {
    slug: "pypi-malware",
    label: "Malicious PyPI packages",
    nav: "Malicious PyPI",
    title: (b) => `PyPI malware detector benchmark: ${b.of} free tools on DataDog's dataset`,
    h1: (b) => `Free PyPI malware detectors on DataDog's dataset: ${b.of} tools ranked`,
    question: "Which free tool catches the most malicious PyPI packages, with the fewest false alarms?",
    dataset: { name: "DataDog malicious software packages dataset", short: "DataDog's dataset", url: "https://github.com/DataDog/malicious-software-packages-dataset" },
    scoreName: "caught minus false alarms",
    variables: ["Share of malicious packages caught", "Share of benign packages flagged (false alarms)", "Youden's J (caught minus false alarms)"],
    keywords: ["PyPI malware scanner", "malicious Python packages", "GuardDog", "Bandit4Mal"],
    sample: (b, us) => `a sealed half of DataDog's malicious PyPI packages (${us.detect[1]} with a payload) and ${us.benign[1]} popular benign packages`,
    cols: malwareCols(),
    limits: [
      "GuardDog's authors helped build this dataset, so GuardDog's catch rate is inflated by construction.",
      "osv-scanner looks packages up in a list of reports. It is shown, not ranked: a lookup of known packages is not detection.",
      "Penthera missed its own pre-registered target for false alarms on this benchmark.",
    ],
  },
  library: {
    slug: "js-injection",
    label: "Injection bugs in JavaScript libraries",
    nav: "Injection bugs in JS",
    title: (b) => `JavaScript injection benchmark: ${b.of} free analyzers on SecBench.js`,
    h1: (b) => `Free JavaScript static analyzers on SecBench.js injection bugs: ${b.of} tools ranked`,
    question: "Which free static analyzer finds the most injection bugs in JavaScript libraries?",
    dataset: { name: "SecBench.js", short: "SecBench.js", url: "https://github.com/cristianstaicu/SecBench.js" },
    scoreName: "share found in the right file",
    variables: ["Command injection bugs found in the right file", "Code injection bugs found in the right file", "Strict recall, both kinds pooled"],
    keywords: ["JavaScript static analysis benchmark", "command injection npm", "CodeQL", "Semgrep", "ODGen"],
    sample: (b, us) => `the sealed test half of SecBench.js (${us.pooled[1]} command and code injection bugs in npm libraries)`,
    cols: [
      ["Command injection", (r) => kn(r.command), (r) => r.command[0] / r.command[1], true],
      ["Code injection", (r) => kn(r.code), (r) => r.code[0] / r.code[1], true],
    ],
    limits: [
      "A bug counts only when the tool points at the right file. False alarms are not part of this score.",
      "A few packages appeared on both halves of the split; the results file reports the score without them.",
      "Penthera's code-injection count did not move between releases. The gain is in command injection.",
    ],
  },
};

function malwareCols() {
  return [
    ["Caught", (r) => `${n2(r.r)} ${ci(r.detectCI)} <span class="bm-kn">${kn(r.detect)}</span>`, (r) => r.r, true],
    ["False alarms", (r) => `${n2(r.fa)} ${ci(r.benignCI)} <span class="bm-kn">${kn(r.benign)}</span>`, (r) => r.fa, false],
  ];
}

/** Limits that hold for every benchmark. */
const COMMON_LIMITS = [
  "The free tools ran on their defaults. Penthera was tuned on the other half of the dataset, then scored once on this half.",
  "A benchmark is not your code. Accuracy on real projects is experiment E1, pre-registered and not yet run.",
];

/** The page's view of one benchmark: ranked rows best first, the rest, Penthera, ties and margins. */
export function view(key, b) {
  const ranked = b.rows.filter((r) => r.rank != null && !r.excluded).sort((x, y) => x.rank - y.rank);
  const unranked = b.rows.filter((r) => r.rank == null || r.excluded);
  const us = ranked.find((r) => r.kind === "penthera");
  const top = ranked[0];
  const next = ranked.find((r) => r !== us);
  // A lead under 0.05 sits inside the 95% intervals here (the rule in public-bench.mjs).
  const close = us && us.rank === 1 && next && us.score - next.score < 0.05 ? next : null;
  const ties = [];
  for (const [i, r] of ranked.entries()) for (const s of ranked.slice(i + 1)) if (r.score === s.score) ties.push([r, s]);
  const iv = RANK_INTERVALS.penthera[key] ? { ...RANK_INTERVALS.penthera[key], replicates: RANK_INTERVALS.replicates } : null;
  return { key, b, c: BENCHMARKS[key], ranked, unranked, us, top, close, ties, iv };
}

/** The tool names in the whole file, every benchmark, Penthera and settings of another tool left out. */
export function fieldTools(pub) {
  const names = new Set();
  for (const b of Object.values(pub.benchmarks)) {
    for (const r of b.rows) if (!r.kind.startsWith("penthera") && !/^another setting of/.test(r.caveat || "")) names.add(r.tool.toLowerCase());
  }
  return names.size;
}

/** The one-paragraph answer: who ranked first, where Penthera ranked, on what sample, when. */
export function answer(v, pub) {
  const { c, b, us, top, close } = v;
  const s = c.sample(b, us);
  if (us === top) {
    const tail = close
      ? ` ${said(close)} scored ${n2(close.score)}, within the margin of error, so read it as a tie.`
      : ` Next was ${said(v.ranked[1])} with ${n2(v.ranked[1].score)}.`;
    return `On ${s}, Penthera ${us.version} ranked 1st of ${b.of} free tools${tiedPhrase(v.iv)}, with ${c.scoreName} ${n2(us.score)}.${tail} Measured on ${longDate(pub.date)}.`;
  }
  const vs = c.cols.map(([h, , val, up]) => {
    const a = val(us), z = val(top);
    if (a === z) return null;
    return `${(up ? a > z : a < z) ? "better" : "worse"} ${h.toLowerCase()} (${n2(a)} against ${n2(z)})`;
  }).filter(Boolean);
  return `On ${s}, ${said(top)} ranked 1st of ${b.of} free tools, with ${c.scoreName} ${n2(top.score)}. Penthera ${us.version} ranked ${ord(us.rank)}${tiedPhrase(v.iv)} with ${n2(us.score)}${vs.length ? `: ${vs.join(", ")}` : ""}. Measured on ${longDate(pub.date)}.`;
}

/** The short form for the hub, llms.txt and /index.md. */
export function rankingLine(v) {
  const { c, b, us, top, close } = v;
  if (us === top) return `Penthera ${us.version} ranked 1st of ${b.of} free tools${tiedPhrase(v.iv) && `${tiedPhrase(v.iv)},`} by ${c.scoreName} (${n2(us.score)})${close ? `, within the margin of error of ${said(close)} (${n2(close.score)})` : `; next, ${said(v.ranked[1])} (${n2(v.ranked[1].score)})`}`;
  return `Penthera ${us.version} ranked ${ord(us.rank)} of ${b.of} free tools${tiedPhrase(v.iv) && `${tiedPhrase(v.iv)},`} by ${c.scoreName} (${n2(us.score)}), behind ${v.ranked.filter((r) => r.rank < us.rank).map((r) => `${said(r)} (${n2(r.score)})`).join(", ")}`;
}

/** Measures on which a ranked tool does better than Penthera. */
export function betterThanUs(v) {
  const out = [];
  for (const [h, , val, up] of v.c.cols) {
    const ours = val(v.us);
    const best = v.ranked.filter((r) => r !== v.us).sort((x, y) => (up ? val(y) - val(x) : val(x) - val(y)))[0];
    if (best && (up ? val(best) > ours : val(best) < ours)) out.push({ measure: h, tool: best, theirs: val(best), ours, overall: best.score });
  }
  return out;
}

const unrankedReason = (r) => (r.kind === "penthera-before" ? "the previous release, for comparison" : r.caveat || "not ranked");

// ── HTML ────────────────────────────────────────────────────────────────────

function bars(v) {
  const max = Math.max(...v.ranked.map((r) => r.score), 0.01);
  const w = (x) => Math.max(1, Math.round((Math.max(0, x) / max) * 100));
  return v.ranked.map((r) => `<li class="pb-row${r.kind === "penthera" ? " is-us" : ""}"><span class="pb-tool">${esc(r.tool)}</span><svg class="pb-track" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true"><rect class="pb-bg" width="100" height="10"/><rect class="pb-bar" width="${w(r.score)}" height="10"/></svg><span class="pb-val">${n2(r.score)}</span></li>`).join("");
}

function table(v) {
  const head = `<tr><th scope="col">Rank</th><th scope="col">Tool</th>${v.c.cols.map(([h]) => `<th scope="col">${esc(h)}</th>`).join("")}<th scope="col">Score: ${esc(v.c.scoreName)}</th></tr>`;
  const row = (r, rank) => `<tr${r.kind === "penthera" ? ' class="is-us"' : ""}><td>${rank}</td><th scope="row">${esc(r.tool)} <span class="bm-ver">${esc(r.version)}</span></th>${v.c.cols.map(([, cell]) => `<td>${cell(r)}</td>`).join("")}<td><strong>${n2(r.score)}</strong>${r.pooledCI ? ` ${ci(r.pooledCI)} <span class="bm-kn">${kn(r.pooled)}</span>` : ""}</td></tr>`;
  const ranked = v.ranked.map((r) => row(r, r.rank)).join("\n");
  const rest = v.unranked.map((r) => row(r, `<span aria-hidden="true">–</span><span class="sr">Not ranked</span>`)).join("\n");
  return `<div class="cmp-scroll" role="region" aria-label="${esc(v.c.label)}: every tool" tabindex="0"><table class="bm-table"><thead>${head}</thead>\n<tbody>\n${ranked}\n${rest}\n</tbody></table></div>`;
}

/** The schema.org Dataset for one benchmark. */
export function datasetLd(v, pub, origin) {
  const url = `${origin}/benchmarks/${v.c.slug}`;
  return {
    "@type": "Dataset",
    "@id": `${url}#dataset`,
    name: `${v.b.title}: free security tools ranked (Penthera E11b)`,
    description: `${answer(v, pub)} Every tool ran offline on the same sealed half of the dataset and was scored the same way: ${v.b.measure}. Scores carry 95% Wilson intervals.`,
    url,
    creator: AUTHOR,
    license: "https://spdx.org/licenses/MIT.html",
    isAccessibleForFree: true,
    datePublished: pub.date,
    keywords: v.c.keywords,
    isBasedOn: { "@type": "Dataset", name: v.c.dataset.name, url: v.c.dataset.url },
    measurementTechnique: v.b.measure,
    variableMeasured: v.c.variables,
    isPartOf: { "@id": `${origin}/benchmarks#dataset` },
    distribution: { "@type": "DataDownload", encodingFormat: "application/json", contentUrl: RAW },
  };
}

/** The schema.org Dataset for the whole file. */
export function hubDatasetLd(pub, origin, views) {
  return {
    "@type": "Dataset",
    "@id": `${origin}/benchmarks#dataset`,
    name: "Penthera public benchmarks (E11b): free security tools on four public datasets",
    description: `Penthera and ${fieldTools(pub)} free open-source security tools, scored the same way on a sealed half of four public datasets: Samsung CredData (secrets), DataDog's malicious npm and PyPI packages, and SecBench.js (injection bugs in JavaScript libraries). The ranking rules were pre-registered. Every score has its 95% Wilson interval and counts; tools that could not be ranked are listed with the reason.`,
    url: `${origin}/benchmarks`,
    creator: AUTHOR,
    license: "https://spdx.org/licenses/MIT.html",
    isAccessibleForFree: true,
    datePublished: pub.date,
    keywords: ["security tool benchmark", "secret scanner benchmark", "malware detection benchmark", "static analysis benchmark", "preregistered"],
    citation: PROTOCOL,
    hasPart: views.map((v) => ({ "@id": `${origin}/benchmarks/${v.c.slug}#dataset` })),
    isBasedOn: [...new Map(views.map((v) => [v.c.dataset.url, { "@type": "Dataset", name: v.c.dataset.name, url: v.c.dataset.url }])).values()],
    distribution: { "@type": "DataDownload", encodingFormat: "application/json", contentUrl: RAW },
  };
}

const crumbs = (origin, items) => ({
  "@type": "BreadcrumbList",
  itemListElement: items.map(([n, path], i) => ({ "@type": "ListItem", position: i + 1, name: n, item: `${origin}${path}` })),
});


/** The <head> and frame every benchmark page shares (the landing-page frame). */
/** One page, on the same paper as the news hub, with its chips under the mast. */
function frame({ title, description, path, h1, crumb, ld, body, origin, styles, theme, image, foot, pub, number, blog = true, script = "/hub.js" }) {
  return paperPage({ title, description, url: `${origin}${path}`, path, h1, crumb, ld, body: `${hubChips("benchmark", blog)}\n${body}`, styles, theme, foot, type: "article", feed: false, number, bar: "Penthera benchmarks", dateline: longDate(pub.date), mast: true, mastHtml: mosaic("RANK"), view: "benchmark", headScript: script, image, headline: true, main: "bm" });
}

/** The answer and what to read before the numbers: side by side when both are short. */
const opening = (answerText, limits, long = false) => `    <div class="bm-open${long ? " is-long" : ""}">
      <p class="bm-answer">${answerText}</p>
      <aside class="bm-limits" aria-labelledby="limits">
        <h2 id="limits">Read this before the numbers</h2>
        <ul>
${limits.map((l) => `          <li>${l}</li>`).join("\n")}
        </ul>
      </aside>
    </div>`;

/** A scoreboard card: Penthera's place, every ranked tool, and the sentence that goes with them. */
const boardCard = (v) => `      <li class="bm-card${v.us.rank === 1 ? "" : " is-behind"}">
        <h3><a href="/benchmarks/${v.c.slug}">${esc(v.c.label)}</a></h3>
        <p class="bm-set">${esc(v.c.dataset.short)}</p>
        <p class="bm-rank"><span>${ord(v.us.rank)}</span> of ${v.b.of}</p>
        <p class="bm-range">${esc((tiedPhrase(v.iv) || (v.close ? ", within the margin of error" : "")).replace(/^, /, "")) || "&nbsp;"}</p>
        <ol class="pb-chart" aria-label="${esc(v.c.scoreName)}, every ranked tool">${bars(v)}</ol>
        <p class="bm-line">${esc(rankingLine(v))}.</p>
      </li>`;

const description = (v) => `${v.c.label}: Penthera ranked ${ord(v.us.rank)} of ${v.b.of} free tools${tiedPhrase(v.iv)} on ${v.c.dataset.short}${v.close && !tiedPhrase(v.iv) ? ", within the margin of error" : ""}. Every score, interval and limit.`;

/** One benchmark page. */
export function benchmarkHtml(key, pub, { origin, styles = "/styles.css", theme = "/theme.js", image, foot = siteFooter(), blog = true }) {
  const v = view(key, pub.benchmarks[key]);
  const path = `/benchmarks/${v.c.slug}`;
  const better = betterThanUs(v);
  const notes = [
    ...v.ties.map(([a, z]) => `${esc(a.tool)} and ${esc(z.tool)} have the same score, ${n2(a.score)}; the order between them carries no meaning.`),
    ...v.ranked.filter((r) => r.caveat).map((r) => `${esc(r.tool)}: ${esc(r.caveat)}.`),
    `A rank needs at least five other free tools measured; this benchmark has ${v.b.field}.`,
    ...(v.iv ? [esc(intervalNote(v.iv))] : []),
    ...fieldNotes(v.key, v.b).map(esc),
    `Median score of the other free tools: ${n2(v.b.others[v.key === "secrets" ? "f1" : v.key === "library" ? "r" : "j"].median)}.`,
  ];
  const body = `${opening(esc(answer(v, pub)), [...v.c.limits, ...COMMON_LIMITS].map(esc), true)}
    <h2>${esc(v.c.question)}</h2>
    <p>${esc(rankingLine(v))}. Scored by ${esc(v.b.measure)}.</p>
    <figure class="bm-fig">
      <ol class="pb-chart" aria-label="${esc(v.c.scoreName)}, every ranked tool">${bars(v)}</ol>
      <figcaption>Score: ${esc(v.c.scoreName)}, relative to the top score. Ranked tools only.</figcaption>
    </figure>
    <h2>Every tool, with 95% intervals</h2>
    <p>Counts are found over total. Intervals are 95% Wilson intervals. Penthera's row is bold.</p>
${table(v)}
    <ul class="bm-notes">
${notes.map((n) => `      <li>${n}</li>`).join("\n")}
    </ul>
    <div class="bm-sections">
    <section>
    <h2>Not ranked, and why</h2>
    <ul>
${v.unranked.map((r) => `      <li>${esc(name(r))}: ${esc(unrankedReason(r))}. Score ${n2(r.score)}.</li>`).join("\n")}
    </ul>
    </section>
    <section>
    <h2>Where another tool does better than Penthera</h2>
${better.length ? `    <ul>
${better.map((x) => `      <li>${esc(x.measure)}: ${esc(said(x.tool))} ${n2(x.theirs)}, Penthera ${n2(x.ours)}. Overall, ${esc(x.tool.tool)} scored ${n2(x.overall)}.</li>`).join("\n")}
    </ul>` : "    <p>On no single measure here.</p>"}
    </section>
    <section>
    <h2>Tools that are not here</h2>
    <p>Paid tools (${esc(pub.paidTools.names.join(", "))}) are not here. ${esc(pub.paidTools.note)}${v.b.skipped ? ` Skipped: ${Object.entries(v.b.skipped).map(([t, why]) => `${esc(t)} (${esc(why)})`).join("; ")}.` : ""}</p>
    </section>
    <section>
    <h2>Published elsewhere, on other data</h2>
    <ul>
${v.b.context.map((c) => `      <li><a href="${esc(c.url)}">${esc(c.title)}</a></li>`).join("\n")}
    </ul>
    <p>Not comparable with the numbers above: other datasets, other scoring.</p>
    </section>
    <section>
    <h2>Check it yourself</h2>
    <p>The dataset is <a href="${esc(v.c.dataset.url)}">${esc(v.c.dataset.name)}</a>. The ranking rules were written down before the run: <a href="${PROTOCOL}">the protocol</a>. Every number on this page is read from <a href="${BLOB}/bench/public/published.json">published.json</a> when the site is built; <a href="${BLOB}/bench/public/RESULTS.md">the results file</a> has the method and per-family detail, and <a href="${BLOB}/bench/public/README.md">the runner's README</a> says how to reproduce it.</p>
    <p>Measured on <time datetime="${pub.date}">${longDate(pub.date)}</time>. ${esc(pub.note)} <a href="/benchmarks">All four benchmarks</a>.</p>
    </section>
    </div>
    <nav class="ttx-keys" aria-label="More pages"><a href="/benchmarks">All four benchmarks</a><a href="${BLOB}/bench/public/published.json">published.json</a><a href="${path}.md">Markdown copy</a></nav>`;
  const ld = ldScript([datasetLd(v, pub, origin), crumbs(origin, [["Penthera", "/"], ["Benchmarks", "/benchmarks"], [v.c.label, path]])]);
  return frame({
    title: v.c.title(v.b), description: description(v), path, h1: v.c.h1(v.b), origin, styles, theme, ld, body, foot, pub, blog,
    number: `P${201 + Object.keys(pub.benchmarks).indexOf(key)}`,
    image: image || `${origin}/media/social/og-plain.png`,
    crumb: `<a class="tag" data-f="4" data-c="0" data-t="0" href="/">Penthera</a><a class="tag" data-f="4" data-c="0" data-t="0" href="/benchmarks">Benchmarks</a><span class="tag" data-f="3" data-c="0" data-t="0">${esc(v.c.label)}</span>`,
  });
}

/** Every benchmark in the file that has a page, in a fixed order. */
export function benchmarkViews(pub) {
  return Object.keys(BENCHMARKS).filter((k) => pub.benchmarks?.[k]).map((k) => view(k, pub.benchmarks[k]));
}

/** The hub, /benchmarks. */
export function hubHtml(pub, { origin, styles = "/styles.css", theme = "/theme.js", image, foot = siteFooter(), blog = true }) {
  const views = benchmarkViews(pub);
  const n = fieldTools(pub);
  const body = `${opening(`Four public datasets other people built, scored the same way. Penthera ${esc(views[0].us.version)} against free tools, on the sealed half of each. Measured on ${longDate(pub.date)}.`, [...COMMON_LIMITS.map(esc), "Each benchmark page lists its own limits, every tool that was not ranked and why, and where another tool does better than Penthera."])}
    <h2 class="bm-q">How does Penthera rank against the free tools?</h2>
    <ol class="bm-board">
${views.map(boardCard).join("\n")}
    </ol>
    <div class="bm-sections">
    <section>
    <h2>How the benchmarks were run</h2>
    <p>Each dataset was split in half before any tuning. Penthera was improved on one half, the dev half, and scored once on the other, sealed half. The scoring and ranking rules were registered before that run: <a href="${PROTOCOL}">the protocol</a>. Every tool ran offline, on its defaults. A rank is given only where at least five other free tools were measured.</p>
    <p>Paid tools (${esc(pub.paidTools.names.join(", "))}) are not here. ${esc(pub.paidTools.note)}</p>
    </section>
    <section>
    <h2>Check it yourself</h2>
    <p>Every number on these pages is read from <a href="${BLOB}/bench/public/published.json">published.json</a> when the site is built. <a href="${BLOB}/bench/public/RESULTS.md">The results file</a> has the method, the leakage audit and per-family detail; <a href="${BLOB}/bench/public/README.md">the runner's README</a> says how to reproduce each run. The bundled benchmark in <a href="${BLOB}/bench/RESULTS.md">bench/RESULTS.md</a> is different: small labs we wrote ourselves, which catch regressions and do not measure accuracy.</p>
    <p>Measured on <time datetime="${pub.date}">${longDate(pub.date)}</time>. ${esc(pub.note)}</p>
    </section>
    </div>
    <nav class="ttx-keys" aria-label="More pages"><a href="/research">Research</a><a href="${BLOB}/bench/public/published.json">published.json</a><a href="/benchmarks.md">Markdown copy</a></nav>`;
  const ld = ldScript([hubDatasetLd(pub, origin, views), crumbs(origin, [["Penthera", "/"], ["Benchmarks", "/benchmarks"]])]);
  return frame({
    title: `Security tool benchmarks: Penthera and ${n} free tools on four public datasets`,
    description: `Penthera and ${n} free security tools on four public datasets: secrets, npm and PyPI malware, JavaScript injection. Every score, interval, loss and limit.`,
    path: "/benchmarks", h1: `Penthera and ${n} free security tools, on four public benchmarks`, origin, styles, theme, ld, body, foot, pub, blog, number: "P200",
    image: image || `${origin}/media/social/og-plain.png`,
    crumb: `<a class="tag" data-f="4" data-c="0" data-t="0" href="/">Penthera</a><span class="tag" data-f="3" data-c="0" data-t="0">Benchmarks</span>`,
  });
}


// ── Markdown, for agents ────────────────────────────────────────────────────

const mdKn = (s) => s.replace(/<span class="bm-kn">([^<]+)<\/span>/g, "($1)");

/** One benchmark page as Markdown. */
export function benchmarkMarkdown(key, pub, { origin }) {
  const v = view(key, pub.benchmarks[key]);
  const head = `| Rank | Tool | ${v.c.cols.map(([h]) => h).join(" | ")} | ${v.c.scoreName} |`;
  const row = (r, rank) => `| ${rank} | ${r.kind === "penthera" ? `**${name(r)}**` : name(r)} | ${v.c.cols.map(([, cell]) => mdKn(cell(r))).join(" | ")} | ${n2(r.score)}${r.pooledCI ? ` ${ci(r.pooledCI)}` : ""} |`;
  return `# ${v.c.h1(v.b)}

> ${v.c.question}

${answer(v, pub)}

## Read this before the numbers

${[...v.c.limits, ...COMMON_LIMITS].map((l) => `- ${l}`).join("\n")}

## Every tool, with 95% intervals

Scored by ${v.b.measure}. Counts are found over total; intervals are 95% Wilson.

${head}
|${"---|".repeat(v.c.cols.length + 3)}
${v.ranked.map((r) => row(r, r.rank)).join("\n")}
${v.unranked.map((r) => row(r, "–")).join("\n")}

Not ranked: ${v.unranked.map((r) => `${name(r)} (${unrankedReason(r)})`).join("; ")}.
${v.iv ? `\n${intervalNote(v.iv)}\n` : ""}${fieldNotes(v.key, v.b).map((s) => `\n${s}\n`).join("")}
## Where another tool does better than Penthera

${betterThanUs(v).map((x) => `- ${x.measure}: ${said(x.tool)} ${n2(x.theirs)}, Penthera ${n2(x.ours)}. Overall, ${x.tool.tool} scored ${n2(x.overall)}.`).join("\n") || "- On no single measure here."}

## Sources

- Dataset: [${v.c.dataset.name}](${v.c.dataset.url})
- Numbers: ${BLOB}/bench/public/published.json (measured ${pub.date}; ${pub.note})
- Protocol: ${PROTOCOL}
- All four benchmarks: ${origin}/benchmarks.md
`;
}

/** The ranking lines, one per benchmark, linking each page (HTML or Markdown). */
export function rankingList(pub, origin, ext = "") {
  return benchmarkViews(pub).map((v) => `- [${v.c.label}, ${v.c.dataset.short}](${origin}/benchmarks/${v.c.slug}${ext}): ${rankingLine(v)}.`).join("\n");
}

/** The hub as Markdown. */
export function hubMarkdown(pub, { origin }) {
  return `# Penthera and ${fieldTools(pub)} free security tools, on four public benchmarks

> How does Penthera rank against the free tools, on public data other people labelled?

Measured on ${pub.date}, on the sealed half of each dataset, scored once. ${pub.note}

${rankingList(pub, origin, ".md")}

${COMMON_LIMITS.join(" ")} Paid tools (${pub.paidTools.names.join(", ")}) are not here. ${pub.paidTools.note}

- Numbers: ${BLOB}/bench/public/published.json
- Protocol: ${PROTOCOL}
`;
}

// ── Share cards ─────────────────────────────────────────────────────────────

const CARDS = "media/social/bench";

/** sha256 of published.json, which the share cards record so a stale card is never used. */
export const pubHash = (text) => createHash("sha256").update(text).digest("hex");

/**
 * The share card for a page, rendered by scripts/media/benchmark-cards.mjs
 * --site into site/media/social/bench/. Used only while it was rendered from
 * this published.json; otherwise null, and the page falls back to og.png.
 */
export function cardFor(site, pubText, slug) {
  const meta = join(site, CARDS, "source.json");
  if (!existsSync(meta) || !existsSync(join(site, CARDS, `${slug}.png`))) return null;
  if (JSON.parse(readFileSync(meta, "utf8")).published !== pubHash(pubText)) return null;
  return `${CARDS}/${slug}.png`;
}
