/**
 * Marketing automation scripts (scripts/marketing/) and the workflows that run
 * them. Everything runs offline: GitHub, npm and skills.sh are injected fakes.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import YAML from "yaml";
import {
  changelogSection, highlights, intro, linkedinPost, shortPost, shareBlock, plain,
  MARKER as SHARE_MARKER, SHORT_MAX, LINKEDIN_TARGET, NPM_URL,
} from "../scripts/marketing/release-post.mjs";
import {
  monthRange, previousMonth, parseSkillsInstalls, parseDependents, parsePrevious,
  collectStats, formatIssue, findPrevious, runMonthly, draftPost as statsPost,
} from "../scripts/marketing/monthly-stats.mjs";
import {
  seenIds, plan, issueTitle, issueBody, batchComment, runRadar, BATCH_MARKER, BATCH_TITLE,
} from "../scripts/marketing/incident-radar.mjs";
import { parseMarkers, reminderBody, runFlywheel, MARKER as FLYWHEEL_MARKER } from "../scripts/marketing/contributor-flywheel.mjs";

const CHANGELOG = `# Changelog

## [Unreleased]

- nothing yet

## [2.0.0] - 2026-11-01

The release where Penthera learns to watch your AI agents at run time. It also
gets faster.

### Added

- Small helper without a bold title that should rank after the headline features
- **\`penthera watch [path]\`** (\`lib/watch.js\`): live monitoring of agent tool calls. It writes a log.
- **Rule packs**: IOC packs for supply-chain incidents, updated on release;
  each pack is reviewed by a person
- **Dashboard** (\`penthera ui --demo\`): a local web view of every scan, with no
  tracking and no external requests at all, which is a long sentence on purpose so that the LinkedIn post has to shrink it to fit within the target length

### Fixed

- **Crash on empty lockfile.** The parser assumed one package

## [1.9.0] - 2026-10-01

- old
`;

describe("release posts", () => {
  it("extracts exactly the section for a tag", () => {
    const s = changelogSection(CHANGELOG, "v2.0.0");
    expect(s).toContain("penthera watch");
    expect(s).not.toContain("## [1.9.0]");
    expect(s).not.toContain("nothing yet");
    expect(changelogSection(CHANGELOG, "v3.0.0")).toBeNull();
  });

  it("picks three bold headline bullets, plain text, Added before Fixed", () => {
    const hs = highlights(changelogSection(CHANGELOG, "v2.0.0"));
    expect(hs.map((h) => h.title)).toEqual(["penthera watch", "Rule packs", "Dashboard"]);
    expect(hs[0].detail).toBe("live monitoring of agent tool calls");
    for (const h of hs) expect(`${h.title} ${h.detail}`).not.toMatch(/[`*]/);
  });

  it("uses the first sentence of the summary paragraph", () => {
    expect(intro(changelogSection(CHANGELOG, "v2.0.0"))).toBe("The release where Penthera learns to watch your AI agents at run time.");
  });

  it("LinkedIn post stays around 600 characters with 3 bullets and both links", () => {
    const post = linkedinPost({ tag: "v2.0.0", section: changelogSection(CHANGELOG, "v2.0.0") });
    expect(post.length).toBeLessThanOrEqual(LINKEDIN_TARGET);
    expect(post.match(/^• /gm)).toHaveLength(3);
    expect(post).toContain(NPM_URL);
    expect(post).toContain("https://github.com/danoszz/penthera/releases/tag/v2.0.0");
    expect(post).not.toMatch(/[`*#]/);
  });

  it("X/Bluesky post is at most 280 characters, even with long titles", () => {
    const long = CHANGELOG.replace("**Rule packs**", `**${"Very long feature name ".repeat(12)}**`);
    for (const cl of [CHANGELOG, long]) {
      const post = shortPost({ tag: "v2.0.0", section: changelogSection(cl, "v2.0.0") });
      expect(post.length).toBeLessThanOrEqual(SHORT_MAX);
      expect(post.match(/^• /gm)).toHaveLength(3);
      expect(post).toContain(NPM_URL);
    }
  });

  it("wraps both posts in a collapsed, marked block", () => {
    const { markdown } = shareBlock({ tag: "v2.0.0", changelog: CHANGELOG });
    expect(markdown.startsWith(SHARE_MARKER)).toBe(true);
    expect(markdown).toContain("<summary>Share this release</summary>");
    expect(markdown.match(/```text/g)).toHaveLength(2);
    expect(() => shareBlock({ tag: "v9.9.9", changelog: CHANGELOG })).toThrow(/No "## \[9.9.9\]"/);
  });

  it("plain() strips Markdown, links and HTML comments", () => {
    expect(plain("**a** `b` [c](http://x) <!-- d -->e")).toBe("a b c e");
  });

  it("works on the real CHANGELOG", () => {
    const cl = readFileSync("CHANGELOG.md", "utf-8");
    const { linkedin, short } = shareBlock({ tag: "v1.4.0", changelog: cl });
    expect(short.length).toBeLessThanOrEqual(SHORT_MAX);
    expect(linkedin.length).toBeLessThanOrEqual(LINKEDIN_TARGET);
  });
});

const SKILLS_HTML = `<div class="x"><div class="text-sm"><span>Installs</span></div><div class="text-3xl font-mono">1,234</div></div>`;
const DEPENDENTS_HTML = `<a class="btn-link selected" href="/o/r/network/dependents">
  <svg aria-hidden="true"><path d="M0"></path></svg>
  42 Repositories
</a><a class="btn-link"><svg></svg> 3 Packages </a>`;

function fakeIo({ repoInfo = { stargazers_count: 120, forks_count: 9 }, issues = [], fail = [] } = {}) {
  const calls = [];
  const gh = (args, opts = {}) => {
    calls.push({ args, input: opts.input });
    const path = args.find((a) => a.startsWith("repos/") || a === "search/issues");
    if (fail.includes("gh")) throw new Error("gh down");
    if (path === "search/issues") return { total_count: 7 };
    if (path.includes("/issues?")) return issues;
    if (path.endsWith("/issues")) return { number: 99 };
    return repoInfo;
  };
  const fetchJson = async (url) => {
    if (fail.includes("npm")) throw new Error("HTTP 503");
    expect(url).toBe("https://api.npmjs.org/downloads/point/2026-09-01:2026-09-30/penthera");
    return { downloads: 3456 };
  };
  const fetchText = async (url) => {
    if (url.startsWith("https://skills.sh/")) return fail.includes("skills") ? "<html>redesigned</html>" : SKILLS_HTML;
    return DEPENDENTS_HTML;
  };
  return { gh, fetchJson, fetchText, calls };
}

describe("monthly stats", () => {
  it("computes month ranges and the previous month", () => {
    expect(monthRange("2026-02")).toEqual({ start: "2026-02-01", end: "2026-02-28", label: "February 2026" });
    expect(monthRange("2028-02").end).toBe("2028-02-29");
    expect(previousMonth(new Date("2026-11-01T07:00:00Z"))).toBe("2026-10");
    expect(previousMonth(new Date("2027-01-01T07:00:00Z"))).toBe("2026-12");
    expect(() => monthRange("Sept")).toThrow(/YYYY|2026-09/);
  });

  it("parses skills.sh and dependents pages strictly", () => {
    expect(parseSkillsInstalls(SKILLS_HTML)).toBe(1234);
    expect(parseSkillsInstalls("<span>Installs</span></div><div>12k</div>")).toBeNull();
    expect(parseSkillsInstalls(SKILLS_HTML + SKILLS_HTML.replace("1,234", "9"))).toBeNull(); // ambiguous
    expect(parseSkillsInstalls("")).toBeNull();
    expect(parseDependents(DEPENDENTS_HTML)).toBe(42);
    expect(parseDependents("<a>no count</a>")).toBeNull();
  });

  it("collects every metric from injected fetchers", async () => {
    const io = fakeIo();
    const s = await collectStats({ month: "2026-09", repo: "o/r", ...io });
    expect(s).toEqual({ month: "2026-09", npmDownloads: 3456, stars: 120, forks: 9, skillsInstalls: 1234, dependents: 42, prsMerged: 7 });
    const search = io.calls.find((c) => c.args.includes("search/issues"));
    expect(search.args.join(" ")).toContain("merged:2026-09-01..2026-09-30");
  });

  it("leaves a number out when its source fails instead of guessing", async () => {
    const s = await collectStats({ month: "2026-09", repo: "o/r", ...fakeIo({ fail: ["npm", "skills", "gh"] }) });
    expect(s).toMatchObject({ npmDownloads: null, skillsInstalls: null, stars: null, prsMerged: null, dependents: 42 });
    expect(formatIssue(s, null).body).toContain("| npm downloads (month) | n/a | – |");
  });

  it("formats the issue with deltas from the previous issue's hidden data", () => {
    const prev = { month: "2026-08", npmDownloads: 3000, stars: 100, forks: 9, skillsInstalls: null, dependents: 40, prsMerged: 9 };
    const cur = { month: "2026-09", npmDownloads: 3456, stars: 120, forks: 9, skillsInstalls: 1234, dependents: 42, prsMerged: 7 };
    const { title, body } = formatIssue(cur, prev);
    expect(title).toBe("Penthera this month: September 2026");
    expect(body).toContain("| npm downloads (month) | 3,456 | +456 |");
    expect(body).toContain("| GitHub stars | 120 | +20 |");
    expect(body).toContain("| Forks | 9 | ±0 |");
    expect(body).toContain("| skills.sh installs | 1,234 | – |");
    expect(body).toContain("| PRs merged (month) | 7 | -2 |");
    expect(parsePrevious(body)).toEqual(cur);
    expect(statsPost(cur, prev)).toContain("120 stars (+20)");
  });

  it("finds the most recent earlier stats issue", () => {
    const mk = (month, created) => ({ created_at: created, body: `x <!-- penthera-stats ${JSON.stringify({ month })} -->` });
    const issues = [mk("2026-07", "2026-08-01"), mk("2026-08", "2026-09-01"), { created_at: "2026-09-15", body: "unrelated" }, mk("2026-09", "2026-10-01")];
    expect(findPrevious(issues, "2026-09").month).toBe("2026-08");
    expect(findPrevious([], "2026-09")).toBeNull();
  });

  it("opens one issue, never a duplicate, and nothing on a dry run", async () => {
    const io = fakeIo();
    const r = await runMonthly({ repo: "o/r", month: "2026-09", ...io, log: () => {} });
    expect(r.created).toBe(true);
    const post = io.calls.find((c) => c.input);
    expect(JSON.parse(post.input)).toMatchObject({ title: "Penthera this month: September 2026", labels: ["monthly-stats"] });

    const dup = fakeIo({ issues: [{ title: "Penthera this month: September 2026", body: "" }] });
    expect((await runMonthly({ repo: "o/r", month: "2026-09", ...dup, log: () => {} })).created).toBe(false);
    expect(dup.calls.some((c) => c.input)).toBe(false);

    const dry = fakeIo();
    await runMonthly({ repo: "o/r", month: "2026-09", dryRun: true, ...dry, log: () => {} });
    expect(dry.calls.some((c) => c.input)).toBe(false);
  });
});

const adv = (id, name, { eco = "npm", published = "2026-10-19T05:00:00Z", range = ">= 0" } = {}) => ({
  ghsa_id: id, html_url: `https://github.com/advisories/${id}`, summary: `Malware in ${name}`, severity: "critical",
  published_at: published, withdrawn_at: null,
  vulnerabilities: [{ package: { ecosystem: eco, name }, vulnerable_version_range: range }],
});

describe("incident radar", () => {
  const ids = Array.from({ length: 8 }, (_, i) => `GHSA-aaaa-bbbb-000${i}`);
  const popular = new Set(["chalk", "debug"]);

  it("collects seen GHSA ids from any text", () => {
    expect([...seenIds(["see ghsa-aaaa-bbbb-0001 and GHSA-aaaa-bbbb-0002", null])]).toEqual(["GHSA-AAAA-BBBB-0001", "GHSA-AAAA-BBBB-0002"]);
  });

  it("notable mode: own issues for popular packages, the rest batched", () => {
    const advisories = [adv(ids[0], "typo-thing"), adv(ids[1], "chalk", { range: "= 5.6.1" }), adv(ids[2], "debug"), adv(ids[3], "x", { eco: "pip" })];
    const { individual, batch } = plan(advisories, { seen: seenIds([ids[2]]), popular });
    expect(individual.map((a) => a.ghsa_id)).toEqual([ids[1]]);
    expect(batch.map((a) => a.ghsa_id).sort()).toEqual([ids[0], ids[3]].sort());
  });

  it("all mode: at most 5 issues per run, the rest batched, withdrawn skipped", () => {
    const advisories = ids.map((id, i) => adv(id, `pkg-${i}`, { published: `2026-10-19T0${i}:00:00Z` }));
    advisories[7].withdrawn_at = "2026-10-19T09:00:00Z";
    const { individual, batch } = plan([...advisories, advisories[0]], { seen: new Set(), popular, mode: "all", cap: 5 });
    expect(individual).toHaveLength(5);
    expect(individual[0].ghsa_id).toBe(ids[6]); // newest first
    expect(batch).toHaveLength(2);
  });

  it("issue has the link, packages, checklist and a draft post", () => {
    const a = adv(ids[1], "chalk", { range: "= 5.6.1" });
    expect(issueTitle(a)).toBe(`Incident radar: malware in chalk (npm) · ${ids[1]}`);
    const body = issueBody(a, { rulesDir: true, notable: true });
    expect(body).toContain(`**Advisory:** https://github.com/advisories/${ids[1]}`);
    expect(body).toContain("| npm | `chalk` | `= 5.6.1` |");
    expect(body).toContain("rule pack in `lib/rules/`");
    expect(body).toContain("- [ ] Verify `penthera deps` flags it");
    expect(body).toContain("npx penthera deps .");
    expect(issueBody(a, { rulesDir: false })).toContain("no `lib/rules/` yet");
    expect(issueTitle(adv(ids[0], "evil", { eco: "pip" }))).toContain("(PyPI)");
  });

  it("runs end to end: dedupes against issues and radar comments, caps, batches", async () => {
    const posted = [];
    const gh = (args, { input } = {}) => {
      const path = args.find((a) => a.startsWith("/advisories") || a.startsWith("repos/"));
      if (input) { posted.push({ path, body: JSON.parse(input) }); return { number: 7 }; }
      if (path.startsWith("/advisories")) {
        return path.includes("ecosystem=npm")
          ? [[adv(ids[0], "chalk"), adv(ids[1], "debug")], [adv(ids[2], "typo"), adv(ids[5], "old", { published: "2026-10-01T00:00:00Z" })]]
          : [adv(ids[3], "pypkg", { eco: "pip" }), adv(ids[4], "seen-in-comment", { eco: "pip" })];
      }
      if (path.includes("/issues/comments?")) return [{ body: `${BATCH_MARKER}\n${ids[4]}` }, { body: `${ids[2]} quoted by a person` }];
      if (path.includes("state=all")) return [{ title: `Incident radar: malware in debug (npm) · ${ids[1]}`, body: "" }];
      if (path.includes("state=open")) return [];
      throw new Error(`unexpected ${path}`);
    };
    const out = await runRadar({ gh, repo: "o/r", now: new Date("2026-10-19T06:00:00Z"), popular, log: () => {} });
    expect(out.individual.map((i) => i.title)).toEqual([`Incident radar: malware in chalk (npm) · ${ids[0]}`]);
    // typo (a person quoting an id does not count as seen) and pypkg are batched; old is outside the window.
    expect(out.batch).toContain(ids[2]);
    expect(out.batch).toContain(ids[3]);
    expect(out.batch).not.toContain(ids[5]);
    expect(posted.map((p) => p.path)).toEqual(["repos/o/r/issues", "repos/o/r/issues", "repos/o/r/issues/7/comments"]);
    expect(posted[0].body.labels).toEqual(["incident-radar"]);
    expect(posted[1].body.title).toBe(BATCH_TITLE);
  });

  it("dry run posts nothing", async () => {
    let wrote = false;
    const gh = (args, { input } = {}) => {
      if (input) wrote = true;
      return args.some((a) => a.startsWith("/advisories?type=malware&ecosystem=npm")) ? [adv(ids[0], "chalk")] : [];
    };
    const out = await runRadar({ gh, repo: "o/r", now: new Date("2026-10-19T06:00:00Z"), popular, dryRun: true, log: () => {} });
    expect(out.individual).toHaveLength(1);
    expect(wrote).toBe(false);
  });

  it("batch comment lists each advisory once per package name", () => {
    const a = adv(ids[0], "dup");
    a.vulnerabilities.push({ package: { ecosystem: "npm", name: "dup" }, vulnerable_version_range: "= 2.0.0" });
    const c = batchComment([a], { date: "2026-10-19" });
    expect(c.startsWith(BATCH_MARKER)).toBe(true);
    expect(c).toContain("| `dup` | `>= 0`, `= 2.0.0` |");
  });
});

describe("contributor flywheel", () => {
  const grep = [
    "src/a.js:12:  // TODO(good-first-issue): handle the empty case",
    "lib/b.js:3: * TODO(good-first-issue) - document the option */",
    "src/c.js:9:  // TODO: not for newcomers",
  ].join("\n");

  it("parses markers from git grep output", () => {
    expect(parseMarkers(grep)).toEqual([
      { file: "src/a.js", line: 12, text: "handle the empty case" },
      { file: "lib/b.js", line: 3, text: "document the option" },
    ]);
  });

  it("does nothing with enough good first issues, creates then updates the reminder otherwise", () => {
    const markers = parseMarkers(grep);
    const writes = [];
    const make = (gfi, reminders) => (args, { input } = {}) => {
      if (input) { writes.push({ args, body: JSON.parse(input) }); return {}; }
      return args[1].includes("good%20first%20issue") ? gfi : reminders;
    };
    const three = [{}, {}, {}];
    expect(runFlywheel({ gh: make(three, []), repo: "o/r", markers, log: () => {} }).action).toBe("none");
    expect(runFlywheel({ gh: make([{}, { pull_request: {} }], []), repo: "o/r", markers, log: () => {} }).action).toBe("created");
    expect(writes[0].body.body).toContain("[`src/a.js:12`](https://github.com/o/r/blob/main/src/a.js#L12): handle the empty case");
    const existing = [{ number: 4, body: `${FLYWHEEL_MARKER} old` }];
    expect(runFlywheel({ gh: make([], existing), repo: "o/r", markers, log: () => {} }).action).toBe("updated");
    expect(writes[1].args).toContain("repos/o/r/issues/4");
  });

  it("asks for markers when none are left", () => {
    expect(reminderBody([], { open: 0, min: 3, repo: "o/r" })).toContain("No `TODO(good-first-issue)` markers left");
  });
});

describe("workflows", () => {
  const dir = ".github/workflows";
  const files = readdirSync(dir).filter((f) => f.endsWith(".yml"));
  const SHA = /^[\w.-]+\/[\w.-]+(\/[\w./-]+)?@[0-9a-f]{40}$/;

  for (const f of files) {
    it(`${f} parses, has triggers, permissions and SHA-pinned actions`, () => {
      const wf = YAML.parse(readFileSync(`${dir}/${f}`, "utf-8"));
      expect(wf.name, f).toBeTruthy();
      expect(wf.on, f).toBeTruthy();
      expect(wf.permissions, `${f}: top-level permissions`).toBeTruthy();
      expect(Object.keys(wf.jobs || {}).length, f).toBeGreaterThan(0);
      for (const [name, job] of Object.entries(wf.jobs)) {
        expect(job["runs-on"] || job.uses, `${f}:${name}`).toBeTruthy();
        for (const step of job.steps || []) {
          if (step.uses && !step.uses.startsWith("./")) expect(step.uses, `${f}:${name}`).toMatch(SHA);
        }
      }
    });
  }

  it("marketing workflows hold no social-media tokens and only least-privilege scopes", () => {
    const marketing = ["incident-radar.yml", "monthly-stats.yml", "contributor-flywheel.yml", "demo-media.yml"];
    for (const f of marketing) {
      const text = readFileSync(`${dir}/${f}`, "utf-8");
      expect(text, f).not.toMatch(/secrets\.(?!GITHUB_TOKEN)/);
      const wf = YAML.parse(text);
      expect(wf.permissions, f).toEqual(f === "demo-media.yml" ? { contents: "read" } : { contents: "read", issues: "write" });
    }
  });
});
