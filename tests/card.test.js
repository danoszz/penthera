import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync, symlinkSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { spawnSync } from "node:child_process";
import { buildBrief, VERDICTS } from "../src/report/brief.js";
import { runBrief } from "../src/cli/brief.js";
import { buildCardModel, publicText } from "../src/card/model.js";
import { renderCards, writeCards, CardWriteError } from "../src/card/index.js";
import { postLayout, ogLayout, SIZES } from "../src/card/layout.js";
import { toSvg, rasterize, pathPolygons } from "../src/card/draw.js";
import { encodePng } from "../src/card/png.js";
import { GLYPHS } from "../src/card/font.js";

const ROOT = join(import.meta.dirname, "..");
const FIXTURES = join(ROOT, "tests", "fixtures", "card");
const UPDATE = process.env.UPDATE_CARD_FIXTURES === "1";
const VERSION = "2.4.2";
const DATE = "2026-11-08";
const sha = (b) => createHash("sha256").update(b).digest("hex");

const f = (o) => ({ severity: "high", confidence: "likely", category: "secrets", source: "secret-scan", title: "Hardcoded password in source", description: "Possible secret.", ...o });
const coverage = (files) => ({
  files, truncated: false,
  families: [
    { id: "secrets", label: "Secret scan", ran: true, examined: files, skipped: {} },
    { id: "routes", label: "Route and code-pattern analysis", ran: true, examined: files, skipped: {} },
  ],
  notRun: [],
});
const repo = (findings, extra = {}) => ({ target: "/Users/someone/work/my-saas-app", mode: "repo", findings, coverage: coverage(214), ...extra });
const deps = (extra = {}) => ({ target: "/Users/someone/work/my-saas-app", mode: "deps", findings: [], deps: { total: 312, scanned: 312, notInstalled: [], ecosystem: "npm" }, ...extra });
const agents = (extra = {}) => ({ target: "/Users/someone/work/my-saas-app", mode: "agents", findings: [], agents: { grade: "A", unparsed: 0, inventory: { configFiles: ["a", "b", "c", "d"] }, notChecked: [] }, ...extra });

// The three states the card must never blur: something to fix, nothing found, and a site it could not read.
const STATES = {
  findings: [
    repo([
      f({ url: "src/lib/supabase.ts", line: 4, severity: "critical", title: "Supabase service-role key in src/lib/supabase.ts", remediation: "Move the key to a server-only environment variable, then rotate it in the Supabase dashboard." }),
      f({ url: "app/api/upload/route.ts", line: 12, category: "code-pattern", title: "command-injection in app/api/upload/route.ts", remediation: "Use execFile with an argument array." }),
      f({ url: "app/api/admin/route.ts", line: 3, category: "auth", title: "Route without an auth check in app/api/admin/route.ts" }),
    ]),
    deps(),
    agents(),
  ],
  clean: [
    repo([]), deps(), agents(),
    { target: "https://my-saas-app.com", mode: "url", reachable: true, httpStatus: 200, findings: [] },
  ],
  unread: [
    { target: "https://my-saas-app.com", mode: "url", reachable: true, httpStatus: 403, challenge: { provider: "Vercel" }, findings: [] },
  ],
  // An agent-config audit alone, shaped like `penthera agents` on a setup with a hidden instruction.
  agents: [
    agents({
      target: "/Users/someone/demo/agent-demo-bad",
      agents: { grade: "F", score: 0, unparsed: 0, inventory: { configFiles: [".mcp.json", ".claude/settings.json"] }, notChecked: ["MCP tool descriptions: servers are not started, so tool-description poisoning is not checked."] },
      findings: [
        f({ url: "skills/helper/SKILL.md", category: "agent-config", title: "Text addressed to a security scanner" }),
        f({ url: ".cursor/rules/style.mdc", severity: "critical", category: "agent-config", title: "Hidden text in Unicode tag characters", description: `Decoded: "inert". Raw: ${String.fromCodePoint(0xe0041, 0xe0042)}` }),
        f({ url: ".claude/settings.json", severity: "critical", category: "agent-config", title: "SessionStart hook downloads and runs code" }),
        f({ url: ".claude/settings.json", severity: "medium", category: "agent-config", title: "Broad permission" }),
        f({ url: "penthera.lock", severity: "info", category: "agent-config", title: "No penthera.lock" }),
      ],
    }),
  ],
};

const modelOf = (results) => buildCardModel(buildBrief(results), results, { version: VERSION, date: DATE });
const textsOf = (card) => card.ops.filter((o) => o.op === "text").map((o) => o.s);

describe("card model: the verdict is the brief's", () => {
  it("uses the brief's verdict for every state", () => {
    for (const results of Object.values(STATES)) {
      expect(modelOf(results).verdict).toBe(buildBrief(results).verdict);
    }
  });

  it("findings: the number to fix first and the top fix", () => {
    const m = modelOf(STATES.findings);
    expect(m.verdict).toBe(VERDICTS.fix);
    expect(m.hero).toEqual({ value: "3", label: "to fix first" });
    expect(m.top.title).toBe("Supabase service-role key");
    expect(m.top.fix).toMatch(/^Move the key/);
    expect(m.checked.map((c) => c.state)).toEqual(["read", "read", "read", "not-run"]);
  });

  it("clean: zero to fix, and it still lists what was not proven", () => {
    const m = modelOf(STATES.clean);
    expect(m.verdict).toBe(VERDICTS.clean);
    expect(m.hero.value).toBe("0");
    expect(m.top).toBeNull();
    expect(m.notChecked).toContain("Login, access rules and payments: not proven");
  });

  it("site not read: a question mark, never a zero", () => {
    const m = modelOf(STATES.unread);
    expect(m.verdict).toBe(VERDICTS.unread);
    expect(m.hero.value).toBe("?");
    expect(m.checked.find((c) => c.id === "site").state).toBe("unread");
    expect(m.notChecked[0]).toMatch(/couldn't see your site/);
  });

  it("nothing to assess: a question mark, never a zero", () => {
    const empty = [{ target: "/x/empty", mode: "repo", findings: [], coverage: { files: 0, families: [{ id: "secrets", label: "Secret scan", ran: true, examined: 0, skipped: {} }], notRun: [] } }];
    const m = modelOf(empty);
    expect(m.verdict).toBe(VERDICTS.none);
    expect(m.hero.value).toBe("?");
    expect(m.notChecked.join(" ")).toMatch(/not a clean result/);
  });

  it("suppressed findings are the big number, not a clean zero", () => {
    const results = [repo([], { suppressed: [f({ severity: "critical" }), f({})] })];
    const m = modelOf(results);
    expect(m.verdict).toMatch(/suppressed/);
    expect(m.hero).toEqual({ value: "2", label: "suppressed, not counted" });
    expect(m.notChecked.join(" ")).toMatch(/2 suppressed/);
  });

  it("agents: the grade leads, with its score, the not-read line and the most severe finding first", () => {
    const m = modelOf(STATES.agents);
    expect(m.target).toBe("agent-demo-bad");
    expect(m.verdict).toBe(VERDICTS.fix);
    expect(m.grade).toEqual({ letter: "F", score: 0 });
    expect(m.toFix).toEqual({ value: 4, label: "To fix first" });
    expect(m.checked.find((c) => c.id === "agents")).toMatchObject({ state: "read", detail: "2 files" });
    expect(m.top.title).toBe("Hidden text in Unicode tag characters");
    expect(m.notChecked[0]).toBe("MCP tool descriptions: servers are not started, so tool-description poisoning is not checked");
    // Only a repo or live-site run gets the login line, as in the brief.
    expect(m.notChecked.join(" ")).not.toMatch(/Login/);
    expect(m.command).toBe("npx penthera agents --card");
    const text = textsOf(postLayout(m)).join(" ");
    expect(text).toContain("0/100");
    expect(text).toContain("$ npx penthera agents --card");
  });

  it("no score is invented: repo and URL cards have no grade, and a mixed card keeps the count", () => {
    expect(modelOf(STATES.findings).grade).toBeNull();
    expect(modelOf(STATES.unread).grade).toBeNull();
    const mixed = [repo([]), agents({ agents: { grade: "B", score: 80, unparsed: 0, inventory: { configFiles: ["a"] }, notChecked: [] } })];
    const m = modelOf(mixed);
    expect(m.grade).toBeNull();
    expect(m.checked.find((c) => c.id === "agents").detail).toBe("B · 80/100");
    expect(m.command).toBe("npx penthera --card");
  });

  it("a grade never hides suppressed findings or unreadable config", () => {
    const sup = [agents({ agents: { grade: "A", score: 100, unparsed: 0, inventory: { configFiles: ["a"] }, notChecked: [] }, suppressed: [f({ severity: "critical" })] })];
    expect(modelOf(sup).grade).toBeNull();
    expect(modelOf(sup).hero.value).toBe("1");
    const broken = [agents({ agents: { grade: "A", score: 100, unparsed: 1, inventory: { configFiles: ["a"] }, notChecked: [] } })];
    expect(modelOf(broken).grade).toBeNull();
  });

  it("hidden characters never reach the card, in the image or its description", () => {
    const { post, og } = renderCards(modelOf(STATES.agents));
    for (const svg of [post.svg, og.svg]) expect(svg).not.toMatch(/[\u{e0000}-\u{e007f}]/u);
  });

  it("always says what was not checked", () => {
    for (const results of Object.values(STATES)) expect(modelOf(results).notChecked.length).toBeGreaterThan(0);
  });
});

describe("card model: safe to post", () => {
  it("shows the folder name, never the full path", () => {
    const m = modelOf(STATES.findings);
    expect(m.target).toBe("my-saas-app");
    const svg = renderCards(m).post.svg;
    expect(svg).not.toContain("/Users/");
    expect(svg).not.toContain("someone");
  });

  it("drops paths, URLs and key-shaped strings from titles and fixes", () => {
    // Fake keys are built at run time, so no key-shaped literal sits in the repo.
    const stripeLike = ["sk", "live", "51HxYzAbCdEfGh1234567890"].join("_");
    const githubLike = `${"ghp"}_${"a".repeat(34)}1`;
    expect(publicText(`Hardcoded key ${stripeLike} in src/config/stripe.ts:12`)).toBe("Hardcoded key [hidden]");
    expect(publicText(`Token ${githubLike} found`)).toBe("Token [hidden] found");
    expect(publicText("See https://example.com/x?token=abc and `rotate` it")).toBe("See and rotate it");
    expect(publicText("eval in apps/web/.next/server/chunk.js")).toBe("eval");
    expect(publicText("a\u0000b\u001bc")).toBe("a b c");
  });

  it("a secret in a finding's title never reaches the card", () => {
    const key = ["AKIA", "ABCDEFGHIJKLMNOP", "1234"].join("");
    const results = [repo([f({ severity: "critical", url: "x.js", title: `AWS key ${key} in x.js`, remediation: `Rotate ${key} now.` })])];
    const { post, og } = renderCards(modelOf(results));
    for (const svg of [post.svg, og.svg]) expect(svg).not.toContain(key);
    expect(JSON.stringify(modelOf(results))).not.toContain(key);
  });

  it("a megabyte-long repo-controlled title is cleaned in bounded time", () => {
    const t0 = performance.now();
    const out = publicText(`MCP server "${"a.".repeat(500_000)}" runs npx`, 90);
    expect(performance.now() - t0).toBeLessThan(500);
    expect(out.length).toBeLessThanOrEqual(90);
  });

  it("draws only characters the pixel font has", () => {
    for (const results of Object.values(STATES)) {
      for (const layout of [postLayout, ogLayout]) {
        for (const s of textsOf(layout(modelOf(results)))) {
          for (const ch of s) if (ch !== " ") expect(GLYPHS[ch.codePointAt(0)], `glyph for ${ch}`).toBeDefined();
        }
      }
    }
  });
});

describe("card layouts", () => {
  it("both sizes always carry the not-checked lines, and the last one is never dropped", () => {
    for (const results of Object.values(STATES)) {
      const m = modelOf(results);
      const last = m.notChecked[m.notChecked.length - 1].split(" ").slice(-2).join(" ");
      for (const layout of [postLayout, ogLayout]) {
        const text = textsOf(layout(m)).join(" ");
        expect(text).toContain("NOT CHECKED");
        expect(text).toContain(last);
      }
    }
  });

  it("everything stays inside the card, and the post's text inside the slip", () => {
    const long = modelOf(STATES.findings);
    long.notChecked = Array.from({ length: 9 }, (_, i) => `A long line about something not checked, number ${i}, that wraps`).concat("Login, access rules and payments: not proven");
    long.top.title = "A".repeat(80);
    for (const [layout, size] of [[postLayout, SIZES.post], [ogLayout, SIZES.og]]) {
      const card = layout(long);
      for (const o of card.ops) {
        if (o.op !== "text") continue;
        expect(o.x).toBeGreaterThanOrEqual(0);
        expect(o.x + [...o.s].length * 7 * o.k).toBeLessThanOrEqual(size.w);
        expect(o.y + 14 * o.k).toBeLessThanOrEqual(size.h);
      }
      expect(textsOf(card).join(" ")).toContain("not proven");
    }
  });

  it("keeps X's bottom-left corner of the link card free of text", () => {
    for (const results of Object.values(STATES)) {
      for (const o of ogLayout(modelOf(results)).ops) {
        if (o.op === "text" && o.x < 600) expect(o.y + 14 * o.k).toBeLessThanOrEqual(630 - 160);
      }
    }
  });
});

describe("card renderer", () => {
  it("writes a valid PNG whose pixels match the raster", () => {
    const card = { w: 3, h: 2, ops: [{ op: "rect", x: 0, y: 0, w: 3, h: 2, fill: "#0000ed" }, { op: "rect", x: 1, y: 0, w: 1, h: 1, fill: "#ffffff" }] };
    const { px } = rasterize(card);
    expect([...px.slice(0, 6)]).toEqual([0, 0, 237, 255, 255, 255]);
    const png = encodePng(3, 2, px);
    expect(png.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a");
    expect(png.readUInt32BE(16)).toBe(3);
    expect(png.readUInt32BE(20)).toBe(2);
    const idatLen = png.readUInt32BE(33);
    const raw = inflateSync(png.subarray(41, 41 + idatLen));
    expect([...raw]).toEqual([0, ...px.slice(0, 9), 0, ...px.slice(9)]);
  });

  it("parses the shipped wordmark into closed shapes", () => {
    const svg = readFileSync(join(ROOT, "src", "ui", "static", "logo.svg"), "utf8");
    const polys = [...svg.matchAll(/ d="([^"]+)"/g)].flatMap((m) => pathPolygons(m[1]));
    expect(polys.length).toBeGreaterThan(8);
  });

  it("escapes the SVG title and description", () => {
    const svg = toSvg({ w: 1, h: 1, ops: [], title: "<a & b>", desc: '"x"' });
    expect(svg).toContain("<title>&lt;a &amp; b&gt;</title>");
    expect(svg).toContain("<desc>&quot;x&quot;</desc>");
  });

  it("uses no network module and no dependency", () => {
    const dir = join(ROOT, "src", "card");
    for (const file of readdirSync(dir)) {
      const src = readFileSync(join(dir, file), "utf8");
      const imports = [...src.matchAll(/from "([^"]+)"/g)].map((m) => m[1]);
      for (const i of imports) expect(i.startsWith(".") || ["node:fs", "node:path", "node:url", "node:zlib", "node:crypto"].includes(i), `${file} imports ${i}`).toBe(true);
      expect(src).not.toMatch(/\bfetch\(|https?\.request|node:net|node:http/);
    }
  });
});

// Snapshot fixtures: the post card as SVG (open it to see it), plus hashes of
// the link card and of both rasters. UPDATE_CARD_FIXTURES=1 rewrites them.
describe("card snapshots", () => {
  const hashes = {};
  for (const [state, results] of Object.entries(STATES)) {
    it(`${state} matches its fixture`, () => {
      const cards = renderCards(modelOf(results));
      const svgFile = join(FIXTURES, `${state}.svg`);
      const got = {
        og_svg: sha(cards.og.svg),
        post_pixels: sha(rasterize(postLayout(modelOf(results))).px),
        og_pixels: sha(rasterize(ogLayout(modelOf(results))).px),
      };
      if (UPDATE) {
        mkdirSync(FIXTURES, { recursive: true });
        writeFileSync(svgFile, cards.post.svg);
        hashes[state] = got;
        const file = join(FIXTURES, "hashes.json");
        const all = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
        writeFileSync(file, JSON.stringify({ ...all, ...hashes }, null, 2) + "\n");
        return;
      }
      expect(cards.post.svg).toBe(readFileSync(svgFile, "utf8"));
      expect(got).toEqual(JSON.parse(readFileSync(join(FIXTURES, "hashes.json"), "utf8"))[state]);
    });
  }
});

describe("penthera brief --card", () => {
  it("writes the post and link cards, as PNG and SVG", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-card-"));
    const files = STATES.findings.map((r, i) => {
      const p = join(dir, `r${i}.json`);
      writeFileSync(p, JSON.stringify(r));
      return p;
    });
    const sink = { write() {} };
    expect(runBrief([...files, "--card-out", join(dir, "out", "card")], { out: sink, err: sink, version: VERSION, date: DATE })).toBe(0);
    for (const name of ["card.png", "card.svg", "card-og.png", "card-og.svg"]) expect(existsSync(join(dir, "out", name))).toBe(true);
    const png = readFileSync(join(dir, "out", "card.png"));
    expect([png.readUInt32BE(16), png.readUInt32BE(20)]).toEqual([1080, 1350]);
    expect(png.length).toBeLessThan(80_000);
  });

  it("writes nothing without --card", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-card-"));
    const p = join(dir, "r.json");
    writeFileSync(p, JSON.stringify(STATES.clean[0]));
    const sink = { write() {} };
    expect(runBrief([p], { out: sink, err: sink })).toBe(0);
    expect(readdirSync(dir)).toEqual(["r.json"]);
  });

  it("writeCards strips an extension from the output path", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-card-"));
    const { paths } = writeCards(buildBrief(STATES.clean), STATES.clean, { version: VERSION, out: join(dir, "x.png"), date: DATE });
    expect(paths.map((p) => p.slice(dir.length + 1)).sort()).toEqual(["x-og.png", "x-og.svg", "x.png", "x.svg"]);
  });
});

// A scanned checkout controls the folder the card lands in. Vercel finding
// 01M6XG3Z8WZKK62KD4D9KQ7GW4: a planted link must never be written through.
describe("card writes never follow a planted link", () => {
  const setup = () => {
    const root = mkdtempSync(join(tmpdir(), "penthera-card-link-"));
    const repo = join(root, "repo"), outside = join(root, "outside");
    mkdirSync(repo);
    mkdirSync(outside);
    const secret = join(outside, "keep.txt");
    writeFileSync(secret, "do not touch\n");
    return { root, repo, outside, secret };
  };
  const write = (out, cwd) => writeCards(buildBrief(STATES.clean), STATES.clean, { version: VERSION, date: DATE, out, cwd });

  it("a link planted at every card name stays a link's target untouched; the card replaces the link", () => {
    const { repo, secret } = setup();
    for (const name of ["penthera-card.png", "penthera-card.svg", "penthera-card-og.png", "penthera-card-og.svg"]) symlinkSync(secret, join(repo, name));
    const before = readFileSync(secret);
    write("penthera-card", repo);
    expect(readFileSync(secret)).toEqual(before);
    for (const name of ["penthera-card.png", "penthera-card.svg", "penthera-card-og.png", "penthera-card-og.svg"]) {
      expect(lstatSync(join(repo, name)).isSymbolicLink()).toBe(false);
      expect(lstatSync(join(repo, name)).isFile()).toBe(true);
    }
    expect(readdirSync(repo).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("refuses an output folder that is a link, inside the working directory", () => {
    const { repo, outside } = setup();
    symlinkSync(outside, join(repo, "reports"));
    expect(() => write("reports/card", repo)).toThrow(CardWriteError);
    expect(() => write("reports/card", repo)).toThrow(/reports is a symbolic link/);
    expect(readdirSync(outside)).toEqual(["keep.txt"]);
  });

  it("refuses a link in the middle of the path, even when the folder behind it exists", () => {
    const { repo, outside } = setup();
    mkdirSync(join(outside, "sub"));
    symlinkSync(outside, join(repo, "reports"));
    expect(() => write("reports/sub/card", repo)).toThrow(CardWriteError);
    // The same path given as an absolute path from somewhere else.
    expect(() => write(join(repo, "reports", "sub", "card"), mkdtempSync(join(tmpdir(), "penthera-cwd-")))).toThrow(CardWriteError);
    expect(readdirSync(join(outside, "sub"))).toEqual([]);
  });

  it("refuses a folder planted where a card file goes, before writing any card file", () => {
    const { repo } = setup();
    mkdirSync(join(repo, "penthera-card.svg"));
    expect(() => write("penthera-card", repo)).toThrow(/is a folder/);
    expect(readdirSync(repo).sort()).toEqual(["penthera-card.svg"]);
  });

  it("creates missing folders one level at a time", () => {
    const { repo } = setup();
    const { paths } = write("a/b/card", repo);
    expect(paths.every((p) => existsSync(p))).toBe(true);
  });

  it("penthera brief --card exits 2 with a clear line when the folder is a link", () => {
    const { repo, outside } = setup();
    symlinkSync(outside, join(repo, "reports"));
    const report = join(repo, "r.json");
    writeFileSync(report, JSON.stringify(STATES.clean[0]));
    let err = "";
    const code = runBrief([report, "--card-out", join(repo, "reports", "card")], { out: { write() {} }, err: { write: (t) => { err += t; } } });
    expect(code).toBe(2);
    expect(err).toMatch(/share card was not written: .*reports is a symbolic link/);
    expect(readdirSync(outside)).toEqual(["keep.txt"]);
  });
});

describe("--card on commands that cannot draw one", () => {
  const run = (args, cwd) => spawnSync(process.execPath, [join(ROOT, "bin", "penthera.js"), ...args], { cwd, encoding: "utf-8", env: { ...process.env, PENTHERA_NO_ONBOARDING: "1" } });
  it("penthera deps --card exits 2 instead of skipping the card", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-card-deps-"));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x" } } }));
    const r = run(["deps", ".", "--card"], dir);
    expect(r.status).toBe(2);
    expect(r.stderr + r.stdout).toMatch(/--card does not work with penthera deps/);
    expect(readdirSync(dir)).toEqual(["package-lock.json"]);
  });
  it("--baseline with -q refuses --card", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-card-base-"));
    writeFileSync(join(dir, "base.json"), JSON.stringify({ findings: [] }));
    const r = run(["--repo", ".", "--baseline", "base.json", "-q", "--card"], dir);
    expect(r.status).toBe(2);
    expect(r.stderr + r.stdout).toMatch(/--baseline with -q/);
  });
});
