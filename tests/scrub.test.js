/**
 * One secret scrubber for every output (lib/scrub.js). Each test plants a key
 * of every known shape in a scan result and checks that no output carries it:
 * the terminal report, --quiet, JSON, Markdown, SARIF, the audience reports,
 * the evidence bundle, the brief, the share card, MCP results, errors and logs.
 *
 * The keys are built from parts at run time, so this file holds none whole.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { scrubSecrets, scrubDeep, SCRUB_MARGIN } from "../lib/scrub.js";
import { printReport, printFindings, printError, createProgress, formatJson, formatSarif } from "../src/reporter.js";
import { formatMarkdownReport } from "../src/report/markdown.js";
import { formatAudienceReport, AUDIENCES } from "../src/report/audience.js";
import { buildBrief, formatBrief } from "../src/report/brief.js";
import { buildResult, callResult, errorResult, cleanText } from "../src/mcp/results.js";
import { serve } from "../src/mcp/server.js";
import { buildCardModel, publicText } from "../src/card/model.js";
import { writeEvidence, customReport } from "../src/cli/report-outputs.js";
import { parseTemplate } from "../src/report/template.js";
import { compareFindings } from "../src/cli/baseline.js";

const b64url = (s) => Buffer.from(s).toString("base64url");
const alnum = (n, seed = 7) => Array.from({ length: n }, (_, i) => "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0"[(i * seed + 3) % 30]).join("");

// name -> the whole secret as it would sit in a file.
const KEYS = {
  "Stripe live": "sk_" + "live_" + alnum(24),
  "Stripe restricted": "rk_" + "live_" + alnum(24, 11),
  "Stripe test": "sk_" + "test_" + alnum(24, 13),
  "Stripe webhook": "whsec" + "_" + alnum(32),
  GitHub: "gh" + "p_" + alnum(36),
  "GitHub fine-grained": "github" + "_pat_" + alnum(82, 17),
  AWS: "AK" + "IA" + "Z7X3Q9P2M4N6B8V1",
  OpenAI: "sk-" + "proj-" + alnum(40),
  Anthropic: "sk-" + "ant-api03-" + alnum(48),
  Google: "AI" + "za" + alnum(35),
  Groq: "gs" + "k_" + alnum(52),
  "Hugging Face": "h" + "f_" + alnum(36),
  "Supabase JWT": [b64url('{"alg":"HS256","typ":"JWT"}'), b64url('{"role":"service_role","iss":"supabase","ref":"abcdefghijkl"}'), alnum(43)].join("."),
  "Supabase secret": "sb_" + "secret_" + alnum(32),
  Slack: "xo" + "xb-" + "1234567890-" + alnum(24),
  npm: "np" + "m_" + alnum(36),
  GitLab: "gl" + "pat-" + alnum(20),
  SendGrid: "S" + "G." + alnum(22) + "." + alnum(43, 19),
  "Vercel Blob": "vercel" + "_blob_rw_" + alnum(16) + "_" + alnum(30),
  "Private key": "-----BEGIN RSA PRIVATE KEY-----\n" + Array.from({ length: 4 }, (_, i) => alnum(64, 3 + i)).join("\n") + "\n-----END RSA PRIVATE KEY-----",
};
// Not a shape of its own: the password inside a connection string, the token after Bearer.
const URL_PASSWORD = "Pw" + alnum(18, 23);
const BEARER_TOKEN = alnum(40, 29);
const EXTRA = {
  "URL password": [`postgres://app:${URL_PASSWORD}@db.internal:5432/app`, URL_PASSWORD],
  Bearer: [`Authorization: Bearer ${BEARER_TOKEN}`, BEARER_TOKEN],
};

// What must never show: the middle of each key (masks keep at most the first and last 4).
const LEAKS = [
  ...Object.entries(KEYS).map(([name, k]) => [name, k.includes("\n") ? k.split("\n")[1] : k.slice(5, -5)]),
  ...Object.entries(EXTRA).map(([name, [, secret]]) => [name, secret.slice(2, -2)]),
];
const PLANTED = [...Object.values(KEYS), ...Object.values(EXTRA).map(([text]) => text)];

function expectClean(out, where) {
  const leaked = LEAKS.filter(([, s]) => out.includes(s)).map(([name]) => name);
  expect(leaked, `${where} leaked`).toEqual([]);
}

/** A repo scan result whose findings carry every planted secret, in every field a report prints. */
function plantedResult() {
  const findings = PLANTED.map((secret, i) => ({
    severity: i % 2 ? "high" : "critical",
    confidence: "likely",
    source: "static-analysis",
    category: "code-pattern",
    title: `Leak ${i} ${secret}`,
    description: `The config holds ${secret} on line ${i + 1}.`,
    remediation: `Remove ${secret} and rotate it.`,
    url: `src/file${i}.js`,
    file: `src/file${i}.js`,
    line: i + 1,
    evidence: secret,
    fid: `f${String(i).padStart(11, "0")}`,
  }));
  return {
    target: "/repo",
    mode: "repo",
    modes: ["repo"],
    timestamp: "2026-11-10T00:00:00.000Z",
    findings,
    errors: [{ probe: "x", message: `failed with ${KEYS.GitHub}`, url: EXTRA["URL password"][0] }],
    notChecked: [`A note that quotes ${KEYS["Stripe live"]}`],
  };
}

function capture(stream, fn) {
  let out = "";
  const spy = vi.spyOn(process[stream], "write").mockImplementation((s) => { out += String(s); return true; });
  try { fn(); } finally { spy.mockRestore(); }
  return out;
}

afterEach(() => vi.restoreAllMocks());

describe("scrubSecrets", () => {
  it.each(Object.entries(KEYS))("masks a %s key", (_, key) => {
    const out = scrubSecrets(`before ${key} after`);
    expect(out.startsWith("before ")).toBe(true);
    expect(out.endsWith(" after")).toBe(true);
    expect(out).not.toContain(key.includes("\n") ? key.split("\n")[1] : key.slice(5, -5));
  });

  it("masks the password in a URL and the token after Bearer, and keeps the rest", () => {
    expect(scrubSecrets(EXTRA["URL password"][0])).toBe("postgres://app:***@db.internal:5432/app");
    expect(scrubSecrets(EXTRA.Bearer[0])).toBe("Authorization: Bearer ***");
  });

  it("masks as the reports do, and changes nothing the second time", () => {
    const once = scrubSecrets(`key ${KEYS["Stripe live"]}`);
    expect(once).toBe(`key ${KEYS["Stripe live"].slice(0, 4)}…${KEYS["Stripe live"].slice(-4)}`);
    expect(scrubSecrets(once)).toBe(once);
    for (const k of PLANTED) expect(scrubSecrets(scrubSecrets(k))).toBe(scrubSecrets(k));
  });

  it("leaves prose, paths, hashes and words that only contain a prefix alone", () => {
    for (const s of [
      "Possible secret in `src/a.js`: `sk_l…abcd`",
      "/Users/dev/projects/my-nextjs-app/src/app/api/route.ts",
      "sha256 3f786850e387550fdab836ed7e6dc881de23001b",
      "the risk-assessmentframeworkthing is fine",
      "Set STRIPE_SECRET_KEY in your environment.",
      "https://example.com/docs#section",
      "user@example.com",
    ]) expect(scrubSecrets(s)).toBe(s);
  });

  it("returns what is not a string as it is", () => {
    expect(scrubSecrets(null)).toBe(null);
    expect(scrubSecrets(42)).toBe(42);
  });

  it("is linear on a long run of JWT-like text", () => {
    const t0 = performance.now();
    scrubSecrets("eyJ".repeat(300_000));
    scrubSecrets(`eyJ${"a".repeat(500_000)}.eyJ${"b".repeat(500_000)}`);
    expect(performance.now() - t0).toBeLessThan(2000);
  });
});

describe("scrubDeep", () => {
  it("copies only what changes, and keeps everything else", () => {
    const clean = { a: [1, "x", { b: "y" }], c: null, d: true };
    expect(scrubDeep(clean)).toBe(clean);
    const dirty = { keep: { b: "y" }, list: ["x", `k ${KEYS.npm}`], n: 3 };
    const out = scrubDeep(dirty);
    expect(out).not.toBe(dirty);
    expect(out.keep).toBe(dirty.keep);
    expect(out.n).toBe(3);
    expect(out.list[1]).not.toContain(KEYS.npm);
    expect(dirty.list[1]).toContain(KEYS.npm); // the input is not changed
  });

  it("survives a cycle", () => {
    const a = { s: KEYS.GitLab };
    a.self = a;
    expect(scrubDeep(a).s).not.toContain(KEYS.GitLab);
  });
});

describe("every output masks every planted key", () => {
  it("the terminal report and --quiet", () => {
    const r = plantedResult();
    r.brief = buildBrief(r);
    expectClean(capture("stdout", () => printReport(r, { verbose: true, limit: `limit ${KEYS.AWS}` })), "terminal report");
    expectClean(capture("stdout", () => printFindings(r.findings)), "--quiet");
  });

  it("JSON (the -o report and --json)", () => {
    expectClean(formatJson(plantedResult()), "JSON");
  });

  it("Markdown, every audience report and a custom template", () => {
    const r = plantedResult();
    r.brief = buildBrief(r);
    expectClean(formatMarkdownReport(r, { version: "0.0.0" }), "Markdown");
    for (const a of AUDIENCES) expectClean(formatAudienceReport(r, a, { version: "0.0.0" }), `audience ${a}`);
    const template = parseTemplate("{{#each findings}}{{title}} {{description}}\n{{/each}}");
    expectClean(customReport(r, {}, { version: "0.0.0", template }), "custom template");
  });

  it("SARIF", () => {
    expectClean(JSON.stringify(formatSarif(plantedResult())), "SARIF");
  });

  it("the evidence bundle", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "penthera-scrub-")), "bundle");
    const r = plantedResult();
    r.brief = buildBrief(r);
    writeEvidence(r, { evidence: dir }, { version: "0.0.0", template: null, mdOpts: { version: "0.0.0" }, sbom: null, argv: [] });
    for (const f of readdirSync(dir)) expectClean(readFileSync(join(dir, f), "utf-8"), `evidence ${f}`);
  });

  it("the brief, as built and as read back from a file", () => {
    const r = plantedResult();
    const brief = buildBrief(r);
    expectClean(JSON.stringify(brief), "brief JSON");
    expectClean(formatBrief(brief), "brief Markdown");
    // A brief read from a report someone else wrote, with raw keys in it.
    const raw = JSON.parse(JSON.stringify(brief));
    raw.act_on[0].title = KEYS["Stripe live"];
    raw.first.action = `Rotate ${KEYS.Anthropic}`;
    expectClean(formatBrief(raw), "brief from a file");
  });

  it("the share card", () => {
    const r = plantedResult();
    const model = buildCardModel(buildBrief(r), [r], { version: "0.0.0", date: "2026-11-10" });
    expectClean(JSON.stringify(model), "card");
    for (const k of PLANTED) expectClean(publicText(`Fix ${k} now`, 200), "card text");
  });

  it("MCP results and tool errors", () => {
    const r = plantedResult();
    const built = buildResult({ tool: "scan_repo", target: ".", findings: r.findings, limits: [`limit ${KEYS.Groq}`], scan: { mode: "repo" } });
    const res = callResult(built);
    expectClean(JSON.stringify(res), "MCP result");
    expectClean(JSON.stringify(callResult({ structured: { raw: KEYS.Slack }, text: `text ${KEYS.SendGrid}` })), "MCP result, raw");
    expectClean(JSON.stringify(errorResult(`scan_repo failed: ${KEYS["Supabase JWT"]}`)), "MCP error");
  });

  it("the MCP server's logs and protocol errors", async () => {
    const input = new PassThrough();
    const lines = [];
    const logs = [];
    const done = serve({ input, write: (l) => lines.push(l), serverRoots: [tmpdir()], version: "0.0.0", log: (m) => logs.push(m) });
    // A request with an unsupported version: the error message quotes it.
    input.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": KEYS["Stripe live"] } } }) + "\n");
    input.end();
    await done;
    expectClean(lines.join("\n"), "MCP protocol");
    expectClean(logs.join("\n"), "MCP log");
  });

  it("error messages and progress lines", () => {
    expectClean(capture("stderr", () => printError(`Cannot read ${EXTRA["URL password"][0]} with ${KEYS.GitHub}`)), "printError");
    expectClean(capture("stderr", () => createProgress(false)(`Scanning with ${KEYS["Vercel Blob"]}`)), "progress");
  });
});

describe("redacting before any truncation", () => {
  it("masks a key that the MCP text cut would split", () => {
    for (const k of PLANTED) {
      const s = `${"x ".repeat(995)}${k} tail`;
      const out = cleanText(s, 2000);
      expect(out).toMatch(/cut at 2000 characters/);
      expectClean(out, "cleanText at the cut");
    }
  });

  it("masks a key that the card's cut would split", () => {
    for (const k of PLANTED) expectClean(publicText(`${"word ".repeat(70)}${k}`, 90), "card cut");
  });

  it("still cuts a very long text, and scrubs only a bounded window", () => {
    const long = "y".repeat(2000 + SCRUB_MARGIN + 10);
    expect(cleanText(long, 2000)).toBe(`${"y".repeat(2000)}… [cut at 2000 characters]`);
  });
});

describe("baselines compare through the scrubber", () => {
  it("a finding whose title held a raw key matches the scrubbed report of the same run", () => {
    const f = { source: "static-analysis", category: "x", title: `Key ${KEYS.npm}`, url: "a.js", severity: "high" };
    const saved = JSON.parse(formatJson({ findings: [f] }));
    const cmp = compareFindings([f], saved);
    expect(cmp.stats.newCount).toBe(0);
    expect(cmp.stats.unchangedCount).toBe(1);
  });
});
