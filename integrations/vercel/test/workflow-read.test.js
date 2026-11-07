// The workflow template's pass rule, run for real: Penthera's own scanner (scanUrl) scans a fake
// deployment that serves Vercel's bot challenge, one that is down, and a clean one; then the
// workflow's own step scripts run in bash on that report, with a fake curl that records what the
// relay step would send. Fail closed: only a report that proves the site was read can pass.
// Offline: fetch is a fake, DNS and TLS are mocked, and curl never leaves the machine.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// The repo's vendored YAML parser: no package to install.
import YAML from "../../../lib/vendor/yaml/index.js";

vi.mock("node:dns/promises", () => {
  const fail = async () => { throw Object.assign(new Error("dns disabled in tests"), { code: "ENOTFOUND" }); };
  return { resolveTxt: fail, resolveMx: fail, default: { resolveTxt: fail, resolveMx: fail } };
});
vi.mock("node:tls", () => {
  const connect = () => { throw new Error("tls disabled in tests"); };
  return { default: { connect }, connect };
});

const { scanUrl } = await import("../../../src/scan-url.js");
const { WORKFLOW_YAML } = await import("../lib/workflow.mjs");

const steps = YAML.parse(WORKFLOW_YAML).jobs.scan.steps;
const step = (id) => steps.find((s) => s.id === id);
const relayStep = steps.find((s) => s.name === "Report pass or fail to the Vercel check");
const HOST = "shop-abc123.vercel.app";
const TARGET = `https://${HOST}`;
const sha = (s) => createHash("sha256").update(s).digest("hex");

let dir;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "pv-read-")); });
afterEach(() => {
  vi.unstubAllGlobals();
  rmSync(dir, { recursive: true, force: true });
});

/** A fake deployment: "clean" serves a page, "challenge" Vercel's bot challenge, "down" nothing. */
function deployment(kind) {
  return vi.fn(async (input) => {
    const url = new URL(String(input));
    if (url.hostname !== HOST) return new Response("unavailable", { status: 503 });
    if (kind === "down") throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } });
    if (kind === "challenge") return new Response("<html>Vercel Security Checkpoint</html>", { status: 429, headers: { "content-type": "text/html", "x-vercel-mitigated": "challenge" } });
    if (url.pathname === "/") return new Response("<!doctype html><html><head><title>shop</title></head><body>shop</body></html>", { status: 200, headers: { "content-type": "text/html", "content-security-policy": "default-src 'self'", "x-frame-options": "DENY", "x-content-type-options": "nosniff" } });
    return new Response("not found", { status: 404 });
  });
}

/** Penthera's real report for a deployment of that kind, as the Action writes it. */
async function realReport(kind) {
  vi.stubGlobal("fetch", deployment(kind));
  const result = await scanUrl(TARGET, { timeout: 2_000, concurrency: 5, profile: "quick", skipRetireJs: true, skipParamDiscovery: true, offline: true });
  vi.unstubAllGlobals();
  const file = join(dir, `${kind}.json`);
  writeFileSync(file, JSON.stringify(result));
  return file;
}

/** Runs one step's script as GitHub does (bash -eo pipefail), with a fake curl. */
function runStep(script, env) {
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  const sent = join(dir, "sent.json");
  rmSync(sent, { force: true });
  // OIDC token requests get a token; the POST to the relay is recorded and answered like the relay.
  writeFileSync(join(bin, "curl"), `#!/usr/bin/env bash
out=""; data=""; url=""; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a" ;; --data) data="$a" ;; esac
  case "$a" in http*) url="$a" ;; esac
  prev="$a"
done
case "$url" in
  *audience=*) printf '{"value":"oidc-token"}' ;;
  */report) printf '%s' "$data" > "${sent}"; c=$(printf '%s' "$data" | jq -r .conclusion); printf '{"ok":true,"conclusion":"%s"}' "$c" > "$out"; printf 200 ;;
  *) printf 200 ;;
esac
`);
  chmodSync(join(bin, "curl"), 0o755);
  const output = join(dir, "github-output");
  writeFileSync(output, "");
  const r = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", "-c", script], {
    encoding: "utf-8",
    env: { PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: dir, GITHUB_OUTPUT: output, ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.example.test/?x=1", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "req", ...env },
  });
  const outputs = Object.fromEntries(readFileSync(output, "utf-8").split("\n").filter(Boolean).map((l) => l.split("=")));
  return { ...r, outputs, sent: existsSync(sent) ? JSON.parse(readFileSync(sent, "utf-8")) : null };
}

/** The workflow from the scan on: the read check, then the relay step with the outcome GitHub would give it. */
function afterScan(report) {
  const read = runStep(step("read").run, { REPORT: report });
  const relay = runStep(relayStep.run, {
    SCAN_OUTCOME: read.status === 0 ? "success" : "failure",
    REASON: read.outputs.reason ?? "",
    SCANNED: TARGET,
    DEPLOYMENT_ID: "dpl_abc",
    PROJECT_ID: "prj_abc",
    RELAY: "https://vercel.penthera.example.test",
  });
  return { read, relay };
}

describe("the workflow reports succeeded only when the report proves the site was read", () => {
  it("a deployment that serves Vercel's bot challenge: the scan passes, the read check fails, the relay sends failed with the reason", async () => {
    const report = await realReport("challenge");
    expect(JSON.parse(readFileSync(report, "utf-8"))).toMatchObject({ reachable: true, challenge: { provider: "Vercel", action: "challenge" } });
    const { read, relay } = afterScan(report);
    expect(read.status).toBe(1);
    expect(read.stdout).toContain("::error::Site not read (challenge)");
    expect(relay.status, relay.stderr).toBe(0);
    expect(relay.sent).toEqual({ deploymentId: "dpl_abc", projectId: "prj_abc", conclusion: "failed", hostSha256: sha(HOST), reason: "challenge" });
  });

  it("a deployment that is down: failed, unreachable", async () => {
    const report = await realReport("down");
    expect(JSON.parse(readFileSync(report, "utf-8")).reachable).toBe(false);
    const { read, relay } = afterScan(report);
    expect(read.status).toBe(1);
    expect(relay.sent).toMatchObject({ conclusion: "failed", reason: "unreachable" });
  });

  it("a clean deployment the scan read: succeeded, with the hash of the scanned host and no reason", async () => {
    const report = await realReport("clean");
    const { read, relay } = afterScan(report);
    expect(read.status, read.stdout + read.stderr).toBe(0);
    expect(relay.sent).toEqual({ deploymentId: "dpl_abc", projectId: "prj_abc", conclusion: "succeeded", hostSha256: sha(HOST) });
    expect(relay.stdout).toContain("Reported succeeded to the Vercel check.");
  });

  it("every other report that does not prove a read fails, also one that is missing or not JSON", () => {
    const read = ["endpoint-discovery"];
    const cases = [
      // A production app that redirects its *.vercel.app host to its own domain: nothing of this deployment was read.
      [{ reachable: true, httpStatus: 308, executedProbes: read, findings: [] }, "redirected"],
      [{ reachable: true, httpStatus: 301, executedProbes: read, findings: [] }, "redirected"],
      [{ reachable: true, httpStatus: 429, executedProbes: read, findings: [] }, "status"],
      [{ reachable: true, httpStatus: 410, executedProbes: read, findings: [] }, "status"],
      [{ reachable: true, httpStatus: "200", executedProbes: read, findings: [] }, "incomplete"],
      [{ reachable: true, httpStatus: 200, executedProbes: read, findings: [], endpoints: { byStatus: { 200: 3, 429: 40 } } }, "rate_limited"],
      [{ reachable: true, httpStatus: 200, executedProbes: "x-endpoint-discovery", findings: [] }, "incomplete"],
      [{ reachable: true, httpStatus: 401, executedProbes: ["endpoint-discovery"], findings: [] }, "denied"],
      [{ reachable: true, httpStatus: 403, executedProbes: ["endpoint-discovery"], findings: [] }, "denied"],
      [{ reachable: true, httpStatus: 403, executedProbes: ["endpoint-discovery"], findings: [{ source: "waf-challenge" }] }, "denied"],
      [{ reachable: true, httpStatus: 200, executedProbes: ["endpoint-discovery"], findings: [{ source: "waf-challenge" }] }, "blocked"],
      [{ reachable: true, httpStatus: 200, executedProbes: ["reachability"], findings: [] }, "incomplete"],
      [{ reachable: true, httpStatus: 200 }, "incomplete"],
      [{}, "incomplete"],
      [[1], "unreadable"],
      ["text", "unreadable"],
    ];
    for (const [report, reason] of cases) {
      const file = join(dir, "r.json");
      writeFileSync(file, JSON.stringify(report));
      const read = runStep(step("read").run, { REPORT: file });
      expect(read.status, JSON.stringify(report)).toBe(1);
      expect(read.outputs.reason, JSON.stringify(report)).toBe(reason);
    }
    for (const bad of [join(dir, "missing.json"), (writeFileSync(join(dir, "bad.json"), "{not json"), join(dir, "bad.json"))]) {
      const read = runStep(step("read").run, { REPORT: bad });
      expect(read.status).toBe(1);
      expect(read.outputs.reason).toBe("unreadable");
    }
  });

  it("the relay step counts only the read check's outcome, which is skipped (so failed) when the scan failed", () => {
    expect(step("read").if).toBe("steps.penthera.outcome == 'success'");
    expect(relayStep.env.SCAN_OUTCOME).toBe("${{ steps.read.outcome }}");
    for (const outcome of ["skipped", "failure", "cancelled", ""]) {
      const relay = runStep(relayStep.run, { SCAN_OUTCOME: outcome, REASON: "", SCANNED: TARGET, DEPLOYMENT_ID: "dpl_abc", PROJECT_ID: "prj_abc", RELAY: "https://vercel.penthera.example.test" });
      expect(relay.sent.conclusion, outcome).toBe("failed");
    }
  });
});

describe("the URL check takes a whole-string *.vercel.app host only", () => {
  it("refuses a host with a second line, a path or a lookalike, before any request", () => {
    for (const url of [`https://evil.example.test\n${HOST}`, `https://${HOST}\nevil.example.test`, "https://evil.test/x.vercel.app", "https://a.b.vercel.app", "https://shop.vercel.app.evil.test"]) {
      const r = runStep(step("target").run, { DEPLOYMENT_URL: url });
      expect(r.status, JSON.stringify(url)).toBe(2);
      expect(r.outputs.url, JSON.stringify(url)).toBeUndefined();
    }
    expect(runStep(step("target").run, { DEPLOYMENT_URL: TARGET }).outputs.url).toBe(TARGET);
  });

  it("the relay step refuses ids with a second line before asking GitHub for a token", () => {
    for (const [d, p] of [["dpl_abc\ndpl_x", "prj_abc"], ["dpl_abc", "prj_abc\nprj_x"]]) {
      const r = runStep(relayStep.run, { SCAN_OUTCOME: "success", REASON: "", SCANNED: TARGET, DEPLOYMENT_ID: d, PROJECT_ID: p, RELAY: "https://vercel.penthera.example.test" });
      expect(r.status).toBe(1);
      expect(r.sent).toBeNull();
    }
  });
});
