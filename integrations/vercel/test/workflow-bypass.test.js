// The workflow template's Deployment Protection handling, run for real: each step's own script
// in bash (as GitHub runs it: -eo pipefail), with a fake curl that records its arguments and the
// header file it was given. Offline: nothing leaves the machine.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { WORKFLOW_YAML } from "../lib/workflow.mjs";

const steps = parse(WORKFLOW_YAML).jobs.scan.steps;
const step = (id) => steps.find((s) => s.id === id);
// Made at run time, so no secret-shaped string sits in the source.
const SECRET = randomBytes(16).toString("hex");
const SECRET_REF = "${{ secrets.VERCEL_AUTOMATION_BYPASS_SECRET }}";

let dir;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "pv-workflow-")); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** Runs one step's script with a fake curl that answers `code` and records what it got. */
function runStep(id, env, { code = "200" } = {}) {
  const bin = join(dir, "bin");
  const out = join(dir, "out");
  mkdirSync(bin, { recursive: true });
  mkdirSync(out, { recursive: true });
  writeFileSync(join(bin, "curl"), `#!/usr/bin/env bash
printf '%s\\n' "$@" > "${out}/argv"
prev=""
for a in "$@"; do
  if [ "$prev" = "-H" ] && [ "\${a#@}" != "$a" ]; then cp "\${a#@}" "${out}/header"; echo "\${a#@}" > "${out}/header-path"; fi
  prev="$a"
done
printf '%s' "${code}"
`);
  chmodSync(join(bin, "curl"), 0o755);
  const runner = join(dir, "runner");
  mkdirSync(runner, { recursive: true });
  const output = join(dir, "github-output");
  writeFileSync(output, "");
  const r = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", "-c", step(id).run], {
    encoding: "utf-8",
    env: { PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: runner, GITHUB_OUTPUT: output, ...env },
  });
  const read = (f) => (existsSync(join(out, f)) ? readFileSync(join(out, f), "utf-8") : null);
  return { ...r, output: readFileSync(output, "utf-8"), argv: read("argv"), header: read("header"), headerPath: read("header-path")?.trim() ?? null };
}

describe("the workflow and the Vercel bypass secret", () => {
  it("reads the secret only in the URL check and the Penthera step, never in the report to Penthera's server", () => {
    // The read check and the relay never see it: the read check in workflow-read.test.js.
    const users = steps.filter((s) => JSON.stringify(s).includes("VERCEL_AUTOMATION_BYPASS_SECRET")).map((s) => s.id);
    expect(users).toEqual(["target", "penthera"]);
    expect(step("target").env.BYPASS).toBe(SECRET_REF);
    expect(step("penthera").with["vercel-bypass-secret"]).toBe(SECRET_REF);
    const report = steps.find((s) => s.name === "Report pass or fail to the Vercel check");
    expect(JSON.stringify(report)).not.toMatch(/BYPASS|bypass/);
  });

  it("with the secret: masks it first, sends it from a header file to the deployment host only, never on the command line, and removes the file", () => {
    const r = runStep("target", { DEPLOYMENT_URL: "https://shop-abc123.vercel.app", BYPASS: SECRET });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout.split("\n")[0]).toBe(`::add-mask::${SECRET}`);
    expect(r.header).toBe(`x-vercel-protection-bypass: ${SECRET}\n`);
    expect(r.argv).not.toContain(SECRET);
    expect(r.argv.trim().split("\n").at(-1)).toBe("https://shop-abc123.vercel.app/");
    expect(existsSync(r.headerPath)).toBe(false);
    expect(r.output).toBe("url=https://shop-abc123.vercel.app\n");
  });

  it("without the secret: no mask, an empty header file, and a 401 fails with the steps to add the secret", () => {
    const r = runStep("target", { DEPLOYMENT_URL: "https://shop-abc123.vercel.app", BYPASS: "" }, { code: "401" });
    expect(r.status).toBe(2);
    expect(r.stdout).not.toContain("::add-mask::");
    expect(r.header).toBe("");
    expect(r.stdout).toMatch(/::error::https:\/\/shop-abc123\.vercel\.app answers 401: Deployment Protection\. Add the repo secret VERCEL_AUTOMATION_BYPASS_SECRET: docs\.penthera\.org\/vercel#deployment-protection/);
    expect(r.output).toBe("");
  });

  it("with a secret Vercel refuses (403): fails the same way, and the secret is not in the message", () => {
    const r = runStep("target", { DEPLOYMENT_URL: "https://shop-abc123.vercel.app", BYPASS: SECRET }, { code: "403" });
    expect(r.status).toBe(2);
    expect(r.stdout.split("\n").slice(1).join("\n")).not.toContain(SECRET);
    expect(r.stdout).toMatch(/answers 403: Deployment Protection\./);
  });

  it("refuses any host that is not a *.vercel.app deployment before curl runs, so the secret goes nowhere else", () => {
    for (const url of ["https://shop.example.com", "https://evil.test/x.vercel.app", "https://shop.vercel.app.evil.test", "https://a.b.vercel.app"]) {
      const r = runStep("target", { DEPLOYMENT_URL: url, BYPASS: SECRET });
      expect(r.status, url).toBe(2);
      expect(r.argv, url).toBeNull();
    }
  });
});
