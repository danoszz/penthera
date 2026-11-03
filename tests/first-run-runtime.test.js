// One runtime pin on an end-of-life line is one problem with one fix. It gave one HIGH
// row per advisory on top of the EOL row (first-run study, 2 Nov 2026).
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runtimeAdvisoriesForRepo } from "../lib/advisories/index.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-runtime-"));
  temps.push(dir);
  for (const [p, t] of Object.entries(files)) writeFileSync(join(dir, p), t);
  return dir;
}

describe("a pin on an end-of-life line", () => {
  const findings = runtimeAdvisoriesForRepo(repo({ ".tool-versions": "nodejs 23.11.1\n", Dockerfile: "FROM node:23.11.1-alpine\nCMD [\"node\", \"server.js\"]\n" }));
  const node = findings.filter((f) => /Node\.js 23/.test(f.title));

  it("is one finding, not one per advisory", () => {
    expect(node).toHaveLength(1);
    expect(node[0].title).toMatch(/end of life/);
  });

  it("lists the advisories that line will never get a fix for, with their CVEs", () => {
    expect(node[0].description).toMatch(/won't get a fix/);
    expect(node[0].advisories?.length).toBeGreaterThan(0);
    expect(node[0].cves?.length).toBeGreaterThan(0);
    expect(node[0].remediation).toMatch(/Move to a supported Node\.js line \(\d+: [\d.]+\+/);
  });

  it("points at the Dockerfile, which ships, before .tool-versions", () => {
    expect(node[0].url).toMatch(/Dockerfile$/);
  });
});

describe("a pin on a supported line", () => {
  it("keeps one row per advisory it lacks the fix for", () => {
    const f = runtimeAdvisoriesForRepo(repo({ ".nvmrc": "22.1.0\n" }));
    expect(f.filter((x) => /is affected by/.test(x.title)).length).toBeGreaterThan(1);
    expect(f.some((x) => /end of life/.test(x.title))).toBe(false);
  });
});
