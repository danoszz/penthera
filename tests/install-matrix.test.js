// The install matrix's upgrade job: from the previous minor release to the candidate.
// It read "from 1.9.0" while installing 2.2.0, which only reinstalled the same version.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { upgradeFrom } from "../scripts/ci/upgrade-from.mjs";

const workflow = readFileSync(new URL("../.github/workflows/install-matrix.yml", import.meta.url), "utf8");
const changelog = "## [Unreleased]\n## [2.2.0]\n## [2.1.2]\n## [2.1.1]\n## [2.1.0]\n## [2.1.0-rc.2]\n## [2.0.0]\n## [1.9.0]\n";

describe("the install matrix's upgrade job", () => {
  it("starts from the newest release of the previous minor", () => {
    expect(upgradeFrom("2.2.0", changelog)).toBe("2.1.2");
    expect(upgradeFrom("2.2.1", changelog)).toBe("2.1.2");
    expect(upgradeFrom("2.3.0", changelog)).toBe("2.2.0");
    expect(upgradeFrom("3.0.0", changelog)).toBe("2.2.0");
    expect(upgradeFrom("2.1.0", changelog)).toBe("2.0.0");
  });

  it("never upgrades from the candidate itself", () => {
    const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const from = upgradeFrom(version, readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8"));
    expect(from).toMatch(/^\d+\.\d+\.\d+$/);
    expect(from).not.toBe(version);
  });

  it("names and installs the version it computes, with none typed in", () => {
    expect(workflow).toContain("FROM_VERSION: ${{ needs.pack.outputs.from }}");
    expect(workflow).toMatch(/name: upgrade from \$\{\{ needs\.pack\.outputs\.from \}\}/);
    expect(workflow).toContain("node scripts/ci/upgrade-from.mjs");
    expect(workflow).not.toMatch(/FROM_VERSION: \d/);
    expect(workflow).not.toMatch(/upgrade from \d/);
  });
});
