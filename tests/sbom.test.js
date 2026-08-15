/**
 * CycloneDX SBOM generation from dependency manifests (offline).
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildSbom } from "../lib/whitebox/sbom.js";

function repoWith(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-sbom-"));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}
function withRepo(files, fn) {
  const dir = repoWith(files);
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe("SBOM (CycloneDX)", () => {
  it("returns null when there is no manifest", () => {
    withRepo({ "readme.md": "hi" }, (dir) => expect(buildSbom(dir)).toBeNull());
  });

  it("builds from package-lock.json with resolved versions, purls, and dev scope", () => {
    const lock = JSON.stringify({
      name: "app", version: "1.0.0", lockfileVersion: 3,
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/left-pad": { version: "1.3.0" },
        "node_modules/vitest": { version: "3.1.1", dev: true },
      },
    });
    withRepo({ "package.json": JSON.stringify({ name: "app", version: "1.0.0" }), "package-lock.json": lock }, (dir) => {
      const sbom = buildSbom(dir, { serialNumber: "urn:uuid:x", timestamp: "2026-08-15T00:00:00Z" });
      expect(sbom.bomFormat).toBe("CycloneDX");
      expect(sbom.specVersion).toBe("1.5");
      expect(sbom.metadata.component).toMatchObject({ name: "app", version: "1.0.0" });
      const lp = sbom.components.find((c) => c.name === "left-pad");
      expect(lp.version).toBe("1.3.0");
      expect(lp.purl).toBe("pkg:npm/left-pad@1.3.0");
      expect(sbom.components.find((c) => c.name === "vitest").scope).toBe("optional");
    });
  });

  it("falls back to package.json ranges when there is no lockfile", () => {
    withRepo({ "package.json": JSON.stringify({ name: "app", version: "2.0.0", dependencies: { yaml: "^2.8.3" } }) }, (dir) => {
      const sbom = buildSbom(dir);
      const yaml = sbom.components.find((c) => c.name === "yaml");
      expect(yaml.version).toBe("2.8.3");
      expect(yaml.properties?.[0]?.value).toMatch(/range/i);
    });
  });

  it("parses requirements.txt as pypi components", () => {
    withRepo({ "requirements.txt": "flask==2.3.0\nrequests>=2.0\n# comment\n-r other.txt\n" }, (dir) => {
      const sbom = buildSbom(dir);
      expect(sbom.components.find((c) => c.name === "flask").purl).toBe("pkg:pypi/flask@2.3.0");
      expect(sbom.components.find((c) => c.name === "requests")).toBeTruthy();
    });
  });
});
