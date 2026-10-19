/**
 * Evidence bundle (--evidence) and `penthera evidence verify`: hashes, tamper
 * detection, path safety, redaction, and an SSH sign/verify round trip
 * (skipped when ssh-keygen is not installed).
 */
import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, symlinkSync, existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync, spawnSync } from "node:child_process";
import {
  writeEvidenceBundle, verifyEvidence, redactArgv, hasSshKeygen, sha256, MANIFEST, SIGNATURE,
} from "../src/report/evidence.js";
import { writeEvidence, prepareReportOptions } from "../src/cli/report-outputs.js";
import { reportResult, REPORT_VERSION } from "./fixtures/report-result.js";

const roots = [];
function tmp(prefix = "penthera-ev-") {
  const d = mkdtempSync(join(tmpdir(), prefix));
  roots.push(d);
  return d;
}
afterAll(() => { for (const d of roots) rmSync(d, { recursive: true, force: true }); });

const META = { version: REPORT_VERSION, argv: ["https://shop.example", "--evidence", "ev"], target: "https://shop.example", generatedAt: "2026-10-19T10:00:00.000Z" };

function bundle(extra = {}) {
  const dir = join(tmp(), "ev");
  writeEvidenceBundle(dir, [
    { path: "report.json", content: "{\"a\":1}\n", kind: "json" },
    { path: "report.md", content: "# Report\n", kind: "markdown" },
  ], { ...META, ...extra });
  return dir;
}
const readManifest = (dir) => JSON.parse(readFileSync(join(dir, MANIFEST), "utf-8"));
const writeManifest = (dir, m) => writeFileSync(join(dir, MANIFEST), JSON.stringify(m, null, 2) + "\n");

describe("evidence bundle", () => {
  it("writes a manifest with the SHA-256 of every artifact", () => {
    const dir = bundle();
    const m = readManifest(dir);
    expect(m.schema).toBe("penthera-evidence/1");
    expect(m.tool).toMatchObject({ name: "penthera", version: REPORT_VERSION });
    expect(m.generated_at).toBe(META.generatedAt);
    expect(m.target).toBe("https://shop.example");
    expect(m.command).toBe("penthera https://shop.example --evidence ev");
    expect(m.artifacts.map((a) => a.path)).toEqual(["report.json", "report.md"]);
    expect(m.artifacts[1].sha256).toBe(sha256(Buffer.from("# Report\n")));
    expect(m.signature).toBeNull();
    const r = verifyEvidence(dir);
    expect(r.ok).toBe(true);
    expect(r.signature.status).toBe("unsigned");
  });

  it("records the git commit of the scanned repo", () => {
    const repo = tmp("penthera-ev-git-");
    execFileSync("git", ["init", "-q", repo]);
    writeFileSync(join(repo, "a.txt"), "a");
    execFileSync("git", ["-C", repo, "add", "."]);
    execFileSync("git", ["-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]);
    const head = execFileSync("git", ["-C", repo, "rev-parse", "HEAD"], { encoding: "utf-8" }).trim();
    const m = readManifest(bundle({ repo }));
    expect(m.git).toEqual({ commit: head, dirty: false });
  });

  it("refuses a directory that is not empty", () => {
    const dir = bundle();
    expect(() => writeEvidenceBundle(dir, [], META)).toThrow(/not empty/);
  });

  it("fails when an artifact changes", () => {
    const dir = bundle();
    writeFileSync(join(dir, "report.md"), "# Report (edited)\n");
    const r = verifyEvidence(dir);
    expect(r.ok).toBe(false);
    expect(r.problems).toContain("report.md: hash mismatch");
  });

  it("fails when the manifest is tampered with", () => {
    const dir = bundle();
    const m = readManifest(dir);
    m.artifacts[0].sha256 = "0".repeat(64);
    writeManifest(dir, m);
    expect(verifyEvidence(dir).ok).toBe(false);
  });

  it("fails on a missing, extra or symlinked file", () => {
    const missing = bundle();
    rmSync(join(missing, "report.json"));
    expect(verifyEvidence(missing).problems).toContain("report.json: missing");

    const extra = bundle();
    writeFileSync(join(extra, "notes.md"), "trust me");
    expect(verifyEvidence(extra).problems).toContain("notes.md is in the bundle but not in the manifest");

    const linked = bundle();
    const outside = join(tmp(), "outside.md");
    writeFileSync(outside, "# Report\n");
    rmSync(join(linked, "report.md"));
    symlinkSync(outside, join(linked, "report.md"));
    expect(verifyEvidence(linked).problems).toContain("report.md: not a regular file");
  });

  it("rejects manifest paths that escape the bundle", () => {
    const dir = bundle();
    const m = readManifest(dir);
    for (const p of ["../outside.md", "/etc/passwd", "a/../../b", "sub\\..\\x", ".hidden", MANIFEST]) {
      writeManifest(dir, { ...m, artifacts: [...m.artifacts, { path: p, sha256: "0".repeat(64) }] });
      const r = verifyEvidence(dir);
      expect(r.ok).toBe(false);
      expect(r.problems.some((x) => x.startsWith("unsafe or duplicate artifact path"))).toBe(true);
    }
  });

  it("fails cleanly on a missing or broken manifest", () => {
    expect(verifyEvidence(tmp()).problems[0]).toMatch(/manifest.json not found/);
    const dir = bundle();
    writeFileSync(join(dir, MANIFEST), "{not json");
    expect(verifyEvidence(dir).problems[0]).toMatch(/not valid JSON/);
    writeManifest(dir, { schema: "other", artifacts: [] });
    expect(verifyEvidence(dir).problems[0]).toMatch(/not a penthera-evidence\/1 manifest/);
  });

  it("warns UNSIGNED on an unsigned bundle, and --require-signature fails it (360 review)", () => {
    const dir = bundle();
    const r = verifyEvidence(dir);
    expect(r.ok).toBe(true);
    expect(r.warnings.join()).toMatch(/UNSIGNED/);
    expect(verifyEvidence(dir, { requireSignature: true }).ok).toBe(false);
    const bin = resolve("bin/penthera.js");
    const cli = spawnSync(process.execPath, [bin, "evidence", "verify", dir], { encoding: "utf-8" });
    expect(cli.status).toBe(0);
    expect(cli.stderr).toMatch(/WARNING {2}UNSIGNED/);
    expect(cli.stdout).toMatch(/\(UNSIGNED\)/);
    const usage = spawnSync(process.execPath, [bin, "evidence", "verify", dir, "--require-signature"], { encoding: "utf-8" });
    expect(usage.status).toBe(2);
    const strict = spawnSync(process.execPath, [bin, "evidence", "verify", dir, "--require-signature", "--allowed-signers", join(dir, "nope")], { encoding: "utf-8" });
    expect(strict.status).toBe(1);
  });

  it("fails when --allowed-signers is given but the bundle is unsigned", () => {
    const dir = bundle();
    const r = verifyEvidence(dir, { allowedSigners: join(dir, "nope") });
    expect(r.ok).toBe(false);
    expect(r.signature.status).toBe("missing");
  });

  it("writes JSON, Markdown, SARIF and all audience reports from a scan result", () => {
    const dir = join(tmp(), "ev");
    const tpl = join(tmp(), "t.md");
    writeFileSync(tpl, "Critical: {{summary.critical}}\n");
    const opts = { evidence: dir, "report-template": tpl };
    const { template } = prepareReportOptions(opts);
    const { manifest } = writeEvidence(reportResult(), opts, {
      version: REPORT_VERSION, template, mdOpts: { version: REPORT_VERSION }, sbom: { bomFormat: "CycloneDX" },
      argv: ["https://shop.example", "--auth-bearer", "tok3n"], now: META.generatedAt,
    });
    expect(manifest.artifacts.map((a) => a.path)).toEqual([
      "README.md", "report-auditor.md", "report-custom.md", "report-developer.md", "report-owner.md",
      "report.json", "report.md", "report.sarif", "sbom.cdx.json",
    ]);
    expect(manifest.command).not.toContain("tok3n");
    expect(readFileSync(join(dir, "report-custom.md"), "utf-8")).toBe("Critical: 1\n");
    expect(JSON.parse(readFileSync(join(dir, "report.sarif"), "utf-8")).version).toBe("2.1.0");
    expect(verifyEvidence(dir).ok).toBe(true);
  });
});

describe("command line redaction", () => {
  it("masks auth flags, token-like flags and URL credentials", () => {
    expect(redactArgv([
      "https://user:pw@shop.example/?token=abc&page=2", "--auth-cookie", "sid=1", "--auth-bearer=xyz",
      "--api-key", "k", "--repo", ".", "--sign-key", "~/.ssh/id_ed25519",
    ])).toEqual([
      "https://REDACTED@shop.example/?token=REDACTED&page=2", "--auth-cookie", "[REDACTED]", "--auth-bearer=[REDACTED]",
      "--api-key", "[REDACTED]", "--repo", ".", "--sign-key", "~/.ssh/id_ed25519",
    ]);
  });
});

describe.skipIf(!hasSshKeygen())("SSH signature round trip", () => {
  const keys = tmp("penthera-ev-keys-");
  const key = join(keys, "signer");
  const other = join(keys, "other");
  const gen = (path, comment) => execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path]);
  const allowed = (path, principal, pub) => {
    const [type, b64] = readFileSync(`${pub}.pub`, "utf-8").trim().split(" ");
    writeFileSync(path, `${principal} namespaces="penthera-evidence" ${type} ${b64}\n`);
    return path;
  };

  beforeAll(() => {
    gen(key, "auditee@example.com");
    gen(other, "mallory@example.com");
    allowed(join(keys, "allowed"), "auditee@example.com", key);
  });

  it("signs the manifest and verifies it against allowed signers", () => {
    const dir = bundle({ signKey: key });
    expect(existsSync(join(dir, SIGNATURE))).toBe(true);
    expect(readManifest(dir).signature.public_key).toMatch(/^ssh-ed25519 /);

    const ok = verifyEvidence(dir, { allowedSigners: join(keys, "allowed") });
    expect(ok.ok).toBe(true);
    expect(ok.signature).toMatchObject({ status: "valid", principal: "auditee@example.com" });

    // 360 review: a valid signature by a key nobody checked is not "verified".
    const unknown = verifyEvidence(dir);
    expect(unknown.ok).toBe(false);
    expect(unknown.signature.status).toBe("unverified");
    expect(unknown.problems.join()).toMatch(/--allowed-signers/);

    const wrong = verifyEvidence(dir, { allowedSigners: allowed(join(keys, "allowed-other"), "mallory@example.com", other) });
    expect(wrong.ok).toBe(false);
    expect(wrong.signature.status).toBe("invalid");
  });

  it("fails when a signed manifest is edited, even with consistent hashes", () => {
    const dir = bundle({ signKey: key });
    writeFileSync(join(dir, "report.md"), "# Forged\n");
    const m = readManifest(dir);
    m.artifacts.find((a) => a.path === "report.md").sha256 = sha256(Buffer.from("# Forged\n"));
    writeManifest(dir, m);
    const r = verifyEvidence(dir, { allowedSigners: join(keys, "allowed") });
    expect(r.files.every((f) => f.ok)).toBe(true);
    expect(r.ok).toBe(false);
    expect(r.signature.status).toBe("invalid");
  });

  it("fails a bundle re-signed with an attacker's key when no signer is pinned, and a declared signature with no .sig (360 review)", () => {
    const dir = bundle({ signKey: other });
    const bin = resolve("bin/penthera.js");
    const r = spawnSync(process.execPath, [bin, "evidence", "verify", dir], { encoding: "utf-8" });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/signer was not checked/);
    rmSync(join(dir, SIGNATURE));
    const stripped = verifyEvidence(dir);
    expect(stripped.ok).toBe(false);
    expect(stripped.signature.status).toBe("missing");
  });

  it("penthera evidence verify exits 0 for a good bundle and 1 for a tampered one", () => {
    const bin = resolve("bin/penthera.js");
    const dir = bundle({ signKey: key });
    const run = () => spawnSync(process.execPath, [bin, "evidence", "verify", dir, "--allowed-signers", join(keys, "allowed")], { encoding: "utf-8" });
    const good = run();
    expect(good.status).toBe(0);
    expect(good.stdout).toContain("Verified");
    writeFileSync(join(dir, "report.json"), "{}\n");
    const bad = run();
    expect(bad.status).toBe(1);
    expect(bad.stdout).toContain("report.json: hash mismatch");
  });
});

describe("penthera --evidence end to end", () => {
  it("writes a bundle from a repo scan that `evidence verify` accepts", () => {
    const bin = resolve("bin/penthera.js");
    const ev = join(tmp(), "ev");
    const repo = resolve("tests/fixtures/fix/express");
    const scan = spawnSync(process.execPath, [bin, "--repo", repo, "--evidence", ev, "--audience", "auditor", "-q"], {
      encoding: "utf-8", env: { ...process.env, PENTHERA_NO_ONBOARDING: "1" },
    });
    expect([0, 1]).toContain(scan.status);
    expect(readManifest(ev).artifacts.length).toBe(7);
    const v = spawnSync(process.execPath, [bin, "evidence", "verify", ev, "--json"], { encoding: "utf-8" });
    expect(v.status).toBe(0);
    expect(JSON.parse(v.stdout).ok).toBe(true);
  });

  it("rejects a bad --report-template before scanning", () => {
    const bin = resolve("bin/penthera.js");
    const tpl = join(tmp(), "bad.md");
    writeFileSync(tpl, "{{constructor.constructor}}");
    const r = spawnSync(process.execPath, [bin, "--repo", ".", "--report-template", tpl], {
      encoding: "utf-8", env: { ...process.env, PENTHERA_NO_ONBOARDING: "1" },
    });
    expect(r.status).toBe(2);
    expect(r.stderr + r.stdout).toMatch(/not allowed/);
  });
});
