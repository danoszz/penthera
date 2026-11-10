/**
 * One count, everywhere. Every surface (the CLI brief, the terminal report,
 * `penthera ui`, the MCP tools, the JSON and SARIF reports, `penthera fix` and
 * the fix loop) counts one run's findings with these definitions and these
 * words, so no two of them can disagree about the same app:
 *
 *   finding        anything a rule reported, info and likely noise included
 *   problem        a finding to act on or to check first: not info, not
 *                  likely noise (fixtures, tests, generated or git-ignored
 *                  files), not suppressed
 *   fix planned    one diff from `penthera fix`; one fix can cover several
 *                  problems (one config change for five missing headers)
 *
 * The bucket comes from fields the engines set (severity, confidence,
 * localOnly, path), never from a model.
 */

// Generated or build output: nobody edits these files, so a hit in them is noise.
// Names only a tool writes are always generated. dist, build and out are generated
// only when no source folder comes before them: app/api/build/route.ts is a real
// route, packages/x/dist/index.js is build output.
const GENERATED = /(?:^|\/)(?:\.next[^/]*|\.turbo|\.svelte-kit|\.nuxt|\.output|__pycache__|coverage)\//;
const BUILD_DIR = /(?:^|\/)(?:dist|build|out)\//;
const SOURCE_DIR = /(?:^|\/)(?:app|pages|src|api|routes|lib|server|functions|controllers|handlers)\//;
const isGenerated = (p) => {
  if (GENERATED.test(p)) return true;
  const m = BUILD_DIR.exec(p);
  return !!m && !SOURCE_DIR.test(p.slice(0, m.index + 1));
};
// Third-party code shipped inside the repo: minified files and vendored library folders.
const VENDORED = /(?:^|\/)(?:vendor|vendors|third_party|third-party|bower_components)\/|(?:^|\/)(?:public|static|assets|wwwroot)\/(?:js\/|scripts\/)?(?:lib|libs|vendor)\/|[.-](?:min|compressed|packed)\.(?:js|mjs|cjs|css)$/;
// A sign of planted or malicious code is never demoted for where it sits: a minified
// file or a vendor folder is exactly where such code hides.
const HOSTILE = /^(?:rootkit|persistence|suspicious-files|suspicious-process|malware|ioc|supply-chain|dependency-risk|agent-config)$/;
const isHostile = (f) => HOSTILE.test(String(f.category || "")) || /^ioc[.:-]/i.test(String(f.templateId || f.rule || ""));
// Examples, demos and documentation samples: sample keys and passwords live here.
const EXAMPLE = /(?:^|\/)(?:examples?|samples?|demos?)\//;
const FIXTURE = /(?:^|\/)(?:fixtures?|__fixtures__|testdata|__mocks__)\//;
// Test code: a key here is a test's own sample. A fixtures folder keeps its own reason, so FIXTURE is checked first.
const TEST_FILE = /(?:^|\/)(?:tests?(?:[_-][^/]*)?|__tests__|e2e|cypress|playwright)\/|(?:^|\/)[^/]*\.(?:test|spec|cy)\.[^/]+$/;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/** The file a finding points at, or null for a URL. */
export function pathOf(f) {
  const u = f.file || f.url;
  return u && !URL_RE.test(String(u)) ? String(u) : null;
}

/** Which bucket a finding goes in, and for noise, why. First match wins. */
export function bucketOf(f, { skillTarget = false } = {}) {
  const p = pathOf(f) || "";
  if (f.localOnly) return { bucket: "noise", reason: "local-only" };
  // A skill ships its dist/ and build/, so in a named skill those are real code.
  if (!skillTarget && isGenerated(p)) return { bucket: "noise", reason: "generated" };
  if (FIXTURE.test(p)) return { bucket: "noise", reason: "fixture" };
  if (TEST_FILE.test(p)) return { bucket: "noise", reason: "test-file" };
  if (!skillTarget && !isHostile(f) && VENDORED.test(p)) return { bucket: "noise", reason: "vendored" };
  if (!isHostile(f) && EXAMPLE.test(p)) return { bucket: "noise", reason: "example" };
  if (f.severity === "info") return { bucket: "info" };
  if (["potential", "needs-human-review"].includes(f.confidence)) return { bucket: "check" };
  if (f.severity === "low") return { bucket: "check" };
  if (f.category === "dependency-risk") return { bucket: "check" };
  return { bucket: "act" };
}

/** True for a problem: a finding to act on or to check first. */
export function isProblem(f, opts) {
  const { bucket } = bucketOf(f, opts);
  return bucket === "act" || bucket === "check";
}

/**
 * The counts behind every surface's numbers. Suppressed findings are not in
 * `findings` (they sit in a report's `suppressed`), so pass them apart.
 *
 * @param {object[]} findings
 * @param {{ skillTarget?: boolean, suppressed?: number }} [opts]
 * @returns {{ problems: number, act: number, check: number, noise: number, info: number, suppressed: number, total: number }}
 */
export function problemCounts(findings, { skillTarget = false, suppressed = 0 } = {}) {
  const c = { problems: 0, act: 0, check: 0, noise: 0, info: 0, suppressed, total: 0 };
  for (const f of findings || []) {
    if (!f || typeof f !== "object") continue;
    c.total++;
    c[bucketOf(f, { skillTarget }).bucket]++;
  }
  c.problems = c.act + c.check;
  return c;
}

export const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** "8 problems (5 to act on, 3 to check first)", the same words in every surface. */
export function problemsText(c) {
  return `${plural(c.problems, "problem")} (${c.act} to act on, ${c.check} to check first)`;
}

/**
 * The fix plan's headline: "5 fixes planned for 8 problems", or "for 7 of 8
 * problems" when some have no fix.
 *
 * @param {number} fixes  plans
 * @param {number} covered  problems a plan fixes
 * @param {number} problems  problems in the run
 */
export function fixesText(fixes, covered, problems) {
  const of = covered === problems ? plural(problems, "problem") : `${covered} of ${plural(problems, "problem")}`;
  return `${fixes} ${fixes === 1 ? "fix" : "fixes"} planned for ${of}`;
}
