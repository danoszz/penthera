/**
 * cron-route-no-secret (Mythos C1, 12 Nov 2026): a route that `vercel.json`
 * runs on a schedule (`crons[].path`) and that checks nothing, so anyone who
 * finds the URL can run the job: send the digest to every user, charge the
 * renewals, delete the old rows.
 *
 * The check counts when the route compares the `Authorization` header or
 * `CRON_SECRET` (`authHeader !== \`Bearer ${process.env.CRON_SECRET}\``),
 * passes `CRON_SECRET` to a call, or verifies a signed request (QStash's
 * `verifySignatureAppRouter` or a `Receiver`). Reading the header only to log
 * it is not a check. Vercel's own docs set the header from `CRON_SECRET`.
 */
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { lexJs } from "./js-lex.js";
import { parseJson } from "../json-text.js";
import { firstWrite, makeBudget } from "./missing-checks.js";

export const CRON_RULE = "cron-route-no-secret";
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_CRONS = 200;
const EXTS = ["ts", "js", "mjs", "tsx", "jsx"];

/** The route files that serve `path`, App Router first, then Pages API routes. */
function routeFiles(root, path) {
  let clean = String(path).split("?")[0];
  let a = 0, b = clean.length;
  while (a < b && clean[a] === "/") a++;
  while (b > a && clean[b - 1] === "/") b--;
  clean = clean.slice(a, b);
  if (!clean || clean.includes("..") || !/^[\w\-./[\]]+$/.test(clean)) return [];
  const out = [];
  for (const base of ["app", "src/app"]) for (const e of EXTS) out.push(`${base}/${clean}/route.${e}`);
  for (const base of ["pages", "src/pages"]) for (const e of EXTS) out.push(`${base}/${clean}.${e}`, `${base}/${clean}/index.${e}`);
  return out.filter((rel) => existsSync(join(root, rel)));
}

const SIGNED = /\b(?:verifySignatureAppRouter|verifySignatureEdge)\s*\(|\bnew\s+Receiver\s*\(\s*\{/;
// A compare that is not only "is it set" (`=== undefined`, `!== null`).
const REAL_COMPARE = /(?<![!=])(?:===|!==|==|!=)(?!=)(?!\s*(?:undefined|null)\b)|\btimingSafeEqual\s*\(/;
// The handler is wrapped (`export const GET = withCron(handler)`) or calls a local helper with the
// request (`await assertCron(req)`): the check may sit there, so the finding is only possible.
const WRAPPED = /\bexport\s+const\s+(?:GET|POST|PUT|DELETE|PATCH)\s*=\s*[\w$.]+\s*\(|\bawait\s+[\w$]+\s*\(\s*(?:req|request)\s*\)/;

/**
 * Does the route check the caller? `CRON_SECRET` in code (a template's `${…}` counts, a
 * comment or a string does not) and a real compare or constant-time compare in the file,
 * or a QStash signature check. Multi-line compares and the secret held in a constant
 * (`const expected = \`Bearer ${env.CRON_SECRET}\``) count (blind review of batch 5).
 */
export function cronChecked(source) {
  const { code, expr } = lexJs(source);
  if (SIGNED.test(code)) return true;
  return /\bCRON_SECRET\b/.test(expr) && REAL_COMPARE.test(code);
}

const clean = (t, max) => String(t ?? "").replace(/[\u0000-\u001f\u007f`[\]()]/g, " ").slice(0, max);

/**
 * Findings for the repository's scheduled routes.
 * @param {string} repoPath
 * @param {{ refused?: object[] }} [opts]
 */
export function scanCronRoutes(repoPath, { refused = [] } = {}) {
  const root = resolve(repoPath);
  const cfg = join(root, "vercel.json");
  if (!existsSync(cfg)) return [];
  let crons;
  try {
    const json = parseJson(readRepoFile(cfg, { root, label: "vercel.json", maxBytes: MAX_BYTES }));
    crons = Array.isArray(json?.crons) ? json.crons.slice(0, MAX_CRONS) : [];
    if (Array.isArray(json?.crons) && json.crons.length > MAX_CRONS) refused.push({ path: cfg, reason: `it lists more than ${MAX_CRONS} crons, so the rest were not checked`, partial: true });
  } catch (e) {
    if (isRefused(e)) refused.push(e);
    else refused.push({ path: cfg, reason: `it could not be read as JSON (${e.code || e.message})` });
    return [];
  }
  const findings = [];
  const seen = new Set();
  for (const c of crons) {
    for (const rel of routeFiles(root, c?.path)) {
      if (seen.has(rel)) continue;
      seen.add(rel);
      let source;
      try { source = readRepoFile(join(root, rel), { root, label: rel, maxBytes: MAX_BYTES }); } catch (e) {
        if (isRefused(e)) refused.push(e);
        else if (e.code !== "ENOENT") refused.push({ path: join(root, rel), reason: `it could not be read (${e.code || e.message})` });
        continue;
      }
      if (cronChecked(source)) continue;
      const { code, plain } = lexJs(source);
      const wrapped = WRAPPED.test(code);
      const budget = makeBudget(code.length);
      const writes = firstWrite(code, plain, 0, code.length, budget) !== -1;
      findings.push({
        severity: writes ? "high" : "medium",
        confidence: wrapped ? "potential" : "likely",
        title: `Scheduled route runs without checking the caller in ${rel}`,
        description: `\`vercel.json\` runs \`${clean(c.path, 200)}\` on a schedule (\`${clean(c.schedule, 60)}\`), and \`${rel}\` checks neither the \`Authorization\` header nor \`CRON_SECRET\`, nor a signed request. Anyone who finds the URL can run the job${writes ? "; this one writes data, sends mail or calls a payment API" : ""}.${wrapped ? " The handler is wrapped or calls a helper with the request, so the check may sit there." : ""}`,
        remediation: "Set CRON_SECRET in the project's environment (Vercel sends it as `Authorization: Bearer <secret>` to cron routes) and reject other calls first: `if (request.headers.get(\"authorization\") !== `Bearer ${process.env.CRON_SECRET}`) return new Response(\"Unauthorized\", { status: 401 });`",
        url: rel,
        file: rel,
        line: 1,
        templateId: CRON_RULE,
        category: "auth-bypass",
        source: "static-analysis",
      });
    }
  }
  return findings;
}
