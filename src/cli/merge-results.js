/**
 * Merge multi-target scan results into one report.
 */
import { enrichFindingsWithWstg } from "../../lib/owasp-wstg.js";
import { stampProvenance } from "../../lib/provenance.js";
import { fingerprintFinding } from "../../lib/audit-loop.js";

export function mergeResults(results) {
  let merged;

  if (results.length === 1) {
    merged = { ...results[0] };
  } else {
    merged = {
      target: results.map((r) => r.target).join(" + "),
      modes: results.map((r) => r.mode),
      local: results.some((r) => r.local),
      timestamp: new Date().toISOString(),
      duration: results.reduce((sum, r) => sum + (r.duration || 0), 0),
      reachable: results.some((r) => r.reachable),
      tls: results.find((r) => r.tls)?.tls || null,
      fingerprint: results.find((r) => r.fingerprint)?.fingerprint || null,
      recon: results.find((r) => r.recon)?.recon || null,
      openapi: results.find((r) => r.openapi)?.openapi || null,
      endpoints: mergeEndpoints(results),
      cookies: results.find((r) => r.cookies)?.cookies || null,
      jsLibraries: results.find((r) => r.jsLibraries)?.jsLibraries || null,
      paramDiscovery: results.find((r) => r.paramDiscovery)?.paramDiscovery || null,
      challenge: results.find((r) => r.challenge)?.challenge,
      httpStatus: results.find((r) => r.httpStatus)?.httpStatus,
      siteUnread: results.find((r) => r.mode === "url" && r.reachable === false) ? { target: results.find((r) => r.mode === "url").target, httpStatus: results.find((r) => r.mode === "url").httpStatus } : undefined,
      attackSurface: results.find((r) => r.attackSurface?.length)?.attackSurface || null,
      boundaries: results.find((r) => r.boundaries && Object.keys(r.boundaries).length)?.boundaries || null,
      apiRoot: results.find((r) => r.apiRoot)?.apiRoot || null,
      machine: results.find((r) => r.machine)?.machine || null,
      executedProbes: results.flatMap((r) => r.executedProbes || []),
      egress: results.find((r) => r.egress)?.egress || null,
      coverage: results.find((r) => r.coverage)?.coverage || null,
      errors: results.flatMap((r) => r.errors || []),
      findings: dedupeFindings(results.flatMap((r) => r.findings || [])),
      // A refused input in any target makes the merged run incomplete (exit 2).
      ...(results.some((r) => r.incomplete?.length) ? { incomplete: results.flatMap((r) => r.incomplete || []) } : {}),
    };
  }

  merged.findings = enrichFindingsWithWstg(merged.findings);
  // Provenance + honest-confidence on every finding (source, method,
  // collected_at, confidence). Additive: consumers that don't use it ignore it.
  merged.findings = stampProvenance(merged.findings, merged.timestamp);
  return merged;
}

function mergeEndpoints(results) {
  const all = results.flatMap((r) => {
    if (r.endpoints?.list) return r.endpoints.list;
    return [];
  });

  if (all.length === 0) {
    const first = results.find((r) => r.endpoints);
    return first?.endpoints || { total: 0, discovered: 0, byStatus: {} };
  }

  const byStatus = {};
  for (const ep of all) {
    byStatus[ep.status] = (byStatus[ep.status] || 0) + 1;
  }

  return { total: all.length, discovered: all.length, byStatus, list: all };
}

const DEDUPE_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * One finding per identity. The identity leaves severity out, so of two
 * duplicates the more severe one is kept, at the first one's place (R10): a
 * later high must not drop behind an earlier low.
 */
export function dedupeFindings(findings) {
  const at = new Map();
  const out = [];
  for (const f of findings) {
    // Same identity function as the baseline diff and the audit loop.
    const key = fingerprintFinding(f);
    const i = at.get(key);
    if (i === undefined) { at.set(key, out.length); out.push(f); continue; }
    if ((DEDUPE_RANK[f.severity] ?? -1) < (DEDUPE_RANK[out[i].severity] ?? -1)) out[i] = f;
  }
  return out;
}
