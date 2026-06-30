/**
 * Merge multi-target scan results into one report.
 */
import { enrichFindingsWithWstg } from "../../lib/owasp-wstg.js";

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
      attackSurface: results.find((r) => r.attackSurface?.length)?.attackSurface || null,
      boundaries: results.find((r) => r.boundaries && Object.keys(r.boundaries).length)?.boundaries || null,
      apiRoot: results.find((r) => r.apiRoot)?.apiRoot || null,
      machine: results.find((r) => r.machine)?.machine || null,
      findings: dedupeFindings(results.flatMap((r) => r.findings || [])),
    };
  }

  merged.findings = enrichFindingsWithWstg(merged.findings);
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

export function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.severity}::${f.title}::${f.url || ""}::${f.source || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
