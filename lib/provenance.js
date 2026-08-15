/**
 * Provenance and honest-confidence labelling for findings (principles #1 and #3).
 *
 * Every finding carries { source, method, collected_at, confidence }:
 *   - source / method: which probe produced it,
 *   - collected_at: when the scan ran,
 *   - confidence: how sure we are it is real and reachable, not just its severity.
 *
 * Confidence is deliberately honest about what a scanner can and cannot judge:
 *   confirmed           deterministic evidence (a header is absent, a cert expired)
 *   likely              a strong signal with a small false-positive chance
 *   potential           a heuristic or timing signal that needs corroboration
 *   needs-human-review  exploitability can't be judged from a scan (e.g. IDOR)
 *
 * A scanner must not present a guess as a fact, so heuristic probes are labelled
 * accordingly rather than being dressed up as certainties.
 */

// Probe source -> default confidence.
const SOURCE_CONFIDENCE = {
  "tls-check": "confirmed",
  "header-audit": "confirmed",
  "cookie-audit": "confirmed",
  "secret-scan": "confirmed",
  "sensitive-file-check": "confirmed",
  "openapi-scan": "confirmed",
  "email-dns-probe": "confirmed",
  "framework-check": "likely",
  "static-analysis": "likely",
  "trust-boundary": "likely",
  "auth-probe": "likely",
  "oauth-probe": "likely",
  "jwt-probe": "likely",
  "injection-probe": "likely",
  "template": "likely",
  "nuclei-community": "likely",
  "client-auth-probe": "needs-human-review",
  "idor-probe": "needs-human-review",
  "fuzzer": "potential",
  "adaptive-probe": "potential",
};

// Category fallback when the source is unknown.
const CATEGORY_CONFIDENCE = {
  headers: "confirmed",
  transport: "confirmed",
  tls: "confirmed",
  cookie: "confirmed",
  secrets: "confirmed",
  cve: "confirmed",
  "js-vulnerability": "confirmed",
  "email-auth": "confirmed",
  auth: "likely",
  "auth-bypass": "needs-human-review",
  ssti: "likely",
  sqli: "likely",
  xss: "likely",
  cmdi: "likely",
  ssrf: "likely",
  "open-redirect": "likely",
  fuzzing: "potential",
};

/** Honest-confidence label for a finding. An explicit finding.confidence wins. */
export function confidenceFor(f) {
  if (f.confidence) return f.confidence;
  return SOURCE_CONFIDENCE[f.source] || CATEGORY_CONFIDENCE[f.category] || "likely";
}

/** Stamp { source, method, collected_at, confidence } onto every finding. */
export function stampProvenance(findings, collectedAt) {
  return (findings || []).map((f) => {
    const source = f.source || "penthera";
    return {
      ...f,
      source,
      method: f.method || source,
      collected_at: f.collected_at || collectedAt || null,
      confidence: confidenceFor(f),
    };
  });
}
