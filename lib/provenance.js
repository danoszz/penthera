/**
 * Provenance and honest-confidence labelling for findings (principles #1 and #3).
 *
 * Every finding carries { source, method, collected_at, confidence }:
 *   - source / method: which probe produced it,
 *   - collected_at: when the scan ran,
 *   - confidence: how sure the rule is about what it matched, not its severity
 *     and not whether it can be exploited in this app,
 *   - exploitability: whether Penthera judged that: "not-assessed" (it never
 *     does for a rule match) or "needs-human-review" (a scanner cannot judge it),
 *   - path: a repo finding's file, next to `url` (which holds it for older readers).
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
  "deps-scan": "likely",
  "runtime-advisory": "likely",
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
  "dependency-risk": "likely",
};

/**
 * Words for each confidence value in text a person or an agent reads: a rule
 * match, never a verdict. The JSON keeps the values themselves.
 */
export const MATCH_LABELS = {
  confirmed: "pattern matched",
  likely: "likely match",
  potential: "possible match",
  "needs-human-review": "needs a person",
};

/** `confidence` in the words of MATCH_LABELS. */
export function matchLabel(confidence) {
  return MATCH_LABELS[confidence] || String(confidence || "likely match");
}

/** Whether Penthera judged exploitability: it does not for a rule match. */
export function exploitabilityFor(f) {
  return confidenceFor(f) === "needs-human-review" ? "needs-human-review" : "not-assessed";
}

const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * A repo finding's file: `file`, or `url` when it holds a file path. Not an
 * address (a scheme) and not a route (`/api/x`, which a trust-boundary finding
 * puts in `url`): an agent opens `path` as a file.
 */
export function pathFor(f) {
  if (f.file) return String(f.file);
  const u = f.url == null ? "" : String(f.url);
  return u && !URL_RE.test(u) && !u.startsWith("/") ? u : null;
}

/** Honest-confidence label for a finding. An explicit finding.confidence wins. */
export function confidenceFor(f) {
  if (f.confidence) return f.confidence;
  return SOURCE_CONFIDENCE[f.source] || CATEGORY_CONFIDENCE[f.category] || "likely";
}

/**
 * Stamp { source, method, collected_at, confidence, exploitability } onto every
 * finding, and `path` onto a repo finding. Fields are only added: `url` keeps
 * the path for readers that use it.
 */
export function stampProvenance(findings, collectedAt) {
  return (findings || []).map((f) => {
    const source = f.source || "penthera";
    const path = f.path ?? pathFor(f);
    return {
      ...f,
      source,
      method: f.method || source,
      collected_at: f.collected_at || collectedAt || null,
      confidence: confidenceFor(f),
      exploitability: f.exploitability || exploitabilityFor(f),
      ...(path ? { path } : {}),
    };
  });
}
