/**
 * OAuth / open redirect misconfiguration probes.
 */
import { joinUrl } from "../../src/utils/url.js";
import { probeFetch } from "../../src/utils/http.js";

const OAUTH_PATHS = [
  "/api/auth/callback",
  "/api/oauth/callback",
  "/auth/callback",
  "/oauth/callback",
];

const EVIL = "https://evil-attacker.example/capture";

export async function probeOAuthMisconfig(baseUrl, opts = {}) {
  const timeout = opts.timeout || 8_000;
  const findings = [];

  for (const path of OAUTH_PATHS) {
    for (const qs of [
      `redirect_uri=${encodeURIComponent(EVIL)}`,
      `redirect=${encodeURIComponent(EVIL)}`,
    ]) {
      const url = joinUrl(baseUrl, `${path}?${qs}`);
      const res = await probeFetch(url, { timeout });

      if (!res) continue;

      const location = res.headers.location || "";
      if (location.includes("evil-attacker.example")) {
        findings.push({
          severity: "high",
          title: "OAuth open redirect",
          description: `${path} redirects to attacker-controlled URL.`,
          url,
          status: res.status,
          category: "auth",
          source: "oauth-probe",
        });
        break;
      }
    }
  }

  return findings;
}
