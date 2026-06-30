/**
 * Detect client-side-only authentication (UI hides data but API is open).
 */
import { joinUrl } from "../../src/utils/url.js";
import { probeFetch } from "../../src/utils/http.js";

const SCRIPT_CANDIDATES = ["/script.js", "/app.js", "/main.js", "/static/script.js"];

/**
 * @param {string} baseUrl
 */
export async function probeClientSideAuth(baseUrl, opts = {}) {
  const timeout = opts.timeout || 8_000;
  const findings = [];

  for (const path of SCRIPT_CANDIDATES) {
    const res = await probeFetch(joinUrl(baseUrl, path), { timeout });
    if (!res || res.status !== 200 || !/function|const|fetch/i.test(res.body)) continue;

    const loadsDataOnBoot = /DOMContentLoaded|initApp|document\.ready/i.test(res.body)
      && /loadAndRender|fetch\s*\(\s*['"][^'"]+\.json/i.test(res.body);
    const hasLoginGate = /doLogin|loginScreen|Sign In/i.test(res.body);

    if (loadsDataOnBoot && hasLoginGate) {
      findings.push({
        severity: "high",
        title: "Client-side-only authentication",
        description:
          `${path} loads dashboard data on page init before login completes. ` +
          "If API endpoints are unauthenticated, all data is accessible without credentials.",
        url: joinUrl(baseUrl, path),
        status: 200,
        category: "auth",
        source: "client-auth-probe",
      });
    }

    // Extract JSON data URLs referenced in script
    const dataUrls = [...res.body.matchAll(/['"]([^'"]+\.json)['"]/g)].map((m) => m[1]);
    for (const rel of [...new Set(dataUrls)].slice(0, 5)) {
      const dataPath = rel.startsWith("/") ? rel : `/${rel}`;
      const dataRes = await probeFetch(joinUrl(baseUrl, dataPath), { timeout });
      if (dataRes && dataRes.status === 200 && dataRes.body.length > 10) {
        findings.push({
          severity: "high",
          title: `Sensitive data exposed: GET ${dataPath}`,
          description: "JSON data endpoint responds without authentication.",
          url: joinUrl(baseUrl, dataPath),
          status: 200,
          category: "auth",
          source: "client-auth-probe",
        });
      }
    }

    break;
  }

  return findings;
}
