/**
 * JWT misconfiguration probes.
 */
import { joinUrl } from "../../src/utils/url.js";
import { probeFetch } from "../../src/utils/http.js";

function decodeJwtPayload(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

export async function probeJwt(baseUrl, opts = {}) {
  const findings = [];
  const timeout = opts.timeout || 8_000;
  const token = opts.bearerToken;

  if (!token) return findings;

  const payload = decodeJwtPayload(token);
  if (!payload) {
    findings.push({
      severity: "low",
      title: "Configured bearer token is not a valid JWT",
      description: "Token could not be decoded — verify auth configuration.",
      url: baseUrl,
      category: "auth",
      source: "jwt-probe",
    });
    return findings;
  }

  if (payload.exp && new Date(payload.exp * 1000) < new Date()) {
    findings.push({
      severity: "medium",
      title: "Configured JWT is expired",
      description: "Scans with this token may not reflect authenticated routes.",
      url: baseUrl,
      category: "auth",
      source: "jwt-probe",
    });
  }

  if (opts.testPath) {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url");
    const forged = `${header}.${body}.`;

    const res = await probeFetch(joinUrl(baseUrl, opts.testPath), {
      timeout,
      headers: { Authorization: `Bearer ${forged}` },
    });

    if (res?.status === 200) {
      findings.push({
        severity: "critical",
        title: "JWT alg:none bypass accepted",
        description: `Forged unsigned JWT accepted on ${opts.testPath}.`,
        url: joinUrl(baseUrl, opts.testPath),
        status: res.status,
        category: "auth",
        source: "jwt-probe",
      });
    }
  }

  return findings;
}
