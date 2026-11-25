/**
 * JWT misconfiguration probes (lib/blackbox/jwt.js).
 * Uses injected probeFetch for pure unit tests and the local mock server for
 * offline HTTP integration tests.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHmac } from "node:crypto";
import { probeJwt } from "../lib/blackbox/jwt.js";
import { createEgressContext, runWithEgress } from "../src/utils/http.js";
import { startMockServer } from "./fixtures/mock-server.js";

function makeJwt(payload, header = { alg: "HS256", typ: "JWT" }, secret = "test-signing-key") {
  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const sig = header.alg === "none" ? "" : createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${sig}`;
}

const futureExp = () => Math.floor(Date.now() / 1000) + 3600;
const pastExp = () => Math.floor(Date.now() / 1000) - 3600;

describe("probeJwt (injected probeFetch)", () => {
  const baseUrl = "https://api.example.test";

  it("returns no findings when bearerToken is missing", async () => {
    let called = false;
    const findings = await probeJwt(baseUrl, {
      testPath: "/api/user/profile",
      probeFetch: async () => { called = true; return null; },
    });
    expect(findings).toEqual([]);
    expect(called).toBe(false);
  });

  it("reports an invalid bearer token as low severity without probing", async () => {
    let called = false;
    const findings = await probeJwt(baseUrl, {
      bearerToken: "not.a-jwt",
      testPath: "/api/user/profile",
      probeFetch: async () => { called = true; return null; },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "low",
      title: "Configured bearer token is not a valid JWT",
      url: baseUrl,
      category: "auth",
      source: "jwt-probe",
    });
    expect(called).toBe(false);
  });

  it("reports an expired JWT as medium severity", async () => {
    let called = false;
    const token = makeJwt({ sub: "user-1", exp: pastExp() });
    const findings = await probeJwt(baseUrl, {
      bearerToken: token,
      probeFetch: async () => { called = true; return null; },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "medium",
      title: "Configured JWT is expired",
      url: baseUrl,
      category: "auth",
      source: "jwt-probe",
    });
    expect(called).toBe(false);
  });

  it("sends no request when testPath is omitted", async () => {
    let called = false;
    const token = makeJwt({ sub: "user-1", exp: futureExp() });
    const findings = await probeJwt(baseUrl, {
      bearerToken: token,
      probeFetch: async () => { called = true; return null; },
    });
    expect(findings).toEqual([]);
    expect(called).toBe(false);
  });

  it("flags critical alg:none bypass when the endpoint answers 200", async () => {
    const requests = [];
    const token = makeJwt({ sub: "user-1", role: "user", exp: futureExp() });
    const findings = await probeJwt(baseUrl, {
      bearerToken: token,
      testPath: "/api/user/profile",
      probeFetch: async (url, init) => {
        requests.push({ url, init });
        return { status: 200, body: '{"ok":true}', headers: {}, ok: true };
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "critical",
      title: "JWT alg:none bypass accepted",
      url: `${baseUrl}/api/user/profile`,
      status: 200,
      category: "auth",
      source: "jwt-probe",
    });

    expect(requests).toHaveLength(1);
    const sentAuth = requests[0].init.headers.Authorization;
    const forged = sentAuth.replace(/^Bearer\s+/, "");
    const [rawHeader, rawBody, sig] = forged.split(".");
    expect(JSON.parse(Buffer.from(rawHeader, "base64url").toString("utf-8"))).toEqual({
      alg: "none",
      typ: "JWT",
    });
    const decodedBody = JSON.parse(Buffer.from(rawBody, "base64url").toString("utf-8"));
    expect(decodedBody.sub).toBe("user-1");
    expect(decodedBody.role).toBe("user");
    expect(decodedBody.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(sig).toBe("");
  });

  it("produces no critical finding when the endpoint rejects alg:none with 401", async () => {
    const token = makeJwt({ sub: "user-1", exp: futureExp() });
    const findings = await probeJwt(baseUrl, {
      bearerToken: token,
      testPath: "/api/user/profile",
      probeFetch: async () => ({ status: 401, body: '{"error":"unauthorized"}', headers: {}, ok: false }),
    });
    expect(findings).toEqual([]);
  });
});

describe("probeJwt against mock server", () => {
  let mock;

  beforeAll(async () => {
    mock = await startMockServer(0);
  });

  afterAll(async () => {
    await mock?.close();
  });

  it("detects alg:none bypass on /jwt-demo/alg-none", async () => {
    const signedToken = makeJwt({ sub: "alice", role: "user", exp: futureExp() });
    const findings = await runWithEgress(createEgressContext({ target: mock.url }), () =>
      probeJwt(mock.url, {
        bearerToken: signedToken,
        testPath: "/jwt-demo/alg-none",
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "critical",
      title: "JWT alg:none bypass accepted",
      url: `${mock.url}/jwt-demo/alg-none`,
      status: 200,
      category: "auth",
      source: "jwt-probe",
    });
  });

  it("rejects signed HS256 tokens and unauthenticated requests on /jwt-demo/alg-none with 401", async () => {
    const signedToken = makeJwt({ sub: "alice", exp: futureExp() });

    const withSigned = await fetch(`${mock.url}/jwt-demo/alg-none`, {
      headers: { Authorization: `Bearer ${signedToken}` },
    });
    expect(withSigned.status).toBe(401);

    const noAuth = await fetch(`${mock.url}/jwt-demo/alg-none`);
    expect(noAuth.status).toBe(401);

    const findings = await runWithEgress(createEgressContext({ target: mock.url }), () =>
      probeJwt(mock.url, {
        bearerToken: signedToken,
        testPath: "/api/login",
      }),
    );
    expect(findings).toEqual([]);
  });
});
