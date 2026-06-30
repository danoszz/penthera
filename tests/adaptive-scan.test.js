import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startMockServer } from "./fixtures/mock-server.js";
import { scanUrl } from "../src/scan-url.js";
import { routesFromOpenApi, runAdaptiveProbes } from "../lib/blackbox/adaptive-scan.js";

describe("adaptive scan", () => {
  let mock;
  let baseUrl;

  beforeAll(async () => {
    mock = await startMockServer(0);
    baseUrl = mock.url;
  });

  afterAll(async () => {
    await mock.close();
  });

  it("builds routes from OpenAPI spec", async () => {
    const res = await fetch(`${baseUrl}/openapi.json`);
    const spec = await res.json();
    const routes = routesFromOpenApi(spec);
    expect(routes.some((r) => r.url.includes("users"))).toBe(true);
  });

  it("runs adaptive probes on mock API", async () => {
    const res = await fetch(`${baseUrl}/openapi.json`);
    const spec = await res.json();
    const findings = await runAdaptiveProbes(baseUrl, { spec });
    expect(Array.isArray(findings)).toBe(true);
  });

  it("CLI --adaptive integrates with scanUrl", async () => {
    const result = await scanUrl(baseUrl, { adaptive: true, timeout: 5_000, onPhase: () => {} });
    expect(result.reachable).toBe(true);
    expect(result.findings.some((f) => f.source === "adaptive-probe" || f.source === "idor-probe")).toBe(true);
  });
});
