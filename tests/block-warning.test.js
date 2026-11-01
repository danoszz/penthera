import { describe, it, expect } from "vitest";
import { blockWarning } from "../lib/blackbox/challenge.js";

const h = (o) => new Headers(o);

describe("block pages known by their headers", () => {
  it.each([
    [405, { "x-amzn-waf-action": "captcha" }, "AWS WAF"],
    [202, { "x-amzn-waf-action": "challenge" }, "AWS WAF"],
    [403, { server: "awselb/2.0" }, "AWS"],
    [403, { server: "AkamaiGHost" }, "Akamai"],
    [403, { "x-cache": "Error from cloudfront" }, "CloudFront"],
  ])("warns on %s from %o", (status, headers, vendor) => {
    const w = blockWarning(status, h(headers), "https://x.example");
    expect(w.severity).toBe("info");
    expect(w.title).toContain(vendor);
    expect(w.title).toContain("not read");
  });

  it.each([
    [200, { server: "AkamaiGHost" }],
    [200, { server: "awselb/2.0" }],
    [403, { server: "nginx" }],
    [404, { "x-cache": "Error from cloudfront" }],
    [403, {}],
  ])("stays quiet on %s from %o: no guessing", (status, headers) => {
    expect(blockWarning(status, h(headers), "https://x.example")).toBeNull();
  });
});
