import { describe, it, expect } from "vitest";
import { reachLines } from "../src/report/reach.js";

const repo = (urls) => ({ mode: "repo", attackSurface: urls.map((url) => ({ url })) });

describe("what a run reached", () => {
  it("says a refused scan reached nothing, with or without --deep", () => {
    const refused = { mode: "url", challenge: { provider: "Cloudflare", action: "challenge" }, endpoints: { discovered: 0 } };
    const words = ["Live scan: Cloudflare answered instead of the site, so no paths were read and no injection probes were sent."];
    expect(reachLines([refused])).toEqual(words);
    expect(reachLines([{ ...refused, deep: true }])).toEqual(words);
    expect(reachLines([refused]).join()).not.toContain("--deep");
  });

  it("counts the code's routes that --deep reached", () => {
    const url = { mode: "url", deepReach: { found: 40, probed: ["/api/users/7", "/api/calc?x=1", "/api/nope"] } };
    expect(reachLines([url, repo(["/api/calc", "/api/users/:id", "/api/admin", "/health"])]))
      .toEqual(["--deep reached 2 of 4 routes in your code. The rest got no injection probes."]);
  });

  it("gives no total it cannot know without the repo", () => {
    expect(reachLines([{ mode: "url", deepReach: { found: 40, probed: ["/api/a"] } }]))
      .toEqual(["--deep probed 1 of 40 paths it found. Routes it did not find got no injection probes."]);
  });

  it("says a live scan sent no probes, and names checks that did not run", () => {
    expect(reachLines([{ mode: "url", endpoints: { discovered: 5 } }])[0]).toMatch(/5 paths found\. No injection probes/);
    const skipped = { mode: "repo", coverage: { families: [{ label: "Secret scan", ran: true }, { label: "Route analysis", ran: false }] } };
    expect(reachLines([skipped])).toEqual(["Repo scan: not run: Route analysis."]);
  });

  it("does not let a route's dots act as a wildcard", () => {
    const url = { mode: "url", deepReach: { found: 1, probed: ["/apiXv1"] } };
    expect(reachLines([url, repo(["/api.v1"])])[0]).toContain("reached 0 of 1");
  });
});
