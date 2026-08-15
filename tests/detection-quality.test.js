/**
 * Detection-quality fixes: timing confirmation, randomized canary, template
 * matchers that no longer fire on SPA fallback pages, and the Retire.js
 * database failing loudly instead of reporting a false all-clear.
 */
import { describe, it, expect } from "vitest";
import { confirmTimingDelay, makeCanary } from "../lib/injections.js";
import { BUILT_IN_TEMPLATES } from "../lib/templates.js";

const resp = (elapsed) => ({ ok: true, elapsed });

describe("time-based injection confirmation", () => {
  it("confirms a delay that holds across repeats", async () => {
    const r = await confirmTimingDelay(async () => resp(3400), 200);
    expect(r.confirmed).toBe(true);
    expect(r.medianMs).toBe(3400);
  });

  it("rejects a one-off spike (jitter, GC pause, cold start)", async () => {
    // First repeat comes back fast, so the original spike was noise.
    const timings = [3400, 210, 205];
    let i = 0;
    const r = await confirmTimingDelay(async () => resp(timings[i++] ?? 200), 200);
    expect(r.confirmed).toBe(false);
  });

  it("rejects when the delay never clears the absolute floor", async () => {
    // Slow baseline app: everything is slow, nothing is injected.
    const r = await confirmTimingDelay(async () => resp(2600), 2500);
    expect(r.confirmed).toBe(false);
  });

  it("gives up if the endpoint stops responding", async () => {
    const r = await confirmTimingDelay(async () => ({ ok: false, elapsed: 0 }), 200);
    expect(r.confirmed).toBe(false);
  });
});

describe("XSS canary", () => {
  it("is randomized per probe, not a fixed fingerprintable string", () => {
    const a = makeCanary();
    const b = makeCanary();
    expect(a).not.toBe(b);
    expect(a).not.toBe("pnth3r4xss");
  });

  it("stays alphanumeric so no context re-encodes it", () => {
    expect(makeCanary()).toMatch(/^[a-z0-9]+$/);
  });
});

describe("built-in templates no longer fire on SPA fallback pages", () => {
  const byId = (id) => BUILT_IN_TEMPLATES.find((t) => t.id === id);

  it(".env.local template requires dotenv shape and rejects HTML", () => {
    const m = byId("env-local-exposure").http[0].matchers;
    // The bare "=" word matcher is gone: it matched every HTML attribute.
    expect(m.some((x) => x.type === "word" && x.words?.includes("="))).toBe(false);
    expect(m.some((x) => x.type === "regex")).toBe(true);
    expect(m.some((x) => x.type === "negative-word" && x.words.some((w) => /html|DOCTYPE/i.test(w)))).toBe(true);
  });

  it("firebase template requires a JSON body and rejects HTML", () => {
    const m = byId("firebase-database-open-read").http[0].matchers;
    expect(m.some((x) => x.type === "regex")).toBe(true);
    expect(m.some((x) => x.type === "negative-word" && x.words.some((w) => /html|DOCTYPE/i.test(w)))).toBe(true);
  });
});
