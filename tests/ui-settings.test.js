// Setup and the mode survive a restart: the port changes, the data folder doesn't.
import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSettings } from "../src/ui/server.js";

const fileIn = () => join(mkdtempSync(join(tmpdir(), "penthera-ui-")), "home", "ui.json");

describe("dashboard settings", () => {
  it("remembers the mode for the same data folder, and only the mode", () => {
    const file = fileIn();
    expect(createSettings({ file }).get().ux).toBeUndefined();
    createSettings({ file, reportsDir: "/private/app/reports" }).update({ ux: "advanced", offline: false });
    expect(createSettings({ file }).get().ux).toBe("advanced");
    expect(JSON.parse(readFileSync(file, "utf8"))).toEqual({ ux: "advanced" });
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it("ignores anything but the two modes, on disk and from the page", () => {
    const file = fileIn();
    const s = createSettings({ file });
    s.update({ ux: "advanced" });
    expect(s.update({ ux: "root" }).ux).toBe("advanced");
    writeFileSync(file, '{"ux":"root"}');
    expect(createSettings({ file }).get().ux).toBeUndefined();
    writeFileSync(file, "not json");
    expect(createSettings({ file }).get().ux).toBeUndefined();
  });

  it("writes nothing without a file, as in demo mode", () => {
    const s = createSettings({});
    expect(s.update({ ux: "advanced" }).ux).toBe("advanced");
  });
});
