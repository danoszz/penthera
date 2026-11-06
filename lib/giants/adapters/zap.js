/**
 * The ZAP baseline scan (Apache-2.0): a passive spider and passive checks
 * against the live target, in URL scans only. ZAP's active scan is not
 * offered.
 *
 * Penthera runs `zap-baseline.py` from PATH: ZAP installed locally, or a
 * small wrapper of your own that runs it in ZAP's container with the current
 * folder mounted at /zap/wrk (docs/commands/giants.md shows one). `-z -silent`
 * stops ZAP from checking for add-on updates; `-I` keeps warnings from
 * failing the run. ZAP has no --version; its version is read from the report.
 */
import { clean, makeFinding } from "../finding.js";

const RISK = { 3: "high", 2: "medium", 1: "low", 0: "info" };
const MAX_INSTANCES = 20;

export default {
  id: "zap",
  area: "live",
  mode: "url",
  licence: "Apache-2.0",
  homepage: "https://www.zaproxy.org/docs/docker/baseline-scan/",
  minVersion: "2.15.0",
  tested: ["2.17.0"],
  bins: ["zap-baseline.py"],
  versionArgs: null,
  network: "target",
  install: { darwin: "Install ZAP (brew install --cask zap) or put a zap-baseline.py wrapper for the ghcr.io/zaproxy/zaproxy:stable image on PATH", linux: "Put a zap-baseline.py wrapper for the ghcr.io/zaproxy/zaproxy:stable image on PATH", other: "https://www.zaproxy.org/docs/docker/baseline-scan/" },

  command({ url, tmp }) {
    return { args: ["-t", url, "-J", "penthera-zap.json", "-I", "-z", "-silent"], output: `${tmp}/penthera-zap.json`, network: "target" };
  },
  // 0: pass; 1: at least one FAIL; 2: at least one WARN (not with -I); 3: ZAP itself failed.
  exitOk: (code) => code === 0 || code === 1 || code === 2,

  /** The ZAP version named in its report, or null. */
  reportVersion(text) {
    try { return JSON.parse(text)?.["@version"] || null; } catch { return null; }
  },

  parse(text, { tool }) {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { throw new Error(`not JSON: ${e.message}`); }
    if (!doc || typeof doc !== "object" || (doc.site != null && !Array.isArray(doc.site))) throw new Error("no site list");
    const version = doc["@version"] || tool.version;
    const out = [];
    for (const site of doc.site || []) {
      for (const a of site.alerts || []) {
        const cwe = Number(a.cweid) > 0 ? [`CWE-${Number(a.cweid)}`] : [];
        const severity = RISK[Number(a.riskcode)] || "info";
        const instances = (a.instances || []).slice(0, MAX_INSTANCES);
        for (const i of instances.length ? instances : [{ uri: site["@name"] }]) {
          out.push(makeFinding({
            tool: { ...tool, version }, ruleId: String(a.pluginid || a.alertRef || "zap"), ruleUrl: a.pluginid ? `https://www.zaproxy.org/docs/alerts/${encodeURIComponent(a.pluginid)}/` : null,
            category: "web", severity,
            title: `${clean(a.name || a.alert, 160)}${i.param ? ` (${clean(i.param, 60)})` : ""}`,
            description: `${clean(String(a.desc || "").replace(/<[^<>]+>/g, " "), 1000)}${i.param ? ` Parameter: ${clean(i.param, 100)}.` : ""}`,
            url: clean(i.uri || site["@name"], 500),
            key: { cwe, parameter: i.param || null },
            remediation: clean(String(a.solution || "").replace(/<[^<>]+>/g, " "), 1000) || null,
          }));
        }
      }
    }
    return out;
  },
};
