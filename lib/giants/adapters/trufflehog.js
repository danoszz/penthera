/**
 * TruffleHog (AGPL-3.0, run as its own unmodified program): secrets in the
 * files of the scanned folder. Offline it runs with --no-verification. With
 * --giants-online it verifies keys against each provider's API, and a
 * verified key is critical.
 *
 * Its JSON lines carry the raw secret. Penthera keeps only a hash for the
 * merge key and masks every secret in the raw output before the evidence
 * bundle sees it.
 */
import { clean, lineOf, makeFinding, maskSecretsIn, relPath, secretHash, where } from "../finding.js";

function parseLines(text) {
  const rows = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t) continue;
    if (!t.startsWith("{")) throw new Error("output is not JSON lines");
    let o;
    try { o = JSON.parse(t); } catch (e) { throw new Error(`a line is not JSON: ${e.message}`); }
    if (o && typeof o === "object" && o.SourceMetadata) rows.push(o);
  }
  return rows;
}

function secretsOf(o) {
  return [o.Raw, o.RawV2, ...(o.SecretParts && typeof o.SecretParts === "object" ? Object.values(o.SecretParts) : [])]
    .filter((s) => typeof s === "string" && s.length >= 4);
}

export default {
  id: "trufflehog",
  area: "secrets",
  mode: "repo",
  licence: "AGPL-3.0 (run as its own program; not linked or shipped)",
  homepage: "https://github.com/trufflesecurity/trufflehog",
  minVersion: "3.90.0",
  tested: ["3.99.3"],
  bins: ["trufflehog"],
  versionArgs: ["--version"],
  network: "none",
  onlineFeature: "key verification",
  install: { darwin: "brew install trufflehog", linux: "Download a release from https://github.com/trufflesecurity/trufflehog/releases", other: "https://github.com/trufflesecurity/trufflehog/releases" },

  command({ root, online }) {
    return {
      args: ["filesystem", root, "--json", "--no-update", ...(online ? [] : ["--no-verification"])],
      output: "stdout",
      network: online ? "allow" : "deny",
    };
  },
  exitOk: (code) => code === 0,

  parse(text, { root, tool }) {
    return parseLines(text).map((o) => {
      const fs = o.SourceMetadata?.Data?.Filesystem || {};
      const file = relPath(root, fs.file);
      const line = lineOf(fs.line);
      const detector = clean(o.DetectorName || "unknown", 80);
      const verified = o.Verified === true;
      return makeFinding({
        tool, ruleId: detector, ruleUrl: "https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors",
        category: "secret",
        // Fixed table: a key the provider accepted is critical; an unverified match is high.
        severity: verified ? "critical" : "high",
        title: `${detector} secret${verified ? " (verified live)" : ""} in ${where(file, line)}`,
        description: `TruffleHog's ${detector} detector matched in \`${file}\`${line ? ` on line ${line}` : ""}${verified ? "; the provider accepted the key" : ", not verified"}. The value is not shown.`,
        file, line,
        key: { secretHashes: [...new Set(secretsOf(o).flatMap((s) => s.split(":")).filter((s) => s.length >= 4).map(secretHash))] },
        remediation: "Revoke and rotate the key, remove it from the code and the git history, and load it from a secret manager.",
      });
    });
  },

  /** Raw output for the evidence bundle, every secret masked. */
  sanitize(text) {
    let rows;
    try { rows = parseLines(text); } catch { return "(not kept: the output could not be parsed, so its secrets could not be masked)\n"; }
    const secrets = rows.flatMap((o) => [...secretsOf(o), ...(typeof o.Redacted === "string" ? [o.Redacted] : [])]);
    // A connection string's password also turns up on its own (ExtraData, a
    // second detector), so it is masked by itself too.
    for (const s of [...secrets]) {
      try {
        const pw = new URL(s).password;
        if (pw) secrets.push(pw, decodeURIComponent(pw));
      } catch { /* not a URL */ }
    }
    // Mask the parsed strings, then write each line again: a secret stays
    // hidden whatever escapes the raw line used for it (Go writes & as \u0026).
    const maskDeep = (v) => (typeof v === "string" ? maskSecretsIn(v, secrets)
      : Array.isArray(v) ? v.map(maskDeep)
        : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [maskSecretsIn(k, secrets), maskDeep(x)]))
          : v);
    const out = String(text).split("\n").filter((l) => l.trim()).map((l) => JSON.stringify(maskDeep(JSON.parse(l.trim()))));
    return out.length ? out.join("\n") + "\n" : "";
  },
};
