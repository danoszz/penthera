/**
 * Runtime advisories: is the PHP, nginx, Apache, Node.js, Python or OpenSSL
 * this app runs affected by a published security advisory?
 *
 * Evidence (./evidence.js) says which product and, if visible, which version.
 * Rule packs say which versions each advisory affects (`runtime-advisory`) and
 * which release lines are past end of support (`runtime-eol`). This module
 * compares the two and never claims more than the evidence carries:
 *
 *   exact upstream version, below the fix      affected          adv. severity, likely
 *   exact version on an end-of-life line       unsupported       listed in the end-of-life finding
 *                                                                (high), with its own severity
 *   version hidden, a floating tag, a distro
 *     build below the fix, a line the advisory
 *     does not list                            check on server   medium, needs-human-review
 *   exact version at or above every fix        patched           info
 *   no evidence of the product                 nothing           (absence is not "safe")
 *
 * A distro build (8.1.2-1ubuntu2.19, or any version behind a Server header
 * that names a distribution) is never "affected": distributions backport fixes
 * without changing the upstream number. A banner with no distribution token
 * for a product distributions backport (PHP/8.3.6 from Ubuntu 24.04 looks
 * exactly like upstream 8.3.6) gives at most `potential`, with a note to check
 * on the server; a pinned image or version file is upstream and stays `likely`. An advisory with a `condition` (an OS,
 * a SAPI, a module) gives at most `potential`, since neither a banner nor a pin
 * shows the condition. Matching uses only the pack's data and dates, never the
 * scan's clock, so the same input and packs give the same findings.
 */
import { rulesOf } from "../rules/index.js";
import { PRODUCTS } from "./products.js";
import { parseVersion, compareVersions, compareBranches } from "./versions.js";
import { evidenceFromResponse, evidenceFromRepo } from "./evidence.js";

export { evidenceFromResponse, evidenceFromRepo };

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const bySeverity = (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id);

function ids(adv) {
  const list = [...adv.cves, ...adv.ghsa];
  return list.length ? list.join(", ") : adv.id;
}

function advLine(adv) {
  const cvss = adv.cvss ? `, CVSS ${adv.cvss.version} ${adv.cvss.score}` : "";
  return `${adv.title} (${ids(adv)}${cvss}; ${adv.source})`;
}

/** End-of-life record for `branch`, if the pack says it had ended by the rule's own date. */
function eolOf(eolRules, product, branch) {
  if (!branch) return null;
  for (const r of eolRules) {
    if (r.product !== product) continue;
    const b = r.branches.find((x) => x.branch === branch);
    if (b && b.eol <= r.date) return { ...b, rule: r };
  }
  return null;
}

/** Merge evidence of the same product, version and kind seen in several places. */
function group(evidence) {
  const groups = new Map();
  for (const e of evidence) {
    const key = `${e.product}|${e.version?.raw ?? ""}|${e.kind}`;
    if (!groups.has(key)) groups.set(key, { ...e, wheres: [], raws: [] });
    const g = groups.get(key);
    if (!g.wheres.includes(e.where)) g.wheres.push(e.where);
    if (!g.raws.includes(e.raw)) g.raws.push(e.raw);
  }
  return [...groups.values()];
}

/**
 * Verdict of one advisory for one evidence group.
 * @returns {{ verdict: "affected"|"unsupported"|"check"|"patched"|"none", fix?: object, why?: string }}
 */
export function verdictFor(adv, ev, eol) {
  const p = PRODUCTS[ev.product];
  const branch = ev.version ? p.branchOf(ev.version) : null;
  const fix = branch ? adv.fixed.find((f) => f.branch === branch) : null;
  const newest = adv.fixed.map((f) => f.branch).sort(compareBranches).at(-1);
  const newerLine = branch && !fix && newest && compareBranches(branch, newest) > 0;
  // The flaw came in on the oldest listed line (`introduced`), so a line older
  // than that one never had it: httpd 2.2 and CVE-2021-41773 (2.4.49 only).
  const oldest = adv.fixed.reduce((a, f) => (!a || compareBranches(f.branch, a.branch) < 0 ? f : a), null);
  const olderLine = branch && !fix && oldest?.introduced && compareBranches(branch, oldest.branch) < 0;

  if (ev.kind === "present") return { verdict: "check", why: "the version is not visible" };
  if (newerLine || olderLine) return { verdict: "none" };

  if (ev.kind === "branch") {
    if (!fix && eol) return { verdict: "unsupported", why: `release line ${branch} is end of life` };
    return { verdict: "check", fix, why: fix ? `only the release line (${branch}) is pinned, not the exact version` : `the advisory lists no fix for release line ${branch}` };
  }

  // exact or distro: the upstream version is known.
  if (fix) {
    if (fix.introduced && compareVersions(ev.version, fix.introduced) < 0) return { verdict: "none" };
    // A pre-release of the version after the fix may predate the fix: PHP-8.4
    // says 8.4.28-dev from 8.4.27's RC until well after its release, while the
    // fix is merged only at release. Two patches on, it is in. (A pre-release
    // of the fixed version sorts below it and is affected.)
    if (ev.version.pre && compareVersions(ev.version, fix.version) >= 0) {
      const f = parseVersion(fix.version);
      const safe = !f.letters && compareVersions(ev.version.upstream, `${f.major}.${f.minor}.${f.patch + 2}`) >= 0;
      if (!safe) return { verdict: "check", fix, why: `it is a pre-release build (${ev.version.raw}), which may predate the fix` };
    }
    if (compareVersions(ev.version, fix.version) >= 0) return { verdict: "patched", fix };
    if (ev.kind === "distro") return { verdict: "check", fix, why: "it is a distribution build, which may carry the fix as a backport under the same upstream version" };
    return { verdict: "affected", fix };
  }
  if (ev.kind === "distro") return { verdict: "check", why: `release line ${branch} has no upstream fix, but distributions support some lines longer` };
  if (eol) return { verdict: "unsupported", why: `release line ${branch} is end of life` };
  return { verdict: "check", why: `the advisory lists no fix for release line ${branch}` };
}

// An exact version from a banner with no distribution token, for a product
// distributions backport: it may be a patched package under the same number.
const unmarked = (ev, p) => ev.kind === "exact" && ev.banner === true && p.backports;

function unmarkedNote(p, label) {
  return `Check on server: your distribution may have patched this under the same version number. The banner names no distribution, and Debian 11 to 13, Ubuntu 24.04 and later, and RHEL print plain upstream version numbers, so ${label} may be a distribution package. Run \`${p.checkCommand}\` on the server and ask the package manager which package provides it (\`dpkg -S\` or \`rpm -qf\` on the binary). For a package, look the CVE up in your distribution's security tracker.`;
}

function evidenceText(ev) {
  return ev.raws.map((r) => `- ${r}`).join("\n");
}

/**
 * Findings for a set of evidence.
 * @param {object[]} evidence  from evidenceFromResponse() or evidenceFromRepo()
 * @param {{ advisories?: object[], eol?: object[], url?: string }} [opts]  rules (default: the
 *   active packs); `url` is the scanned page, used as the finding location for black-box evidence
 */
export function matchRuntimeAdvisories(evidence, opts = {}) {
  const advisories = opts.advisories || rulesOf("runtime-advisory");
  const eolRules = opts.eol || rulesOf("runtime-eol");
  const findings = [];

  for (const ev of group(evidence)) {
    const p = PRODUCTS[ev.product];
    const label = ev.version ? `${p.name} ${ev.version.raw}` : p.name;
    const branch = ev.version ? p.branchOf(ev.version) : null;
    const eol = ev.kind === "present" ? null : eolOf(eolRules, ev.product, branch);
    // Where a pin is in several files, the Dockerfile ships, so it leads.
    const url = opts.url || ev.wheres.find((w) => /(^|\/)(Dockerfile|[^/]*\.dockerfile|docker-compose[^/]*)$/i.test(w)) || ev.wheres[0];
    const base = { url, category: "runtime-advisory", source: "runtime-advisory", evidence: ev.raws.join("\n") };
    const checks = [];
    const patched = [];
    const unfixed = [];
    const start = findings.length;
    const note = unmarked(ev, p) ? unmarkedNote(p, label) : "";

    for (const adv of advisories.filter((a) => a.product === ev.product).sort(bySeverity)) {
      const v = verdictFor(adv, ev, eol);
      if (v.verdict === "affected") {
        findings.push({
          ...base,
          severity: adv.severity,
          confidence: adv.condition || note ? "potential" : "likely",
          title: `${label} is affected by ${adv.title}`,
          description: [
            `${label} (seen in ${ev.wheres.join(", ")}) is below ${v.fix.version}, the first fixed version on the ${v.fix.branch} line, for ${advLine(adv)}.`,
            adv.kev ? `CISA lists it as exploited in the wild (Known Exploited Vulnerabilities catalog, added ${adv.kev}).` : "",
            adv.condition ? `It only applies when: ${adv.condition}. A version alone cannot show that, so confirm it on the server.` : "",
            note,
            adv.description || "",
            `Evidence:\n${evidenceText(ev)}`,
          ].filter(Boolean).join("\n\n"),
          remediation: `Upgrade ${p.name} to ${v.fix.version} or later on the ${v.fix.branch} line, or to a newer supported line. Then confirm with \`${p.checkCommand}\` on the server.`,
          cves: adv.cves,
          rule: adv.id,
        });
      } else if (v.verdict === "unsupported" && eol && ev.kind !== "distro") {
        // One problem, one fix: these go in the end-of-life finding below.
        unfixed.push(adv);
      } else if (v.verdict === "unsupported") {
        findings.push({
          ...base,
          severity: adv.severity,
          confidence: "potential",
          title: `${label} is on an end-of-life line with no fix for ${adv.title}`,
          description: [
            `${label} (seen in ${ev.wheres.join(", ")}) is on release line ${branch}, which ${p.name} stopped supporting on ${eol.eol} (${eol.rule.source}). The advisory ${advLine(adv)} lists fixes only for ${adv.fixed.map((f) => f.branch).join(", ")}, so this line gets none. Whether the flaw exists on ${branch} is not stated; treat it as affected.`,
            note,
            `Evidence:\n${evidenceText(ev)}`,
          ].filter(Boolean).join("\n\n"),
          remediation: `Move to a supported ${p.name} line (${adv.fixed.map((f) => `${f.branch}: ${f.version}+`).join(", ")}).`,
          cves: adv.cves,
          rule: adv.id,
        });
      } else if (v.verdict === "check") {
        checks.push({ adv, ...v });
      } else if (v.verdict === "patched") {
        patched.push(adv);
      }
    }

    if (checks.length) {
      const why = [...new Set(checks.map((c) => c.why))].join("; ");
      findings.push({
        ...base,
        severity: "medium",
        confidence: "needs-human-review",
        title: `${label} in use: check whether it is affected by ${checks.length === 1 ? checks[0].adv.title : `${checks.length} advisories`}`,
        description: [
          `Penthera cannot tell from outside whether ${label} has the fix: ${why}. That is not a sign it is safe.`,
          `Advisories to check:\n${checks.map((c) => `- ${advLine(c.adv)}${c.fix ? `: fixed in ${c.fix.version} on ${c.fix.branch}` : ""}`).join("\n")}`,
          `Evidence:\n${evidenceText(ev)}`,
        ].join("\n\n"),
        remediation: `Run \`${p.checkCommand}\` on the server (or in the container) and compare with the fixed versions above. For a distribution package, check the distribution's security tracker for the CVE instead of the upstream number.`,
        cves: [...new Set(checks.flatMap((c) => c.adv.cves))],
        rule: checks.map((c) => c.adv.id).join(","),
      });
    }

    if (eol) {
      const distro = ev.kind === "distro";
      // The fix for every unfixed advisory: the newest fixed version on each supported line.
      const lines = new Map();
      for (const f of unfixed.flatMap((a) => a.fixed || [])) {
        const prev = lines.get(f.branch);
        if (!prev || compareVersions(f.version, prev) > 0) lines.set(f.branch, f.version);
      }
      // End of life is certain; the listed advisories are only possible on it, so they
      // keep their own severity in the list and don't raise this row's.
      findings.push({
        ...base,
        severity: distro ? "medium" : "high",
        confidence: distro ? "needs-human-review" : note ? "potential" : "likely",
        title: distro
          ? `${label} is a distribution build of an end-of-life ${p.name} line`
          : `${label} is end of life: no more security fixes`,
        description: [
          `${p.name} ${branch} reached end of support on ${eol.eol} (${eol.rule.source}). Upstream publishes no security fixes for it, including for future advisories.`,
          unfixed.length ? `It won't get a fix for ${unfixed.length === 1 ? "this advisory" : `these ${unfixed.length} advisories`}, which may apply to it:\n${unfixed.map((a) => `- ${a.severity}: ${advLine(a)}`).join("\n")}` : "",
          distro ? "This is a distribution build, and some distributions keep patching a line after upstream stops. Check your distribution's support period for this package." : "",
          note,
          `Evidence:\n${evidenceText(ev)}`,
        ].filter(Boolean).join("\n\n"),
        remediation: lines.size
          ? `Move to a supported ${p.name} line (${[...lines].sort((a, b) => compareBranches(a[0], b[0])).map(([b, v]) => `${b}: ${v}+`).join(", ")}).`
          : `Upgrade to a supported ${p.name} release line.`,
        ...(unfixed.length ? { cves: [...new Set(unfixed.flatMap((a) => a.cves || []))], advisories: unfixed.map((a) => a.id) } : {}),
        rule: eol.rule.id,
      });
    }

    // "Has the fix" only when nothing else about this version needs attention.
    if (patched.length && findings.length === start) {
      findings.push({
        ...base,
        severity: "info",
        confidence: ev.kind === "exact" && !ev.version.pre ? "likely" : "potential",
        title: `${label} has the fix for ${patched.length === 1 ? patched[0].title : `${patched.length} known advisories`} (as advertised)`,
        description: [
          `The version ${ev.kind === "distro" ? "string" : "banner or pin"} is at or above the fixed version for: ${patched.map((a) => ids(a)).join(", ")}. This is what ${ev.wheres.join(", ")} says; a proxy or a stale banner can differ from what runs.`,
          `Evidence:\n${evidenceText(ev)}`,
        ].join("\n\n"),
      });
    }
  }
  return findings;
}

/** Black-box: runtime-advisory findings for a URL scan's homepage fingerprint. */
export function runtimeAdvisoriesForResponse(fingerprint, opts = {}) {
  return matchRuntimeAdvisories(evidenceFromResponse(fingerprint || {}, { phpPaths: opts.phpPaths }), opts);
}

/** White-box: runtime-advisory findings for a repository's runtime pins. */
export function runtimeAdvisoriesForRepo(root, opts) {
  return matchRuntimeAdvisories(evidenceFromRepo(root), opts);
}
