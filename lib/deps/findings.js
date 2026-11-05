/**
 * Findings for `penthera deps`: turn scanned packages, capability diffs,
 * typosquat hits and IOC hits into Penthera's standard finding shape.
 *
 * Pure functions with no file or network access, so the browser check on the
 * site (site/check) builds its findings with the same code as the CLI.
 */
import { CAPABILITIES, maxSeverity, capabilityWhy } from "./capabilities.js";
import { redactCommand } from "../agents/redact.js";


export const SOURCE = "deps-scan";
export const CATEGORY = "dependency-risk";
const KNOWN_BAD = ["ai-config-write", "ai-cli-invoke", "token-harvest"];
// Owners of these scopes legitimately manage their own AI tool config.
const KNOWN_BAD_EXEMPT = { "ai-config-write": ["@anthropic-ai/"], "ai-cli-invoke": ["@anthropic-ai/"] };
const EXEMPT_REGISTRIES = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

/**
 * Is this package really in an exempt scope? The lockfile's `name` is written
 * by whoever wrote the lockfile, so it proves nothing alone (Vercel review,
 * B02). The lock key path, the name in the package.json Penthera read, and
 * the registry URL the lockfile resolved it from must all name the same
 * scoped package. Anything missing or different: no exemption (R5).
 */
export function inExemptScope(pkg, scope) {
  const name = pkg?.name;
  if (typeof name !== "string" || !name.startsWith(scope) || name.length <= scope.length) return false;
  const path = String(pkg.path || "");
  const at = path.lastIndexOf("node_modules/");
  if (at < 0 || path.slice(at + "node_modules/".length) !== name) return false;
  if (pkg.manifestName !== name) return false;
  let url;
  try { url = new URL(pkg.resolved); } catch { return false; }
  // The public registry only: anyone can serve a tarball named for the scope
  // from their own host. A package from a mirror keeps its finding.
  if (url.protocol !== "https:" || !EXEMPT_REGISTRIES.has(url.host) || url.search || url.hash || url.username || url.password) return false;
  // npm's tarball path: /@scope/name/-/name-1.2.3.tgz
  const bare = name.slice(name.indexOf("/") + 1);
  let p;
  try { p = decodeURIComponent(url.pathname); } catch { return false; }
  const prefix = `/${name}/-/${bare}-`;
  return p.startsWith(prefix) && /^[^/]+\.tgz$/.test(p.slice(prefix.length));
}

// ── Findings ──────────────────────────────────────────────────────────────

const capList = (ids) => ids.map((id) => CAPABILITIES[id]?.label || id).join(", ");

function evidenceText(caps, ids) {
  const lines = [];
  for (const id of ids) {
    for (const e of (caps?.[id]?.evidence || []).slice(0, 2)) {
      lines.push(`${CAPABILITIES[id].label}: ${e.file}:${e.line} \`${e.snippet}\``);
    }
  }
  return lines.join("; ");
}

function firstEvidence(caps, ids) {
  for (const id of ids) {
    const e = caps?.[id]?.evidence?.[0];
    if (e) return e;
  }
  return null;
}

function finding({ title, severity, confidence, method, description, pkg, ev, capabilities, extra = {} }) {
  return {
    title,
    severity,
    category: CATEGORY,
    source: SOURCE,
    method,
    confidence,
    description,
    url: ev?.file || pkg.path,
    line: ev?.line || undefined,
    package: pkg.name,
    version: pkg.version,
    capabilities,
    ...extra,
  };
}

/** Risk findings that stand on their own, without a diff. */
export function riskFindings(pkg) {
  const out = [];
  const caps = pkg.capabilities;
  const at = `${pkg.name}@${pkg.version}`;
  if (pkg.partlyRead?.length) {
    out.push(finding({
      title: `${at}: a very long string was not read in full`,
      severity: "info",
      confidence: "confirmed",
      method: "deps-capability-scan",
      description: `Commands inside very long strings were not fully checked (${pkg.partlyRead.slice(0, 3).join(", ")}).`,
      pkg, ev: { file: `${pkg.path}/${pkg.partlyRead[0]}` }, capabilities: [],
    }));
  }
  if (pkg.unscanned) {
    out.push(finding({
      title: `${at}: could not be scanned`,
      severity: "high",
      confidence: "confirmed",
      method: "deps-capability-scan",
      description: `${pkg.unscanned}. Penthera fails closed here: treat this package as able to do anything, including run install scripts, until you have read its ${pkg.ecosystem === "pypi" ? "files" : "tarball"} yourself.`,
      pkg, ev: { file: pkg.ecosystem === "pypi" ? pkg.path : `${pkg.path}/package.json` }, capabilities: [],
      extra: { unscanned: pkg.unscanned },
    }));
  }
  if (pkg.scriptMismatch) {
    out.push(finding({
      title: `${at}: lockfile lists an install script the scan did not find`,
      severity: "high",
      confidence: "confirmed",
      method: "deps-capability-scan",
      description: "package-lock.json marks this package `hasInstallScript`, but the package.json Penthera read declares no preinstall, install or postinstall script and there is no binding.gyp. Either the lockfile was edited, or the tarball shows a scanner different files than npm installs. Do not install it until the difference is explained.",
      pkg, ev: { file: `${pkg.path}/package.json` }, capabilities: ["install-scripts"],
      extra: { scriptMismatch: true },
    }));
  }
  if (!caps) return out;
  const py = pkg.ecosystem === "pypi";
  const why = (id) => capabilityWhy(id, pkg.ecosystem);

  for (const id of KNOWN_BAD) {
    if (!caps[id]) continue;
    if ((KNOWN_BAD_EXEMPT[id] || []).some((scope) => inExemptScope(pkg, scope))) continue;
    const ev = caps[id].evidence[0];
    out.push(finding({
      title: `${at}: ${CAPABILITIES[id].label}`,
      severity: "critical",
      confidence: CAPABILITIES[id].confidence,
      method: "deps-capability-scan",
      description: `${why(id)} Evidence: ${evidenceText(caps, [id])}`,
      pkg, ev, capabilities: [id],
    }));
  }
  if (caps.obfuscated) {
    const ev = caps.obfuscated.evidence[0];
    out.push(finding({
      title: `${at}: obfuscated code`,
      severity: "high",
      confidence: "potential",
      method: "deps-capability-scan",
      description: `${why("obfuscated")} Signals at ${ev.file}:${ev.line}: ${ev.snippet}. Read the file before trusting it; minified code alone does not trigger this.`,
      pkg, ev, capabilities: ["obfuscated"],
    }));
  }
  if (pkg.exfil?.length) {
    const ev = pkg.exfil[0];
    out.push(finding({
      title: `${at}: serialises the whole environment next to network code`,
      severity: "high",
      confidence: "likely",
      method: "deps-capability-scan",
      description: `${py ? "os.environ" : "process.env"} (tokens, keys, CI secrets) is serialised within a few lines of a network call, the shape of credential exfiltration. Evidence: ${ev.file}:${ev.line} \`${ev.snippet}\`. ${evidenceText(caps, ["network"])}`,
      pkg, ev, capabilities: ["env-bulk", "network"],
    }));
  }
  if (pkg.remoteCode?.length) {
    const ev = pkg.remoteCode[0];
    out.push(finding({
      title: `${at}: runs code it downloads`,
      severity: "high",
      confidence: "likely",
      method: "deps-capability-scan",
      description: `${py ? "A downloaded file is started or made executable, or a response reaches exec," : "A network response reaches eval, Function or vm"} a few lines later: it runs whatever the server sends. Evidence: ${ev.file}:${ev.line} \`${ev.snippet}\`.`,
      pkg, ev, capabilities: py ? ["network"] : ["network", "eval"],
    }));
  }
  for (const ev of (pkg.sendsOut || []).slice(0, 1)) {
    out.push(finding({
      title: `${at}: sends command output out in its entry file`,
      severity: "medium",
      confidence: "likely",
      method: "deps-capability-scan",
      description: `A shell command collects system details and the file sends them out, when the package is loaded. Evidence: ${ev.file}:${ev.line} \`${ev.snippet}\`.`,
      pkg, ev, capabilities: ["shell", "network"],
    }));
  }
  for (const ev of (pkg.importRun || []).slice(0, 1)) {
    out.push(finding({
      title: `${at}: ${ev.what} when imported`,
      severity: "medium",
      confidence: "likely",
      method: "deps-capability-scan",
      description: `Module-level code, or a function it calls, runs as soon as the package is imported, before you call anything. A library has little reason to do this at import. Evidence: ${ev.file}:${ev.line} \`${ev.snippet}\`.`,
      pkg, ev, capabilities: [ev.cap],
    }));
  }
  for (const ev of (pkg.chatKey || []).slice(0, 1)) {
    out.push(finding({
      title: `${at}: sends to a chat bot or webhook whose key is in the code`,
      severity: "high",
      confidence: "likely",
      method: "deps-capability-scan",
      description: `A file with network code holds a chat bot token or a webhook URL with its key. A library has no reason to ship one; stealers use them to send what they collect. Evidence: ${ev.file}:${ev.line}.`,
      pkg, ev, capabilities: ["network"],
    }));
  }
  for (const ev of (pkg.remoteDeps || []).slice(0, 1)) {
    out.push(finding({
      title: `${at}: installs a dependency from ${ev.host}`,
      severity: "medium",
      confidence: "likely",
      method: "deps-capability-scan",
      description: `A dependency is a tarball off npm and the code hosts: what it installs can change at any time. Evidence: ${ev.file}:${ev.line} \`${ev.snippet}\`.`,
      pkg, ev, capabilities: [],
    }));
  }
  if (caps["install-scripts"]) {
    const ev = caps["install-scripts"].evidence[0];
    const hooks = Object.entries(pkg.installScripts).map(([h, cmd]) => `${h}: \`${redactCommand(cmd.slice(0, 400), cmd.slice(0, 8192)).slice(0, 100)}\``).join("; ");
    const risky = pkg.installRisk.length > 0;
    out.push(finding({
      title: `${at}: runs ${risky ? "a risky " : ""}install script`,
      severity: risky ? "medium" : "low",
      confidence: "confirmed",
      method: "deps-capability-scan",
      description: `${why("install-scripts")} ${hooks}.${risky ? ` Why it stands out: ${pkg.installRisk.join("; ")}.` : ""} ${py ? "Install from a wheel (`pip install --only-binary :all:`) so no build code runs, or read setup.py first." : "Install with `npm ci --ignore-scripts` if the package works without it."}`,
      pkg, ev, capabilities: ["install-scripts"],
    }));
  }
  // Python: .pth import lines and sitecustomize run on every interpreter start,
  // so installing the package is enough to run them. Medium even when the code
  // they load looks clean; high when it does not.
  const hooks = pkg.startupHooks || [];
  if (hooks.length) {
    const risky = hooks.find((h) => h.risk.length);
    const ev = risky || hooks[0];
    const kind = /\.pth$/i.test(ev.file) ? ".pth" : ev.file.split("/").pop();
    out.push(finding({
      title: `${at}: ${risky ? "runs risky code" : "runs code"} at every Python start (${kind})`,
      severity: risky ? "high" : "medium",
      confidence: "confirmed",
      method: "deps-capability-scan",
      description: `${why("startup-hook")} ${ev.file}:${ev.line} \`${ev.snippet}\`.${risky ? ` Why it stands out: ${risky.risk.join("; ")}.` : " Editable installs, setuptools and virtualenv ship .pth files like this; check it is one of those."}`,
      pkg, ev, capabilities: ["startup-hook"],
    }));
  } else if (caps["startup-hook"]) {
    const ev = caps["startup-hook"].evidence[0];
    out.push(finding({
      title: `${at}: writes a .pth file (code that runs at every Python start)`,
      severity: "medium",
      confidence: "potential",
      method: "deps-capability-scan",
      description: `${why("startup-hook")} Evidence: ${ev.file}:${ev.line} \`${ev.snippet}\`. Installers and environment tools do this legitimately; a library has no reason to.`,
      pkg, ev, capabilities: ["startup-hook"],
    }));
  }
  if (pkg.modified?.length) {
    out.push(finding({
      title: `${at}: ${pkg.modified.length} installed file(s) changed since install`,
      severity: "medium",
      confidence: "confirmed",
      method: "deps-capability-scan",
      description: `These files no longer match the hashes pip recorded in RECORD when the package was installed: ${pkg.modified.slice(0, 5).join(", ")}${pkg.modified.length > 5 ? ", …" : ""}. Something edited them afterwards: a local patch, or code planting itself in the environment. Reinstall the package and see if it comes back.`,
      pkg, ev: { file: pkg.modified[0], line: 1 }, capabilities: [],
      extra: { modified: pkg.modified },
    }));
  }
  return out;
}

/** .pth files in site-packages that no installed distribution claims. */
export function unownedHookFindings(hooks) {
  return hooks.map((h) => ({
    title: `Unowned startup hook ${h.file.split("/").pop()} in site-packages`,
    severity: h.risk.length ? "high" : "medium",
    category: CATEGORY,
    source: SOURCE,
    method: "deps-capability-scan",
    confidence: "confirmed",
    description: `${CAPABILITIES["startup-hook"].why} No installed distribution lists this file in its RECORD, so something wrote it after install. ${h.file}:${h.line} \`${h.snippet}\`.${h.risk.length ? ` The line itself uses ${h.risk.join(", ")}.` : ""} Delete it if you cannot trace where it came from.`,
    url: h.file,
    line: h.line,
    capabilities: ["startup-hook"],
  }));
}

// Capabilities that riskFindings already reports on their own.
const OWN_FINDING = new Set([...KNOWN_BAD, "obfuscated", "install-scripts", "startup-hook"]);

export function diffFindings(diff, ecosystem = "npm") {
  const out = [];
  const why = (id) => capabilityWhy(id, ecosystem);
  for (const a of diff.added) {
    const ids = a.capabilities || [];
    const notable = ids.filter((id) => id !== "env" && id !== "dynamic-require" && !OWN_FINDING.has(id));
    if (notable.length === 0) continue;
    out.push(finding({
      title: `New dependency ${a.name}@${a.version}: ${capList(notable)}`,
      severity: maxSeverity(notable.map((id) => CAPABILITIES[id].severity)),
      confidence: "likely",
      method: "deps-capability-diff",
      description: `A package that was not in the base tree. It can: ${notable.map(why).join(" ")} Evidence: ${evidenceText(a.pkg.capabilities, notable)}`,
      pkg: a.pkg, ev: firstEvidence(a.pkg.capabilities, notable), capabilities: notable,
      extra: { change: "added" },
    }));
  }
  for (const u of diff.upgraded) {
    if (!u.gained || u.gained.length === 0) continue;
    const sev = maxSeverity(u.gained.map((id) => CAPABILITIES[id].severity));
    out.push(finding({
      title: `${u.name} ${u.from} → ${u.to} gained ${capList(u.gained)}`,
      severity: sev,
      confidence: u.gained.some((id) => CAPABILITIES[id].confidence === "potential") && u.gained.length === 1 ? "potential" : "likely",
      method: "deps-capability-diff",
      description: `This upgrade can do things the previous version could not. ${u.gained.map(why).join(" ")} Evidence: ${evidenceText(u.pkg.capabilities, u.gained)}`,
      pkg: u.pkg, ev: firstEvidence(u.pkg.capabilities, u.gained), capabilities: u.gained,
      extra: { change: "upgraded", from: u.from },
    }));
  }
  const missing = diff.upgraded.filter((u) => u.unavailable);
  if (missing.length) {
    out.push({
      title: `${missing.length} upgraded package(s) not compared: old version not available offline`,
      severity: "info",
      category: CATEGORY,
      source: SOURCE,
      method: "deps-capability-diff",
      confidence: "confirmed",
      description: `No local copy to compare against for: ${missing.map((u) => `${u.name} ${u.from} → ${u.to}`).join(", ")}. ${ecosystem === "pypi"
        ? "Create the base environment (`uv sync` or `pip install -r requirements.txt` in a checkout of the base, in a .venv) and pass that folder to --diff; old wheels already in pip's or uv's cache are used automatically when their hash matches the base lockfile."
        : "Install the base tree (`npm ci --ignore-scripts` in a checkout of the base) and pass that folder to --diff, or rerun with --online to fetch the old tarballs from the registry."}`,
      url: ecosystem === "pypi" ? diff.lockfile || "requirements.txt" : "package-lock.json",
    });
  }
  return out;
}

export function typosquatFindings(hits, pkgByName, direct) {
  return hits.map((h) => {
    const pkg = pkgByName.get(h.name) || { name: h.name, version: null, path: "package-lock.json" };
    const isDirect = direct.has(h.name);
    return finding({
      title: `${h.name} looks like ${h.target} (${h.kind})`,
      severity: isDirect ? "medium" : "low",
      confidence: "potential",
      method: "deps-typosquat",
      description: `\`${h.name}\` is ${h.distance} edit(s) from \`${h.target}\` (#${h.rank} in the vendored popular-package list) and is not itself on that list. Typosquats and AI-hallucinated names (slopsquatting) look exactly like this. Check it is the package you meant to install${isDirect ? "" : ` and why a dependency pulls it in`}.`,
      pkg, ev: { file: pkg.path, line: undefined }, capabilities: [],
      extra: { typosquatOf: h.target, direct: isDirect },
    });
  });
}

/**
 * Rule-pack IOC hits: known-malicious versions (from the lockfile, installed
 * or not) and campaign hosts or dropped files found in package contents.
 */
export function iocFindings(tree, iocs, ecosystem = "npm") {
  const out = [];
  if (!iocs) return out;
  for (const p of tree) {
    const hits = [...iocs.matchPackage(p.name, p.version, ecosystem), ...(p.iocHits || [])];
    const seen = new Set();
    for (const h of hits) {
      const key = `${h.rule.pack}/${h.rule.id}/${h.type}/${h.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const r = h.rule;
      const at = `${p.name}@${p.version}`;
      const what = h.type === "package"
        ? `known-malicious version (${r.campaign})`
        : h.type === "file" ? `contains a file dropped by ${r.campaign}: ${h.value}` : `references ${r.campaign} exfiltration endpoint ${h.value}`;
      out.push(finding({
        title: `${at}: ${what}`,
        severity: r.severity,
        confidence: r.confidence,
        method: "deps-ioc",
        description: `${h.type === "package" ? `\`${at}\` is a published malicious version.` : `Indicator found in ${h.file}:${h.line}.`} Listed in rule pack ${r.pack}@${r.packVersion} (rule ${r.id}, recorded ${r.date}). Source: ${r.source}${r.description ? ` ${r.description}` : ""} ${ecosystem === "pypi"
          ? "Remove or pin away from this version, recreate the virtualenv rather than uninstalling into it (code that ran at interpreter start may have planted more), and treat any machine or CI runner that installed it as compromised: rotate the PyPI, GitHub, cloud and SSH credentials it could read."
          : "Remove or pin away from this version, reinstall with `npm ci --ignore-scripts`, and treat any machine or CI runner that installed it as compromised: rotate the npm, GitHub and cloud credentials it could read."}`,
        pkg: p, ev: h.type === "package" ? { file: p.path } : { file: h.file, line: h.line }, capabilities: [],
        extra: { ioc: { pack: r.pack, packVersion: r.packVersion, rule: r.id, type: h.type, value: h.value, campaign: r.campaign, source: r.source } },
      }));
    }
  }
  return out;
}

export function registryFindings(results, pkgByKey) {
  const out = [];
  for (const [key, r] of [...results].sort((a, b) => a[0].localeCompare(b[0]))) {
    const pkg = pkgByKey.get(key);
    if (!pkg) continue;
    for (const s of r.signals) {
      out.push(finding({
        title: `${key}: ${s.text}`,
        severity: s.severity,
        confidence: "confirmed",
        method: "deps-registry",
        description: `From npm registry metadata (--online). ${s.id === "publisher-change" ? "A new publisher on an established package is how account takeovers ship malware; check the release notes and diff." : s.id === "new-package" ? "Brand-new packages are where typosquats and slopsquats (names AI assistants hallucinate) live." : s.id === "fresh-version" ? "Most malicious versions are caught and pulled within days; waiting out a short cooldown on new releases avoids them." : ""}`,
        pkg, ev: { file: pkg.path }, capabilities: [],
        extra: { registrySignal: s.id },
      }));
    }
  }
  return out;
}

