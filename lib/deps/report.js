/**
 * Rendering for `penthera deps`: the terminal section, the Markdown section of
 * the full report, and a short PR comment centred on the capability diff.
 */
import { CAPABILITIES, CAPABILITY_ORDER } from "./capabilities.js";
import { FOOTER } from "../../src/report/footer.js";

const plain = (s) => s;
const label = (id) => CAPABILITIES[id]?.label || id;
const RISKY = new Set(["install-scripts", "shell", "network", "fs-write", "env-bulk", "eval", "obfuscated", "ai-config-write", "ai-cli-invoke", "token-harvest", "startup-hook"]);

function countsLine(counts) {
  return CAPABILITY_ORDER.filter((id) => counts[id]).map((id) => `${label(id)} ${counts[id]}`).join(" · ");
}

/**
 * Terminal lines for result.deps. `c` holds color helpers (bold, dim, red, yellow, green, cyan).
 */
export function formatDepsTerminal(deps, c = {}, opts = {}) {
  const k = { bold: plain, dim: plain, red: plain, yellow: plain, green: plain, cyan: plain, ...c };
  const L = [];
  const missing = deps.notInstalled.length;
  L.push(`  Packages   ${k.bold(String(deps.total))} in ${deps.lockfile} ${k.dim(`(${deps.format || `v${deps.lockfileVersion}`}${deps.prod ? ", prod only" : ""}, ${deps.network})`)}`);
  L.push(`  Scanned    ${deps.scanned}${missing ? k.yellow(` · ${missing} not installed or cached`) : ""}${deps.skippedOptional ? k.dim(` · ${deps.skippedOptional} optional for other platforms`) : ""}`);
  const cl = countsLine(deps.capabilityCounts);
  if (cl) L.push(`  Can do     ${k.dim(cl)}`);
  if (deps.online?.note) L.push(`  Online     ${k.dim(deps.online.note)}`);
  if (deps.typosquats.length) L.push(`  Names      ${k.yellow(`${deps.typosquats.length} look like popular packages`)}`);
  if (deps.licenses) L.push(`  Licenses   ${licenseLine(deps.licenses, k)}`);

  const d = deps.diff;
  if (d) {
    const gained = d.upgraded.filter((u) => u.gained?.length);
    const notable = d.added.filter((a) => (a.capabilities || []).some((id) => RISKY.has(id)));
    L.push(`  Diff       vs ${k.cyan(d.base)}: ${d.added.length} added · ${d.upgraded.length} changed · ${d.removed.length} removed`);
    L.push("");
    if (gained.length === 0 && notable.length === 0) {
      L.push(`  ${k.green("✓")} No package gained capabilities, and no new package can reach shell, network or install-time code.`);
    } else {
      L.push(`  ${k.bold("Gained capabilities")}`);
      L.push("");
      for (const u of gained) {
        L.push(`  ${k.yellow("▲")} ${k.bold(u.name)} ${u.from} → ${u.to}  ${k.red("+ " + u.gained.map(label).join(", "))}`);
        for (const id of u.gained) {
          for (const e of (d.evidence[`${u.name}@${u.to}`]?.[id] || []).slice(0, opts.verbose ? 5 : 1)) {
            L.push(`      ${k.dim(`${e.file}:${e.line}`)}  ${e.snippet}`);
          }
        }
      }
      for (const a of notable) {
        const ids = a.capabilities.filter((id) => RISKY.has(id));
        L.push(`  ${k.yellow("+")} ${k.bold(a.name)} ${a.version} ${k.dim("(new)")}  ${ids.map(label).join(", ")}`);
        for (const id of ids.slice(0, opts.verbose ? ids.length : 2)) {
          const e = d.evidence[`${a.name}@${a.version}`]?.[id]?.[0];
          if (e) L.push(`      ${k.dim(`${e.file}:${e.line}`)}  ${e.snippet}`);
        }
      }
    }
    const lost = d.upgraded.filter((u) => u.lost?.length);
    if (lost.length && opts.verbose) {
      L.push("");
      for (const u of lost) L.push(`  ${k.green("▼")} ${u.name} ${u.from} → ${u.to}  ${k.dim("- " + u.lost.map(label).join(", "))}`);
    }
    const unavailable = d.upgraded.filter((u) => u.unavailable);
    if (unavailable.length) {
      L.push("");
      L.push(`  ${k.dim(`Not compared (old version not available offline): ${unavailable.map((u) => `${u.name} ${u.from}`).join(", ")}`)}`);
    }
  }
  return L;
}

// Package names, versions, paths and snippets come from the lockfile and the
// package files, so in a PR comment they are attacker-controlled text.
const MAX_FIELD = 200;
const ZW = "\u200b"; // zero-width space: breaks mentions, refs and autolinks invisibly
const cap = (s) => {
  const t = String(s ?? "").replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ");
  return t.length > MAX_FIELD ? `${t.slice(0, MAX_FIELD - 1)}…` : t;
};
/** Neutralise GitHub's text-level features: @mentions, #refs and bare-URL autolinks. */
const defuse = (t) => t
  .replace(/@/g, `@${ZW}`)
  .replace(/#/g, `#${ZW}`)
  .replace(/:\/\//g, `:${ZW}//`)
  .replace(/\bwww\./gi, (m) => `${m.slice(0, 3)}${ZW}.`);

/** Plain text safe inside Markdown (tables included): no HTML, links, images, emphasis, mentions. */
export function esc(s) {
  const t = cap(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/[\\`*_{}[\]()!|~]/g, (c) => `\\${c}`);
  return defuse(t);
}

/**
 * An inline code span: one line, no backticks, no table pipes, no angle
 * brackets (an HTML tag that starts before a code span outranks it), capped.
 */
export function code(s) {
  return "`" + defuse(cap(s).replace(/`/g, "ˋ").replace(/\|/g, "¦").replace(/</g, "‹").replace(/>/g, "›")) + "`";
}

/** Capability diff as Markdown (used in the full report and the PR comment). */
export function formatDiffMarkdown(deps) {
  const d = deps.diff;
  const L = [];
  if (!d) return "";
  const gained = d.upgraded.filter((u) => u.gained?.length);
  const added = d.added.filter((a) => (a.capabilities || []).length);
  L.push(`Compared against \`${esc(d.base)}\`: **${d.added.length}** added · **${d.upgraded.length}** changed · **${d.removed.length}** removed.`);
  L.push("");
  if (gained.length === 0 && !added.some((a) => a.capabilities.some((id) => RISKY.has(id)))) {
    L.push("No package gained capabilities, and no new package can reach shell, network or install-time code.");
    L.push("");
  }
  if (gained.length) {
    L.push("### Upgrades that gained capabilities");
    L.push("");
    L.push("| Package | Version | Gained | Evidence |");
    L.push("|---|---|---|---|");
    for (const u of gained) {
      const ev = u.gained.map((id) => d.evidence[`${u.name}@${u.to}`]?.[id]?.[0]).filter(Boolean)[0];
      L.push(`| **${esc(u.name)}** | ${esc(u.from)} → ${esc(u.to)} | ${u.gained.map(label).join(", ")} | ${ev ? `${code(`${ev.file}:${ev.line}`)}` : ""} |`);
    }
    L.push("");
  }
  if (added.length) {
    L.push("### New packages");
    L.push("");
    L.push("| Package | Version | Can do |");
    L.push("|---|---|---|");
    for (const a of added) L.push(`| ${esc(a.name)} | ${esc(a.version)} | ${a.capabilities.map((id) => (RISKY.has(id) ? `**${label(id)}**` : label(id))).join(", ")} |`);
    L.push("");
  }
  const unavailable = d.upgraded.filter((u) => u.unavailable);
  if (unavailable.length) {
    L.push(`> Not compared, old version not available offline: ${unavailable.map((u) => `${esc(u.name)} ${esc(u.from)}`).join(", ")}. Install the base tree and pass it to \`--diff\`${deps.ecosystem === "pypi" ? "" : ", or use \`--online\`"}.`);
    L.push("");
  }
  const withEvidence = [...gained.map((u) => [`${u.name}@${u.to}`, u.gained]), ...added.map((a) => [`${a.name}@${a.version}`, a.capabilities.filter((id) => RISKY.has(id))])]
    .filter(([, ids]) => ids.length);
  if (withEvidence.length) {
    L.push("<details><summary>Evidence (file:line)</summary>");
    L.push("");
    for (const [key, ids] of withEvidence) {
      L.push(`**${esc(key)}**`);
      L.push("");
      for (const id of ids) {
        for (const e of (d.evidence[key]?.[id] || []).slice(0, 3)) L.push(`- ${label(id)}: ${code(`${e.file}:${e.line}`)} ${code(e.snippet)}`);
      }
      L.push("");
    }
    L.push("</details>");
    L.push("");
  }
  return L.join("\n");
}

/** Dependencies section of the full Markdown report. */
/** One-line license policy summary for the terminal and Markdown. */
export function licenseLine(l, k = { red: plain, yellow: plain, green: plain, dim: plain }) {
  const issues = [
    l.breaches && k.red(`${l.breaches} breach the policy`),
    l.unlicensed && k.red(`${l.unlicensed} UNLICENSED`),
    l.missing && k.yellow(`${l.missing} without a license`),
    l.unknown && k.yellow(`${l.unknown} unknown or custom`),
  ].filter(Boolean);
  const tail = [l.exempt && `${l.exempt} exempt`, l.notChecked && `${l.notChecked} not installed (v1 lockfile)`].filter(Boolean);
  return `${l.checked} checked against "${l.policy}": ${issues.length ? issues.join(", ") : k.green("all allowed")}${tail.length ? k.dim(` · ${tail.join(" · ")}`) : ""}`;
}

export function formatDepsMarkdown(deps) {
  const L = [];
  L.push("## Dependencies");
  L.push("");
  L.push(`**${deps.total}** packages in \`${esc(deps.lockfile)}\` (${deps.format ? esc(deps.format) : `lockfile v${deps.lockfileVersion}`}${deps.prod ? ", production only" : ""}), ${deps.scanned} scanned ${deps.network}.${deps.notInstalled.length ? ` ${deps.notInstalled.length} not installed or cached.` : ""}`);
  L.push("");
  const rows = CAPABILITY_ORDER.filter((id) => deps.capabilityCounts[id]);
  if (rows.length) {
    L.push("| Capability | Packages |");
    L.push("|---|---|");
    for (const id of rows) L.push(`| ${label(id)} | ${deps.capabilityCounts[id]} |`);
    L.push("");
  }
  if (deps.licenses) {
    L.push(`**Licenses:** ${licenseLine(deps.licenses)}.`);
    L.push("");
  }
  if (deps.diff) {
    L.push("### Capability diff");
    L.push("");
    L.push(formatDiffMarkdown(deps));
  }
  L.push(`_Static analysis of package code, offline. A capability is what code can do, not proof it is malicious. Typosquat names checked against ${esc(deps.popularList)}._`);
  L.push("");
  return L.join("\n");
}

const MARKER = "<!-- penthera-deps -->";

/** Short PR comment: the capability diff plus the risk findings. */
export function formatPrComment(result, opts = {}) {
  const deps = result.deps;
  const L = [MARKER, "## Dependency capability diff", ""];
  if (deps.diff) L.push(formatDiffMarkdown(deps));
  else L.push(`No base to compare against; ${deps.total} packages scanned.\n`);
  const risks = (result.findings || []).filter((f) => f.severity !== "info" && f.method !== "deps-capability-diff");
  if (risks.length) {
    L.push("### Risk signals");
    L.push("");
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    for (const f of [...risks].sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4))) {
      L.push(`- **${f.severity}** ${esc(f.title)}${f.confidence === "potential" ? " _(potential)_" : ""}${f.url ? ` ${code(`${f.url}${f.line ? `:${f.line}` : ""}`)}` : ""}`);
    }
    L.push("");
  }
  L.push(`<sub>[penthera deps](https://github.com/danoszz/penthera)${opts.version ? ` v${opts.version}` : ""}: offline static analysis, no telemetry. Capabilities are what code can do, not a verdict.</sub>`);
  if (opts.footer !== false) L.push("", FOOTER);
  return L.join("\n") + "\n";
}
