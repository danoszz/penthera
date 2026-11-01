/**
 * --giants in the reports: the "Coverage by area" table, each tool's status
 * and command line, and the findings other tools reported that Penthera did
 * not. Text from tool output is data: it is escaped for Markdown and stripped
 * of control characters for the terminal.
 */
import { mdInline } from "./md-escape.js";

const STATUS_TEXT = {
  ran: "ran",
  "not installed": "not installed",
  refused: "refused",
  skipped: "skipped",
  "timed out": "timed out",
  failed: "failed",
};

/** One short phrase per tool for the coverage table: "gitleaks 8.30.1 (4)", "trufflehog: not installed". */
export function toolPhrase(t) {
  if (t.status === "ran") return `${t.id}${t.version ? ` ${t.version}` : ""} (${t.findings})`;
  return `${t.id}: ${STATUS_TEXT[t.status] || t.status}`;
}

/** Covered when Penthera's own rules read something here or another tool ran. */
export const areaCovered = (a) => Boolean(a.pentheraRead?.read) || a.status === "covered";

/** "Penthera (7 files)", "Penthera: 0 files", "Penthera: run penthera deps", "Penthera: not run". */
export function pentheraPhrase(a) {
  const p = a.pentheraRead;
  return p ? (p.read ? `Penthera (${p.text})` : `Penthera: ${p.text}`) : "Penthera: not run";
}

/** "found by Penthera, gitleaks" for a finding that more than one tool reported, else null. */
export function foundByText(f) {
  const by = f.foundBy || [];
  if (by.length < 2) return null;
  return `found by ${by.map((x) => (x === "penthera" ? "Penthera" : x)).join(", ")}`;
}

/** Terminal lines (without the section rule), given the colour helpers. */
export function giantsTerminalLines(g, c, { pad = (s, n) => (s + " ".repeat(n)).slice(0, n), sevLabel = {}, sevColor = {} } = {}) {
  const L = [];
  L.push(`  ${c.bold("Coverage by area")} ${c.dim(`Penthera's own checks, then the other tools you have installed${g.online ? " (online: --giants-online)" : ""}`)}`);
  L.push("");
  for (const a of g.areas) {
    const tag = areaCovered(a) ? c.green("covered    ") : c.yellow("not covered");
    L.push(`  ${pad(a.label, 16)} ${tag} ${c.dim(`${pentheraPhrase(a)}, ${a.tools.length ? a.tools.map(toolPhrase).join(", ") : "no other tool"}`)}`);
  }
  const notes = g.tools.filter((t) => t.reason && t.status !== "ran");
  for (const t of notes) L.push(`  ${c.dim(`${t.id}: ${t.status}, ${strip(t.reason)}`)}`);
  const warn = g.tools.filter((t) => t.status === "ran" && t.reason);
  for (const t of warn) L.push(`  ${c.yellow(`${t.id}: ${strip(t.reason)}`)}`);
  if (!g.sandbox && g.tools.some((t) => t.status === "ran")) L.push(`  ${c.yellow("No network sandbox on this machine: the tools' network use was not enforced.")}`);
  if (g.requiredNotRun?.length) L.push(`  ${c.red(`Required by the policy file but did not run: ${g.requiredNotRun.join(", ")}`)}`);
  if (g.findings?.length) {
    L.push("");
    L.push(`  ${c.bold("Also reported by other tools")} ${c.dim(`(${g.findings.length}${g.failOn === "never" ? ", not counted toward the exit code" : ""})`)}`);
    L.push("");
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (const f of [...g.findings].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5))) {
      const colorFn = sevColor[f.severity] || c.dim;
      L.push(`  ${colorFn(sevLabel[f.severity] || "    ")}  ${strip(f.title)}  ${c.dim(`[${f.foundBy.join(", ")}]`)}`);
      const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.url;
      if (where) L.push(`  ${" ".repeat(6)} ${c.dim(strip(where))}`);
    }
  }
  return L;
}

/**
 * A code span in a table cell: one line, no backticks, and backslashes then
 * pipes escaped (as mdCell does), so text from a tool cannot end the cell.
 */
const codeCell = (s) => `\`${String(s).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/`/g, "'").replace(/\\/g, "\\\\").replace(/\|/g, "\\|")}\``;

const strip = (s) => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");

/** The Markdown section. */
export function giantsMarkdown(g) {
  const L = ["## Other tools (--giants)", ""];
  L.push(`Penthera ran the free tools installed on this machine and read their output. ${g.online ? "Online features were on (`--giants-online`)." : "Offline: no tool feature that contacts a service was used."} Merge: ${g.merge} (other tools' findings are listed below, not in Penthera's list, unless they match a Penthera finding). ${g.sandbox ? `Offline tools ran with the network denied (${g.sandbox}).` : "No network sandbox was available, so the tools' network use was not enforced."}`);
  L.push("");
  L.push("### Coverage by area", "");
  L.push("| Area | Penthera's own | Other tools | Status |");
  L.push("|------|----------------|-------------|--------|");
  for (const a of g.areas) {
    L.push(`| ${a.label} | ${mdInline(a.penthera)} (${a.pentheraRead ? `${a.pentheraRead.read ? "read " : ""}${mdInline(a.pentheraRead.text)}` : "not run"}) | ${a.tools.length ? mdInline(a.tools.map(toolPhrase).join(", ")) : "none"} | ${areaCovered(a) ? "covered" : "not covered"} |`);
  }
  L.push("");
  if (g.requiredNotRun?.length) L.push(`**Required by the policy file but did not run:** ${g.requiredNotRun.join(", ")}`, "");
  L.push("### Tools", "");
  L.push("| Tool | Version | Status | Findings | Network | Command | Exit |");
  L.push("|------|---------|--------|----------|---------|---------|------|");
  for (const t of g.tools) {
    const status = `${t.status}${t.reason ? `: ${mdInline(t.reason)}` : ""}`;
    L.push(`| ${t.id} | ${t.version || "-"} | ${status} | ${t.status === "ran" ? t.findings : "-"} | ${mdInline(t.network || "-")} | ${t.command ? codeCell(t.command) : "-"} | ${t.exitCode ?? "-"} |`);
  }
  L.push("");
  if (g.findings?.length) {
    L.push(`### Also reported by other tools (${g.findings.length})`, "");
    L.push(g.failOn === "never" ? "Not counted toward the exit code (`giants.failOn: never`)." : "Counted toward the exit code like Penthera's own findings.", "");
    L.push("| Severity | Finding | Where | Found by | Rule |");
    L.push("|----------|---------|-------|----------|------|");
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (const f of [...g.findings].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5))) {
      const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.url || "-";
      const rule = f.sources.map((s) => (s.ruleUrl ? `[${mdInline(s.ruleId)}](${encodeURI(s.ruleUrl)})` : mdInline(s.ruleId))).join(", ");
      L.push(`| ${f.severity} | ${mdInline(f.title)} | ${codeCell(where)} | ${mdInline(f.foundBy.join(", "))} | ${rule} |`);
    }
    L.push("");
  }
  return L;
}
