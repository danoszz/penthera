/**
 * The first screen of a repo scan in a terminal. In 30 seconds a maker sees what
 * Penthera checked, what to act on, what it didn't check and one next step. It reads
 * the brief (brief.js), so the terminal and an agent hear the same verdict, items and
 * next step. Calm when little is found, and it never says the code is safe.
 */
import { VERDICTS } from "./brief.js";
import { nothingClaim } from "./unread.js";

const TOP = 3;
const FAMILY = { secrets: "secrets", routes: "routes and code patterns", "code-sinks": "code-execution sinks", "runtime-pins": "runtime versions" };
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const label = (s) => s.padEnd(12);
const WIDTH = 96;
// A secret finding names the key but carries no fix; this is the step every secret needs.
const SECRET_FIX = "Move it to an environment variable, then replace the key with its provider: it has been in your code.";

/** Parts joined by " · ", wrapped under a label so no line runs past the terminal. */
function wrapped(name, parts) {
  const L = [];
  let line = "";
  for (const p of parts) {
    if (line && (line.length + 3 + p.length) > WIDTH - 14) { L.push(line); line = p; } else line = line ? `${line} · ${p}` : p;
  }
  if (line) L.push(line);
  return L.map((l, i) => `  ${label(i ? "" : name)}${l}`);
}

function checkedParts(coverage) {
  const read = (coverage?.families || []).filter((f) => f.ran !== false && f.examined > 0);
  return read.map((f, i) => `${FAMILY[f.id] || f.label} in ${i ? f.examined : plural(f.examined, "file")}`);
}

function notCheckedParts(modes) {
  const not = [];
  if (!modes.includes("deps")) not.push("your packages (penthera deps .)");
  if (!modes.includes("agents")) not.push("your AI tool config (penthera agents .)");
  if (!modes.includes("url")) not.push("your running app (penthera <url>)");
  not.push("whether login, access rules and payments are right");
  return not;
}

function itemLines(items, start = 1) {
  const L = [];
  items.slice(0, TOP).forEach((i, n) => {
    const where = (i.where || []).join(", ");
    L.push(`  ${start + n}. ${i.title} · ${i.severity}${i.count > 1 ? ` · ${i.count} places` : ""}`);
    if (where) L.push(`     ${where}${i.more ? `, and ${i.more} more` : ""}`);
    const fix = i.fix || ((i.rules || []).includes("secrets") ? SECRET_FIX : i.why);
    if (fix) L.push(`     ${fix}`);
  });
  if (items.length > TOP) L.push(`  + ${items.length - TOP} more in the details below`);
  return L;
}

/** The first screen as plain lines, or [] when there's no brief to read. */
export function firstScreen(result) {
  const b = result?.brief;
  if (!b) return [];
  const modes = (result.modes || [result.mode]).flatMap((m) => String(m).split("+"));
  const L = [""];
  const checked = checkedParts(result.coverage);
  if (checked.length) L.push(...wrapped("Checked", checked));
  L.push("");

  const claim = nothingClaim(result);
  if (b.verdict === VERDICTS.fix) {
    L.push(`  Fix now: ${plural(b.act_on.length, "problem")} to act on.`, "", ...itemLines(b.act_on));
  } else if (b.verdict === VERDICTS.review && b.check_first.length) {
    L.push(`  Review: ${plural(b.check_first.length, "thing")} to check first.`, "", ...itemLines(b.check_first));
  } else if (claim) {
    L.push(`  ${claim}`);
  } else {
    L.push("  Nothing to fix first in what Penthera checked.");
  }
  if (b.counts?.noise) L.push(`  ${plural(b.counts.noise, "finding")} look${b.counts.noise === 1 ? "s" : ""} like test or example code; ${b.counts.noise === 1 ? "it's" : "they're"} in the details.`);

  L.push("", ...wrapped("Not checked", notCheckedParts(modes)));
  const gap = (b.not_checked || []).find((l) => !/does not prove|no finding is still not proof/i.test(l));
  if (gap) L.push(`  ${label("")}${gap}`);
  const next = b.next?.[0];
  if (next) L.push(`  ${label("Next")}${next.command}${next.why ? `   ${next.why.split(". ")[0].replace(/\.$/, "")}.` : ""}`);
  L.push("");
  return L;
}
