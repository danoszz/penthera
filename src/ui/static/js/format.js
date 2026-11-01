export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function ago(iso, now = Date.now()) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "-";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function stamp(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "-";
  const d = new Date(t);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function duration(ms) {
  if (ms == null || !Number.isFinite(ms)) return "-";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m${String(Math.round(s % 60)).padStart(2, "0")}s`;
}

export const pct = (x) => (x == null ? "-" : `${Math.round(x * 100)}%`);

/** Basename-ish short label for a project key (path or origin). */
export function shortProject(key) {
  if (!key) return "-";
  // A URL and a folder checked together are keyed "<url> + <absolute folder>".
  if (key.includes(" + ")) return key.split(" + ").map(shortProject).join(" + ");
  if (/^https?:\/\//.test(key)) return key.replace(/^https?:\/\//, "");
  const parts = key.split(/[\\/]/).filter(Boolean);
  return parts.slice(-2).join("/") || key;
}

/** The URL and folder of a project key: a folder, an origin, or "<url> + <absolute folder>". */
export function keyParts(key) {
  const k = String(key ?? "");
  const both = /^(https?:\/\/\S+) \+ (.+)$/.exec(k);
  if (both) return { url: both[1], folder: both[2] };
  return /^https?:\/\//.test(k) ? { url: k, folder: "" } : { url: "", folder: k };
}

/** Whether a run with this folder and URL belongs to a project. No project means the all-projects view. */
export function runBelongs(project, repo, url) {
  if (!project) return true;
  const p = keyParts(project);
  return Boolean((p.folder && repo === p.folder) || (p.url && url === p.url));
}

export const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

/** What a check looked at, in words; report modes are for the Advanced view. */
export const checkedWhat = (mode, unread) => {
  if (unread && String(mode).includes("url")) return String(mode).includes("repo") ? "your code, not your site" : "site not read";
  return ({ repo: "your code", url: "your site", "url+repo": "your site and code", deps: "your dependencies", agents: "your AI tools", "deps+agents": "your dependencies and AI tools", "agents+deps": "your dependencies and AI tools" })[mode] || "your app";
};

/** Rule text marks code with backticks; on this page they would print as typed. */
export const unticked = (s) => String(s ?? "").replace(/`/g, "");

/** The end of a check: what it found, or `claim` when it read nothing (src/report/unread.js). */
export function checkResult({ counts = {}, total = 0, claim = null, what = null, codeUnchecked = false }) {
  if (claim) return claim;
  const part = { deps: "your dependencies", agents: "your AI tools" }[what];
  const code = codeUnchecked ? " Your code hasn't been checked." : "";
  const notes = counts.info || 0;
  const found = total - notes;
  const top = [counts.critical && `${counts.critical} critical`, counts.high && `${counts.high} serious`].filter(Boolean).join(", ");
  if (found) return `Done. ${plural(found, "problem")} found${top ? `, ${top}` : ""}.${code}`;
  if (part) return `No problems in ${part}${notes ? `, ${plural(notes, "note")}` : ""}.${code}`;
  return notes ? `Done. No problems found, ${plural(notes, "note")}.` : "Done. Penthera found no problems.";
}
