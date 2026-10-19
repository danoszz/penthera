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
  if (/^https?:\/\//.test(key)) return key.replace(/^https?:\/\//, "");
  const parts = key.split(/[\\/]/).filter(Boolean);
  return parts.slice(-2).join("/") || key;
}

export const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
