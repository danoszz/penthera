/**
 * Statistics for Penthera Bench (E1). No dependencies, so every number in
 * RESULTS.md can be checked against this file and its tests.
 *
 * References: Wilson (1927) score interval; Newcombe (1998) method 10 for a
 * difference of two independent proportions; Cohen (1960) kappa with the
 * large-sample variance of Fleiss, Cohen and Everitt (1969); Kish (1965)
 * effective sample size.
 */
import { mulberry32 } from "../prng.js";

export const Z95 = 1.959963984540054;

/** Wilson score interval for x successes in n trials. x may be fractional (weighted). */
export function wilson(x, n, z = Z95) {
  if (!(n > 0)) return { p: null, lo: null, hi: null, n: 0 };
  const p = x / n;
  const z2 = z * z;
  const d = 1 + z2 / n;
  const c = (p + z2 / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / d;
  return { p, lo: Math.max(0, c - h), hi: Math.min(1, c + h), n };
}

/**
 * Newcombe (1998) hybrid score interval (method 10) for p1 − p2, independent
 * samples. Returns { d, lo, hi }.
 */
export function newcombeDiff(x1, n1, x2, n2, z = Z95) {
  const a = wilson(x1, n1, z);
  const b = wilson(x2, n2, z);
  if (a.p == null || b.p == null) return { d: null, lo: null, hi: null };
  const d = a.p - b.p;
  return {
    d,
    lo: d - Math.sqrt((a.p - a.lo) ** 2 + (b.hi - b.p) ** 2),
    hi: d + Math.sqrt((a.hi - a.p) ** 2 + (b.p - b.lo) ** 2),
  };
}

/**
 * Cohen's kappa for two raters over nominal categories, with the
 * Fleiss–Cohen–Everitt (1969) large-sample standard error and a 95% interval.
 * @param {Array<[string, string]>} pairs rater A and rater B label per unit
 */
export function cohenKappa(pairs, z = Z95) {
  const n = pairs.length;
  if (n === 0) return { kappa: null, se: null, lo: null, hi: null, n: 0, agreement: null, expected: null };
  const cats = [...new Set(pairs.flat())].sort();
  const idx = new Map(cats.map((c, i) => [c, i]));
  const k = cats.length;
  const p = Array.from({ length: k }, () => new Array(k).fill(0));
  for (const [a, b] of pairs) p[idx.get(a)][idx.get(b)] += 1 / n;
  const row = p.map((r) => r.reduce((s, v) => s + v, 0));
  const col = cats.map((_, j) => p.reduce((s, r) => s + r[j], 0));
  const po = cats.reduce((s, _, i) => s + p[i][i], 0);
  const pe = cats.reduce((s, _, i) => s + row[i] * col[i], 0);
  if (pe === 1) return { kappa: null, se: null, lo: null, hi: null, n, agreement: po, expected: pe };
  const kappa = (po - pe) / (1 - pe);
  let t1 = 0;
  let t2 = 0;
  for (let i = 0; i < k; i++) {
    t1 += p[i][i] * (1 - (row[i] + col[i]) * (1 - kappa)) ** 2;
    for (let j = 0; j < k; j++) if (i !== j) t2 += p[i][j] * (col[i] + row[j]) ** 2;
  }
  const v = (t1 + (1 - kappa) ** 2 * t2 - (kappa - pe * (1 - kappa)) ** 2) / (n * (1 - pe) ** 2);
  const se = Math.sqrt(Math.max(0, v));
  return { kappa, se, lo: kappa - z * se, hi: kappa + z * se, n, agreement: po, expected: pe };
}

/** Kish effective sample size for unit weights. */
export function kishN(weights) {
  const s = weights.reduce((a, b) => a + b, 0);
  const s2 = weights.reduce((a, b) => a + b * b, 0);
  return s2 > 0 ? (s * s) / s2 : 0;
}

/** Percentile (linear interpolation) of a numeric array. */
export function percentile(values, q) {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const pos = (v.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return v[lo] + (v[hi] - v[lo]) * (pos - lo);
}

/**
 * Cluster bootstrap: resample clusters (projects) with replacement and apply
 * `stat` to each resample. Returns the array of statistics.
 * @param {string[]} clusters cluster ids
 * @param {(sample: string[]) => number|object} stat
 */
export function clusterBootstrap(clusters, stat, { reps = 10000, seed = 1 } = {}) {
  const rnd = mulberry32(seed);
  const out = [];
  for (let r = 0; r < reps; r++) {
    const sample = clusters.map(() => clusters[Math.floor(rnd() * clusters.length)]);
    out.push(stat(sample));
  }
  return out;
}

/** Holm–Bonferroni adjusted p-values, in input order. */
export function holm(pvalues) {
  const order = pvalues.map((p, i) => [p, i]).filter(([p]) => p != null).sort((a, b) => a[0] - b[0]);
  const adj = new Array(pvalues.length).fill(null);
  let running = 0;
  order.forEach(([p, i], rank) => {
    running = Math.max(running, Math.min(1, (order.length - rank) * p));
    adj[i] = running;
  });
  return adj;
}
