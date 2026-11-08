/**
 * The per-file cap on a recipe probe's findings. A file can repeat one pattern
 * thousands of times; a report with one line per hit says nothing more, and
 * its size would grow with the file. The worst are kept, never the first N, so
 * harmless decoys at the top of a file can't push a real hit out.
 */
export const PROBE_CAP = 25;

const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * @param {object[]} findings  one probe's findings in one file
 * @param {string} file
 * @param {number} [cap]
 * @returns {object[]} at most `cap`, most severe first; the last says how many more were left out
 */
export function keepWorst(findings, file, cap = PROBE_CAP) {
  const worst = worstKeeper(file, cap);
  findings.forEach((f, i) => worst.add(f, i));
  return worst.result();
}

/**
 * keepWorst as it goes: add findings one at a time and only the `cap` worst
 * are held, so a file with 240,000 hits never holds 240,000 findings.
 * `order` breaks ties between equally severe findings (lower comes first);
 * it is the offset in the file, or the order of adding.
 *
 * @param {string} file
 * @param {number} [cap]
 * @returns {{ add(f: object, order: number): void, result(): object[] }}
 */
export function worstKeeper(file, cap = PROBE_CAP) {
  const kept = [];
  let total = 0;
  const rank = (e) => SEV[e.f.severity] ?? 5;
  // True when a is worse (should be kept before) b.
  const before = (a, b) => rank(a) - rank(b) || a.order - b.order;
  return {
    add(f, order) {
      total++;
      const e = { f, order };
      if (kept.length < cap) {
        kept.push(e);
        return;
      }
      // Replace the least bad kept one when the new one ranks before it. cap is 25: a scan is cheap.
      let least = 0;
      for (let i = 1; i < kept.length; i++) if (before(kept[least], kept[i]) < 0) least = i;
      if (before(e, kept[least]) < 0) kept[least] = e;
    },
    result() {
      // Nothing left out: every finding, in file order.
      if (total <= cap) return [...kept].sort((a, b) => a.order - b.order).map(({ f }) => f);
      const out = [...kept].sort(before).map(({ f }) => ({ ...f }));
      const more = total - cap;
      const last = out[out.length - 1];
      last.description = `${last.description || ""} ${more} more like ${more === 1 ? "it" : "these"} in ${file} ${more === 1 ? "is" : "are"} not listed.`.trim();
      return out;
    },
  };
}
