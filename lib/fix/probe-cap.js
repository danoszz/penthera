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
  if (findings.length <= cap) return findings;
  const kept = findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => (SEV[a.f.severity] ?? 5) - (SEV[b.f.severity] ?? 5) || a.i - b.i)
    .slice(0, cap)
    .map(({ f }) => ({ ...f }));
  const more = findings.length - cap;
  const last = kept[kept.length - 1];
  last.description = `${last.description || ""} ${more} more like ${more === 1 ? "it" : "these"} in ${file} ${more === 1 ? "is" : "are"} not listed.`.trim();
  return kept;
}
