/**
 * A plain walk over a repository's files for the whitebox checks that read
 * source: every file whose name passes `wants`, in sorted order, skipping the
 * folders in `skip` at any depth and nested repositories (a folder with its
 * own .git). Symlinks are not followed as folders; a linked or non-regular
 * file whose name passes is returned too, so the read (readRepoFile) can
 * refuse it by name instead of a silent skip.
 */
import { existsSync, lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";

export const CODE_FILE = /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/;
export const COMMON_SKIP = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage", "vendor", ".vercel", ".turbo"]);
// More files than any project has at the top: stop and say so.
export const WALK_MAX_FILES = 20_000;

/**
 * A function from a character index to its 1-based line, built once per text
 * (line starts, then a binary search): counting line breaks from the start for
 * every hit is quadratic in the hits.
 */
export function lineIndex(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return (index) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= index) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
}

/**
 * @param {string} root
 * @param {{ wants: (name: string, rel: string) => boolean, skip?: Set<string>, max?: number, ignoredDirs?: Set<string> }} opts
 *   ignoredDirs: absolute paths of folders git ignores (build output, local folders), not entered
 * @returns {{ files: string[], truncated: boolean }} absolute paths
 */
export function walkFiles(root, { wants, skip = COMMON_SKIP, max = WALK_MAX_FILES, ignoredDirs = null }) {
  const files = [];
  let truncated = false;
  const visit = (dir, rel) => {
    if (truncated) return;
    let entries;
    try { entries = readdirSync(dir).sort(); } catch { return; }
    for (const entry of entries) {
      const full = join(dir, entry);
      const relPath = rel ? `${rel}/${entry}` : entry;
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isDirectory()) {
        if (skip.has(entry) || ignoredDirs?.has(full) || existsSync(join(full, ".git"))) continue;
        visit(full, relPath);
      } else if (wants(entry, relPath)) {
        if (files.length >= max) { truncated = true; return; }
        files.push(full);
      }
    }
  };
  visit(root, "");
  return { files, truncated };
}
