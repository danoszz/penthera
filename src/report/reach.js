/**
 * What a run reached and what it did not, in a line or two, so a quiet result
 * is never read as a full check. Printed on every scan.
 */
import { trimEndChars, globMatcher } from "../../lib/linear-text.js";

/** Why a live scan read nothing, for a target that didn't answer or answered with a server error. */
export function unreachableText({ httpStatus }, url) {
  return httpStatus ? `Target answered HTTP ${httpStatus}, so nothing was read: ${url}` : `Target unreachable: ${url}`;
}

/** Does a discovered path answer a route such as /api/users/:id? */
// `:name` is one segment, `*` any characters, `?` makes the character before
// it optional (as the regex this replaces read it). Matched in linear time: the
// route comes from the scanned code, and as a regex a route with many stars
// backtracked without end (Vercel Security Review, 2.3.2).
function matches(route, path) {
  const bare = trimEndChars(path.split("?")[0], "/") || "/";
  const tokens = [];
  for (let i = 0; i < route.length; i++) {
    if (route[i] === ":" && i + 1 < route.length && route[i + 1] !== "/") {
      while (i + 1 < route.length && route[i + 1] !== "/") i++;
      tokens.push({ plus: "seg" });
    } else if (route[i] === "*") tokens.push({ star: "any" });
    else if (route[i] === "?" && tokens.at(-1)?.lit !== undefined) tokens[tokens.length - 1] = { maybe: tokens.at(-1) };
    else if (route[i] === "?" && tokens.length) continue; // after `*`, `:name` or `?`: lazy, the same paths
    else tokens.push({ lit: route[i] });
  }
  return globMatcher(tokens).test(bare);
}

/**
 * @param {object[]} results the raw url and repo results of one run
 * @returns {string[]}
 */
export function reachLines(results) {
  const url = results.find((r) => r.mode === "url" || r.endpoints);
  const repo = results.find((r) => r.mode === "repo");
  const lines = [];
  const families = repo?.coverage?.families || [];
  // No server routes isn't a failure: a client-only app has none.
  if (families.some((f) => f.id === "routes" && !f.ran)) {
    lines.push("Route and code-pattern analysis: no server routes found, so there was nothing to read. A client-only app has none; if yours has some Penthera didn't see, pass --api-root <folder>.");
  }
  const notRun = families.filter((f) => !f.ran && f.id !== "routes").map((f) => f.label);
  if (notRun.length) lines.push(`Repo scan: not run: ${notRun.join(", ")}.`);
  if (!url) return lines;

  if (url.challenge) {
    lines.push(`Live scan: ${url.challenge.provider} answered instead of the site, so no paths were read and no injection probes were sent.`);
    return lines;
  }
  if (url.reachable === false) {
    lines.push(`Live scan: ${unreachableText(url, url.target || "the site")}.`);
    return lines;
  }
  if (!url.deepReach) {
    lines.push(`Live scan: ${url.endpoints?.discovered ?? 0} paths found. No injection probes were sent (they need --deep).`);
    return lines;
  }
  const { found, probed } = url.deepReach;
  const routes = [...new Set((repo?.attackSurface || []).map((r) => r.url))];
  if (routes.length) {
    const reached = routes.filter((route) => probed.some((path) => matches(route, path))).length;
    lines.push(`--deep reached ${reached} of ${routes.length} routes in your code. The rest got no injection probes.`);
  } else {
    lines.push(`--deep probed ${probed.length} of ${found} paths it found. Routes it did not find got no injection probes.`);
  }
  return lines;
}
