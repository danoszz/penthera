/**
 * What a run reached and what it did not, in a line or two, so a quiet result
 * is never read as a full check. Printed on every scan.
 */

/** Why a live scan read nothing, for a target that didn't answer or answered with a server error. */
export function unreachableText({ httpStatus }, url) {
  return httpStatus ? `Target answered HTTP ${httpStatus}, so nothing was read: ${url}` : `Target unreachable: ${url}`;
}

/** Does a discovered path answer a route such as /api/users/:id? */
function matches(route, path) {
  const bare = path.split("?")[0].replace(/\/+$/, "") || "/";
  const pattern = route.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/:[^/]+/g, "[^/]+").replace(/\*/g, ".*");
  return new RegExp(`^${pattern}$`).test(bare);
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
