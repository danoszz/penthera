/**
 * Whether a run read the site it was pointed at. A firewall that answered, an address nothing
 * answered at and a server error all leave nothing to judge, so no surface may grade that or call
 * it clean. Every surface says these same words.
 */
import { uncheckedDeps } from "../../lib/deps/report.js";

export const SITE_NOT_READ = "We couldn't see your site.";
const NO_CLAIM = "so this says nothing about it, good or bad.";

/** What stopped the run reading the site, or null. A report from before `reachable` existed claims nothing. */
export function siteUnread(result) {
  const modes = result?.modes || [result?.mode];
  if (!modes.includes("url")) return null;
  if (result.challenge) return { text: `${result.challenge.provider} answered instead of the site, ${NO_CLAIM}` };
  if (result.reachable !== false) return null;
  return { text: result.httpStatus ? `It answered HTTP ${result.httpStatus}, ${NO_CLAIM}` : `Nothing answered at that address, ${NO_CLAIM}` };
}

/** A run with nothing to read: no agent config, no package code, or an empty folder. It has no grade, and no finding there is no result. */
export function readNothing(result) {
  const modes = (result?.modes || [result?.mode]).flatMap((m) => String(m).split("+"));
  if (modes.length === 1 && modes[0] === "repo") {
    const families = result.coverage?.families || [];
    return families.length > 0 && families.every((f) => !f.examined);
  }
  if (!modes.every((m) => m === "deps" || m === "agents")) return false;
  const audits = [result.agents && result.agents.grade === null && !result.agents.unparsed, result.deps && uncheckedDeps(result.deps)?.none === true].filter((x) => x !== undefined);
  return audits.length > 0 && audits.every(Boolean);
}

/**
 * Why a run can't be graded or called clean, as a short title and a sentence, or null when it read
 * what it was pointed at. Every grade and success sentence asks this first, and
 * tests/never-reads-clean.test.js holds them to it.
 */
export function notRead(result) {
  const site = siteUnread(result);
  if (site) return { title: SITE_NOT_READ, text: site.text };
  const broken = result?.agents?.grade === null ? result.agents.unparsed : 0;
  if (broken) return { partly: true, title: `${broken} config ${broken === 1 ? "file" : "files"} couldn't be read.`, text: "Penthera couldn't parse it, so this says nothing about what's in it." };
  if (readNothing(result)) return { title: "Nothing to assess.", text: "The check read nothing here, so this is not a clean result." };
  const deps = result?.deps ? uncheckedDeps(result.deps) : null;
  if (deps) return { partly: true, title: `${deps.total - deps.missing} of ${deps.total} packages read.`, text: "The rest weren't installed, so this says nothing about them." };
  if (result?.httpStatus === 403 && !result.challenge) return { title: "It answered HTTP 403.", text: "That may be a firewall's page, so this may say nothing about the site." };
  return null;
}

/** notRead as one line, for a report or a run's ending. */
export function nothingClaim(result) {
  const n = notRead(result);
  return n ? `${n.title} ${n.text}` : null;
}
