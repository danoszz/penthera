/**
 * `penthera.policy.json`: what an install may bring in without a human.
 *
 *   {
 *     "allow": ["@acme/*", "esbuild", "sharp@0.33.5"],
 *     "deny": ["ai-cli-invoke", "token-harvest"],
 *     "requireApproval": ["install-scripts", "obfuscated", "typosquat"]
 *   }
 *
 * `deny` and `requireApproval` list capability ids from lib/deps/capabilities.js,
 * plus three of the firewall's own: `typosquat` (a new name close to a popular
 * package), `unscanned` (a new package whose files could not be read safely)
 * and `script-mismatch` (the lockfile says the package has an install script
 * but the scan found none: the scanner and npm disagree about its files).
 *
 * Two floors no policy lowers, not even an allow entry: `script-mismatch` is
 * always denied, and `unscanned` always needs at least an approval. Both mean
 * Penthera could not see what would run, so "clean" would be a guess.
 * `allow` lists package names or globs (`*` matches any run of characters),
 * optionally pinned to one version with `@x.y.z`; an allowed package passes
 * both lists. A field left out keeps its default; a field given replaces it.
 * Everything here is pure: no files are read except the policy itself.
 *
 * The same file has optional sections for other commands: `licenses`
 * (penthera deps, lib/deps/license.js), `hook` (penthera hook run,
 * lib/hook/policy.js), `ai` (lib/ai/consent.js) and `giants` (--giants,
 * lib/giants/policy.js). Each comes back as null / defaults when absent.
 */
import { existsSync, lstatSync } from "node:fs";
import { dirname, join } from "node:path";
import { CAPABILITY_ORDER, CAPABILITIES } from "../deps/capabilities.js";
import { normalizeLicensePolicy } from "../deps/license.js";
import { normalizeHookPolicy } from "../hook/policy.js";
import { normalizeAiPolicy } from "../ai/consent.js";
import { normalizeGiantsPolicy } from "../giants/policy.js";
import { parseJson } from "../json-text.js";
import { globMatcher } from "../linear-text.js";
import { readRepoFile, isRefused } from "../fs-safe.js";

/** A policy file over 1 MiB is refused, not parsed. */
export const POLICY_MAX_BYTES = 1024 * 1024;

export const POLICY_FILE = "penthera.policy.json";

export const RULE_IDS = [...CAPABILITY_ORDER, "typosquat", "unscanned", "script-mismatch"];

/** Floors the policy cannot lower (see the header). */
export const ALWAYS_DENY = Object.freeze(["script-mismatch"]);
export const ALWAYS_APPROVE = Object.freeze(["unscanned"]);

export const RULE_LABELS = {
  ...Object.fromEntries(CAPABILITY_ORDER.map((id) => [id, CAPABILITIES[id].label])),
  typosquat: "looks like a popular package",
  unscanned: "could not be scanned",
  "script-mismatch": "lockfile lists an install script the scan did not find",
};

export const DEFAULT_POLICY = Object.freeze({
  allow: [],
  deny: [],
  requireApproval: ["install-scripts", "startup-hook", "ai-config-write", "ai-cli-invoke", "token-harvest", "obfuscated", "typosquat", "unscanned"],
});

/**
 * Validate and complete a policy object. Throws with a readable message on
 * unknown fields, unknown rule ids, or non-string entries.
 */
export function normalizePolicy(raw, label = POLICY_FILE) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${label}: expected a JSON object`);
  const known = ["allow", "deny", "requireApproval", "licenses", "hook", "ai", "giants", "$schema", "description"];
  const extra = Object.keys(raw).filter((k) => !known.includes(k));
  if (extra.length) throw new Error(`${label}: unknown field(s) ${extra.join(", ")} (expected allow, deny, requireApproval, licenses, hook, ai, giants)`);
  const out = {};
  for (const field of ["allow", "deny", "requireApproval"]) {
    const v = raw[field] ?? DEFAULT_POLICY[field];
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || !x.trim())) {
      throw new Error(`${label}: "${field}" must be an array of non-empty strings`);
    }
    out[field] = [...new Set(v.map((x) => x.trim()))];
  }
  for (const field of ["deny", "requireApproval"]) {
    const bad = out[field].filter((id) => !RULE_IDS.includes(id));
    if (bad.length) throw new Error(`${label}: unknown capability in "${field}": ${bad.join(", ")}. Known: ${RULE_IDS.join(", ")}`);
  }
  out.licenses = raw.licenses == null ? null : normalizeLicensePolicy(raw.licenses, `${label}: licenses`);
  out.hook = normalizeHookPolicy(raw.hook, `${label}: hook`);
  out.ai = normalizeAiPolicy(raw.ai, `${label}: ai`);
  out.giants = normalizeGiantsPolicy(raw.giants, `${label}: giants`);
  return out;
}

/**
 * Load the policy: an explicit path, else penthera.policy.json in the project,
 * else the defaults. Returns { policy, path, warning } (path null for defaults).
 *
 * The project's file is read only as a regular file inside the project, up to
 * 1 MiB: a FIFO or a link to /dev/zero would otherwise hang deps, the hook and
 * install. A refused file gives the defaults and a `warning` that names the
 * file and the reason; the caller says it. An explicit --policy file the user
 * named is followed through a link, but must still be a regular file.
 */
/** What a run says when penthera.policy.json is there but was not read. */
export const POLICY_NOT_READ = "The scan used the default policy and is incomplete: it exits 2.";

export function loadPolicy(root, explicitPath = null) {
  const path = explicitPath || join(root, POLICY_FILE);
  // lstat, not existsSync: a broken link is a policy file that is there and not read.
  let there = existsSync(path);
  if (!there && !explicitPath) { try { lstatSync(path); there = true; } catch { /* absent */ } }
  if (!there) {
    if (explicitPath) throw new Error(`Policy file not found: ${explicitPath}`);
    return { policy: normalizePolicy({}), path: null, warning: null };
  }
  let text;
  try {
    text = explicitPath
      ? readRepoFile(path, { followLinks: true, maxBytes: POLICY_MAX_BYTES })
      : readRepoFile(path, { root: dirname(path), label: POLICY_FILE, maxBytes: POLICY_MAX_BYTES });
  } catch (e) {
    // A policy can tighten the gate, so one that is there but not read is never
    // taken as "no policy": `refused` makes the run incomplete (exit 2), and a gate
    // that acts on the policy (install) stops.
    if (!explicitPath && (isRefused(e) || (e.code && e.code !== "ENOENT"))) {
      const reason = e.reason || e.code;
      return {
        policy: normalizePolicy({}), path: null,
        warning: `${isRefused(e) ? e.message : `${POLICY_FILE} was not read: ${reason}`}. ${POLICY_NOT_READ}`,
        refused: { file: POLICY_FILE, reason },
      };
    }
    throw new Error(`${path}: ${e.message}`);
  }
  let raw;
  try {
    raw = parseJson(text);
  } catch (e) {
    throw new Error(`${path}: ${e.message}`);
  }
  return { policy: normalizePolicy(raw, path), path, warning: null };
}

/** `a*b` with `*` as any characters, matched in linear time (a regex with many stars backtracked). */
const starGlob = (glob) => globMatcher([...glob].map((c) => (c === "*" ? { star: "any" } : { lit: c })));

/** Split "name@1.2.3" / "@scope/name@1.2.3" into { name, version }. */
function splitEntry(entry) {
  const at = entry.lastIndexOf("@");
  if (at > 0) return { name: entry.slice(0, at), version: entry.slice(at + 1) };
  return { name: entry, version: null };
}

/** The first allow entry matching name@version, or null. */
export function matchAllow(allow, name, version) {
  for (const entry of allow) {
    const e = splitEntry(entry);
    if (!starGlob(e.name).test(name)) continue;
    if (e.version && e.version !== "*" && e.version !== version) continue;
    return entry;
  }
  return null;
}

/**
 * Apply the policy to the changes an install would make.
 * @param {{ name, version, flags: string[] }[]} changes flags: the rule ids this change raises
 * @returns {{ items: object[], denied: object[], needsApproval: object[], clean: boolean }}
 */
export function evaluatePolicy(changes, policy) {
  const items = changes.map((c) => {
    const allowedBy = matchAllow(policy.allow, c.name, c.version);
    const deny = c.flags.filter((id) => ALWAYS_DENY.includes(id) || (!allowedBy && policy.deny.includes(id)));
    const approval = c.flags.filter((id) => !deny.includes(id)
      && (ALWAYS_APPROVE.includes(id) || (!allowedBy && policy.requireApproval.includes(id))));
    return { ...c, allowedBy, deny, approval };
  });
  const denied = items.filter((i) => i.deny.length);
  const needsApproval = items.filter((i) => i.approval.length);
  return { items, denied, needsApproval, clean: denied.length === 0 && needsApproval.length === 0 };
}
