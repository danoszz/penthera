/**
 * Organization domains for the E20-R study, from a pinned copy of the Public
 * Suffix List, private suffixes included. Study code only: the file sits under
 * bench/, which is not in the npm package, and it is never fetched at run time.
 * The product keeps src/utils/url.js.
 *
 * The list is under the Mozilla Public License 2.0; its header stays in the file.
 * To update it, fetch one commit by hand, change PSL_VERSION, and re-freeze the
 * protocol: a change after a run starts is a deviation.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath, domainToASCII } from "node:url";

export const PSL_FILE = join(dirname(fileURLToPath(import.meta.url)), "psl", "public_suffix_list.dat");
export const PSL_VERSION = Object.freeze({
  source: "https://github.com/publicsuffix/list",
  commit: "9dfbe81931367b3f0af21035c36ae7eeb830dd88",
  fetched: "2026-10-30",
  sections: "ICANN and private",
});

let rules = null;
function load() {
  rules = { exact: new Set(), wild: new Set(), except: new Set() };
  for (const raw of readFileSync(PSL_FILE, "utf8").split(/\r?\n/)) {
    const line = raw.trim().split(/\s/)[0];
    if (!line || line.startsWith("//")) continue;
    const ascii = (s) => domainToASCII(s) || s;
    if (line.startsWith("!")) rules.except.add(ascii(line.slice(1)));
    else if (line.startsWith("*.")) rules.wild.add(ascii(line.slice(2)));
    else rules.exact.add(ascii(line));
  }
  return rules;
}

export const pslSha256 = () => createHash("sha256").update(readFileSync(PSL_FILE)).digest("hex");

const clean = (host) => String(host).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");

/** The longest matching public suffix. An unlisted TLD is its own suffix, as the list's algorithm says. */
export function publicSuffix(host) {
  const { exact, wild, except } = rules ?? load();
  const name = clean(host);
  const labels = (domainToASCII(name) || name).split(".");
  for (let i = 0; i < labels.length; i++) {
    const here = labels.slice(i).join(".");
    if (except.has(here)) return labels.slice(i + 1).join(".");
    if (exact.has(here) || (i + 1 < labels.length && wild.has(labels.slice(i + 1).join(".")))) return here;
  }
  return labels.at(-1);
}

/** The suffix plus one label. An IP address, or a host that is itself a suffix, comes back unchanged. */
export function orgDomain(host) {
  const name = clean(host);
  if (isIP(name)) return name;
  const ascii = domainToASCII(name) || name;
  const suffix = publicSuffix(ascii);
  if (ascii === suffix) return ascii;
  const labels = ascii.split(".");
  return labels.slice(labels.length - suffix.split(".").length - 1).join(".");
}

/**
 * One name for one site: `www.example.com` is `example.com`. The list decides: when
 * the rest is itself a public suffix, as in `www.github.io`, the `www.` is a real label.
 */
export function siteKey(host) {
  const name = clean(host);
  if (!name.startsWith("www.")) return name;
  const rest = name.slice(4);
  return publicSuffix(rest) === (domainToASCII(rest) || rest) ? name : rest;
}

/** A site's organization. `www.github.io` is a tenant of a shared suffix, not the suffix: only `github.io` itself is that. */
export const siteOrg = orgDomain;
