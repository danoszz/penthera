#!/usr/bin/env node
/**
 * Draft release posts from the CHANGELOG section for a tag.
 *
 *   node scripts/marketing/release-post.mjs --tag v1.5.0 [--changelog CHANGELOG.md] [--json]
 *
 * Prints a Markdown block (a collapsed "Share this release" section) with a
 * LinkedIn post (about 600 characters) and an X/Bluesky post (280 at most).
 * Both have three bullets and the npm and GitHub links. A person copies and
 * posts them; nothing here talks to a social network. Used by
 * .github/workflows/publish.yml; unit-tested in tests/marketing.test.js.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

export const REPO_URL = "https://github.com/danoszz/penthera";
export const NPM_URL = "https://www.npmjs.com/package/penthera";
export const MARKER = "<!-- penthera-share -->";
export const LINKEDIN_TARGET = 600;
export const SHORT_MAX = 280;

/** The text under `## [x.y.z]` up to the next `## ` heading, or null. */
export function changelogSection(changelog, tag) {
  const version = String(tag).replace(/^v/, "");
  const lines = String(changelog).split("\n");
  const start = lines.findIndex((l) => l.startsWith(`## [${version}]`));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && l.startsWith("## "));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join("\n").trim();
}

/** Drop HTML comments, including unterminated and multi-line ones, without a regex. */
function stripComments(s) {
  let out = "";
  let i = 0;
  for (;;) {
    const start = s.indexOf("<!--", i);
    if (start < 0) return out + s.slice(i);
    out += s.slice(i, start);
    const end = s.indexOf("-->", start + 4);
    if (end < 0) return out;
    i = end + 3;
  }
}

/** Plain text: no HTML, no Markdown emphasis, code ticks, links or parenthesised asides. */
export function plain(s) {
  return stripComments(String(s))
    .replace(/[<>]/g, "")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[*_`]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function shorten(s, max) {
  if (s.length <= max) return s;
  const cut = s.slice(0, Math.max(0, max - 1));
  const at = cut.lastIndexOf(" ");
  return `${(at > max * 0.6 ? cut.slice(0, at) : cut).replace(/[\s,;:.(-]+$/, "")}…`;
}

/** First sentence of the summary paragraph under the version heading. */
export function intro(section) {
  const para = [];
  for (const l of section.split("\n")) {
    if (l.startsWith("#") || l.startsWith("- ")) break;
    if (!l.trim()) { if (para.length) break; continue; }
    para.push(l.trim());
  }
  const text = plain(para.join(" "));
  const m = text.match(/^.+?[.!?](?=\s|$)/);
  return m ? m[0] : text;
}

/**
 * The top bullets as { title, detail }. Bullets with a bold title come first
 * (they are the headline features), then the rest in order, Added before Fixed.
 */
export function highlights(section, n = 3) {
  const bullets = [];
  let heading = "";
  let cur = null;
  for (const l of section.split("\n")) {
    if (l.startsWith("### ")) { heading = l.slice(4).trim(); cur = null; continue; }
    if (l.startsWith("- ")) { cur = { heading, text: l.slice(2) }; bullets.push(cur); continue; }
    if (cur && /^\s+\S/.test(l)) cur.text += ` ${l.trim()}`;
    else if (!l.trim()) cur = null;
  }
  const parsed = bullets.map((b, i) => {
    const bold = b.text.match(/^\*\*(.+?)\*\*\s*(?:\([^)]*\))?\s*[:.,-]?\s*(.*)$/);
    const title = bold ? plain(bold[1]).replace(/\s*\[[^\]]*\]/g, "").replace(/[.:]$/, "") : "";
    const rest = plain(bold ? bold[2] : b.text);
    const first = (rest.match(/^.+?[.;:](?=\s|$)/)?.[0] || rest).replace(/[.;:]$/, "");
    return {
      title: title || shorten(first, 60),
      detail: title ? first : "",
      rank: (bold ? 0 : 2) + (/^fix/i.test(b.heading) ? 1 : 0),
      i,
    };
  });
  return parsed.sort((a, b) => a.rank - b.rank || a.i - b.i).slice(0, n).map(({ title, detail }) => ({ title, detail }));
}

const releaseUrl = (tag) => `${REPO_URL}/releases/tag/${tag}`;

/** LinkedIn: plain text, about 600 characters, never more than 700. */
export function linkedinPost({ tag, section }) {
  const hs = highlights(section);
  const lead = intro(section);
  const links = `npm: ${NPM_URL}\nGitHub: ${releaseUrl(tag)}`;
  const head = `Penthera ${tag} is out: open-source security for the apps and AI systems you ship.`;
  const build = (leadMax, detailMax) => [
    head,
    lead ? `\n${shorten(lead, leadMax)}` : "",
    "\nWhat's new:",
    ...hs.map((h) => `• ${h.title}${h.detail && detailMax > 0 ? `: ${shorten(h.detail, detailMax)}` : ""}`),
    "",
    links,
  ].join("\n");
  // Shrink the lead and the bullet details until the post fits the target.
  for (const [leadMax, detailMax] of [[200, 110], [160, 90], [120, 70], [90, 50], [60, 30], [0, 0]]) {
    const post = build(leadMax, detailMax);
    if (post.length <= LINKEDIN_TARGET) return post;
  }
  return build(0, 0);
}

// TODO(good-first-issue): X counts every link as 23 characters; add an X-only variant that uses that rule so bullets can be longer.
/** X/Bluesky: 280 characters at most, counted as plain characters (Bluesky's rule; stricter than X). */
export function shortPost({ tag, section }) {
  const hs = highlights(section);
  const head = `Penthera ${tag} is out.`;
  const tail = `${NPM_URL}\n${releaseUrl(tag)}`;
  const fixed = head.length + tail.length + 3 /* newlines */ + hs.length * 3; /* "• " + newline */
  let room = Math.floor((SHORT_MAX - fixed) / Math.max(1, hs.length));
  let post;
  do {
    post = [head, ...hs.map((h) => `• ${shorten(h.title, room)}`), tail].join("\n");
    room -= 4;
  } while (post.length > SHORT_MAX && room > 5);
  return post;
}

/** The collapsed Markdown block for the job summary and the release body. */
export function shareBlock({ tag, changelog }) {
  const section = changelogSection(changelog, tag);
  if (!section) throw new Error(`No "## [${String(tag).replace(/^v/, "")}]" section in the CHANGELOG.`);
  const li = linkedinPost({ tag, section });
  const sh = shortPost({ tag, section });
  return {
    linkedin: li,
    short: sh,
    markdown: [
      MARKER,
      "<details>",
      "<summary>Share this release</summary>",
      "",
      `**LinkedIn** (${li.length} characters)`,
      "",
      "```text",
      li,
      "```",
      "",
      `**X / Bluesky** (${sh.length}/${SHORT_MAX} characters)`,
      "",
      "```text",
      sh,
      "```",
      "",
      "Drafted from the CHANGELOG. Edit, then post by hand once the npm release is approved.",
      "</details>",
      "",
    ].join("\n"),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const { values } = parseArgs({
    options: { tag: { type: "string" }, changelog: { type: "string", default: "CHANGELOG.md" }, json: { type: "boolean", default: false } },
  });
  if (!values.tag) {
    console.error("Usage: release-post.mjs --tag vX.Y.Z [--changelog CHANGELOG.md] [--json]");
    process.exit(2);
  }
  try {
    const out = shareBlock({ tag: values.tag, changelog: readFileSync(values.changelog, "utf-8") });
    process.stdout.write(values.json ? JSON.stringify(out, null, 2) + "\n" : out.markdown);
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
