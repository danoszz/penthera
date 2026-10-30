/**
 * /type: Penthera's type system, drawn with itself. Every sample below uses the
 * tokens in site/styles.css, so this page can't drift from the site. The rules
 * come from Robert Bringhurst, The Elements of Typographic Style, in our words;
 * the numbers are his sections.
 */
import { paperPage } from "./blog.mjs";

const SCALE = [
  ["t-poster", "42 to 124", "Helvetica", "The poster headline", "Is your site safe?"],
  ["t-h1", "40 to 88", "Helvetica", "Page titles", "Rules decide"],
  ["t-h2", "32 to 56", "Helvetica", "Section titles", "What it finds"],
  ["t-h3", "26 to 40", "Helvetica", "Post titles in a list", "We benchmarked ten scanners"],
  ["t-lead", "22 to 28", "Helvetica", "Standfirsts", "How do you test your own tool without fooling yourself?"],
  ["t-read", "18 to 20", "Charter", "Reading", "A tuned scanner knows the answers, so we sealed half of each dataset before anyone looked at it."],
  ["t-text", "17", "Helvetica", "Interface text", "Find out in seconds. Then fix it with your coding agent."],
  ["t-mono", "16.5", "Departure Mono", "Section heads in a post, inline code", "npx penthera --repo ."],
  ["t-small", "15", "Helvetica", "Captions and tables", "Square: dev half, tuned. Dot: test half."],
  ["t-note", "13", "Departure Mono", "Notes and small print", "Passive. Nothing stored. Your own site only."],
  ["t-label", "11", "Departure Mono", "Stickers and labels, at the font’s own size", "28 October 2026"],
];

const RULES = [
  ["2.1.2", "Keep lines to about 65 characters.", "Long lines lose the reader on the way back. The reading column is 35.5 rem wide and grows with the reader’s own text size."],
  ["2.2.2", "Measure vertical space in lines.", "One line of text is the unit, so the column keeps its beat past heads, lists and figures."],
  ["2.1.3", "Leave the right edge ragged.", "Browsers justify by stretching word gaps. A natural rag reads better, with no automatic hyphens."],
  ["3.5.1", "Let weight fall as size rises.", "Big type is already loud. Large heads are medium, small heads are bold, and each step changes one thing."],
  ["5.4", "Use real marks.", "Curly quotes, true apostrophes and single-character ellipses, set at build time. Code stays exactly as typed, so a command still pastes."],
  ["2.1.9", "Never fake a letter.", "No synthetic bold, italic or small caps. If a face lacks a style, we do without it."],
  ["6.5", "Give each face one job.", "Charter reads, Helvetica heads, Departure Mono labels. No fourth face."],
  ["9.5.3", "Match the ink to the paper.", "A cool near-black on light grounds. Warm blacks suit ivory, not gray."],
  ["1.1.1", "Spend the fun on the furniture.", "Stickers, blocks and colored keys live around the text, never behind it."],
];

const BREAKS = [
  ["Space between paragraphs.", "The book prefers indents. Space is easier for many readers on a screen."],
  ["A heavy title on the blog.", "Size with weight breaks 3.5.1 once, on purpose. It’s the one poster moment."],
  ["Lining numbers.", "Charter has no old-style figures on most devices, and we don’t fake them. Where the font has them, they appear."],
  ["13 px mono.", "Departure Mono is drawn at 11. Notes at 13 trade a little crispness for reading comfort."],
];

/** The page's Markdown copy, for agents. */
export function typeMarkdown({ origin }) {
  return `# Penthera type system

> How is type set on penthera.org?

## Scale

${SCALE.map(([t, px, face, use]) => `- \`--${t}\`: ${px} px, ${face}. ${use}.`).join("\n")}

## Rules

${RULES.map(([n, r, why]) => `- ${r} ${why} (Bringhurst ${n})`).join("\n")}

## Rules we break on purpose

${BREAKS.map(([r, why]) => `- ${r} ${why}`).join("\n")}

Source: ${origin}/type
`;
}

/** /type */
export function typeHtml({ origin, styles, foot }) {
  const body = `    <div class="paper-body ty-intro">
      <p class="terms-for">How is type set on penthera.org?</p>
      <p>One scale, three faces and one set of rules, on every page. They come from Robert Bringhurst’s <em>The Elements of Typographic Style</em>, read end to end and adapted to the screen. Every sample here uses the live tokens, so this page can’t drift from the site.</p>
    </div>
    <h2 class="sticker ty-head">Scale</h2>
    <ol class="ty-scale">
${SCALE.map(([t, px, face, use, sample]) => `      <li><p class="ty-meta"><code>--${t}</code><span>${px} px · ${face}</span><span>${use}</span></p><p class="ty-sample ty-${t}">${sample}</p></li>`).join("\n")}
    </ol>
    <h2 class="sticker ty-head">Rules</h2>
    <ol class="ty-rules">
${RULES.map(([n, rule, why]) => `      <li><p class="ttx-when">Bringhurst ${n}</p><h3>${rule}</h3><p>${why}</p></li>`).join("\n")}
    </ol>
    <h2 class="sticker ty-head">Rules we break on purpose</h2>
    <ol class="ty-rules">
${BREAKS.map(([rule, why]) => `      <li><h3>${rule}</h3><p>${why}</p></li>`).join("\n")}
    </ol>`;
  return paperPage({ title: "Type system", description: "The scale, faces and rules behind every page of penthera.org, adapted from The Elements of Typographic Style.",
    url: `${origin}/type`, path: "/type", h1: "Type system", ld: "", body, styles, theme: "/theme.js", foot, type: "website", feed: false, article: false, number: "P900", bar: "Penthera type",
    crumb: '<a class="tag" href="/">Penthera</a><span class="tag">Type</span>' });
}
