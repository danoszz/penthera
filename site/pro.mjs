/**
 * Penthera Pro (/pro; /upkeep redirects here). A horizontal poster: one
 * statement per panel, read by scrolling down as usual, and the row slides
 * left (/pro.js pins it and maps the page's vertical scroll to it). With no
 * script the panels stack vertically and everything still works.
 *
 *   hero → is the free tool enough? → rules decide → day, week, month → ranks → your code stays → price
 *   → calculator → waitlist
 *
 * The ranks come from bench/public/published.json at build time, the same file
 * as /benchmarks, so the page cannot drift from the published results.
 *
 * Pro is an experiment, not a sale: the page asks whether anyone needs more
 * than the free agent, and the waitlist is how the need is measured. The header is a canvas sketch (/pro.js): a
 * dithered ASCII swirl in brushed steel and Penthera blue that follows the
 * pointer. It is decoration only (aria-hidden); the heading is real text.
 *
 * Nothing is stored: the calculator and the waitlist are one form that only
 * writes an email (mailto) the reader sends. The CSP allows no inline script
 * or style and no form submission (form-action 'none'), so /pro.js turns the
 * form into the email; with no script, the plain mailto link still works.
 */

import { RANK_INTERVALS, tiedPhrase } from "./benchmarks.mjs";

const esc =(s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export const WAITLIST_MAIL = "daan@penthera.org";
export const waitlistHref = (body = "I am: \nI'd want: \nBudget a month: \nAnything else: \n") =>
  `mailto:${WAITLIST_MAIL}?subject=${encodeURIComponent("Penthera Pro waitlist")}&body=${encodeURIComponent(body)}`;

const ROLES = ["Developer", "Designer", "Founder", "Agency", "Something else"];
const WANTS = [
  "A daily watch on what I shipped",
  "A dashboard with history",
  "Signed monthly reports",
  "A person to ask, now and then",
  "Checks my agents can call and pay for",
  "Nothing more: the free tool is enough",
];

const CARDS = [
  ["01", "Every day: what you shipped, checked again.", "Pro matches the dependency list you shipped against new advisories every day: OSV, the CISA known-exploited list and EPSS. If something you shipped becomes known-bad, you get an email or a GitHub issue."],
  ["02", "Every week: your sites, from the outside.", "Passive checks on the domains you've verified: certificates, headers, CSP, and keys exposed in your bundles. Nothing is attacked."],
  ["03", "Every month: a signed report.", "Written from your stored results, for you, your client or your auditor, with evidence for the Cyber Resilience Act. A dashboard with the history in between."],
];

// The calculator's sliders: the reader's own numbers, nothing assumed.
const SLIDERS = [
  { name: "hours", label: "Hours a month your team spends on security now", min: 0, max: 160, step: 5, value: 20, unit: "h", hint: "160 hours is one full-time person." },
  { name: "rate", label: "What an hour of that time costs", min: 40, max: 200, step: 10, value: 90, unit: "$", hint: "Salary and overhead, per hour." },
];


// One drawing per card, decoration only (aria-hidden), in steel and blue. They
// illustrate; they carry no numbers, so they claim nothing.
const STEEL_DEFS = (id) => `<defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="0.45" stop-color="#d3d9e0"/><stop offset="0.55" stop-color="#8f98a6"/><stop offset="1" stop-color="#e3e8ee"/></linearGradient><linearGradient id="${id}-b" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5a5aff"/><stop offset="0.55" stop-color="#0000ed"/><stop offset="1" stop-color="#0000b8"/></linearGradient></defs>`;

const VISUALS = {
  // 02 Every week: a passive check of your site, in the terminal.
  "02": `<svg class="pro-visual" viewBox="0 0 320 180" aria-hidden="true" focusable="false">${STEEL_DEFS("pv1")}
    <rect x="0.5" y="0.5" width="319" height="179" class="pv-frame"/>
    <rect x="0.5" y="0.5" width="319" height="24" fill="url(#pv1)" stroke="rgba(0,0,0,0.25)"/>
    <circle cx="14" cy="12.5" r="4" fill="#fff" stroke="rgba(0,0,0,0.35)"/><circle cx="28" cy="12.5" r="4" fill="#fff" stroke="rgba(0,0,0,0.35)"/><circle cx="42" cy="12.5" r="4" fill="url(#pv1-b)"/>
    <text x="16" y="56" class="pv-mono">$ penthera https://your.app</text>
    <text x="16" y="84" class="pv-mono pv-dim">certificate      ok</text>
    <text x="16" y="108" class="pv-mono pv-dim">headers          1 to fix</text>
    <text x="16" y="132" class="pv-mono pv-dim">keys in bundles  none</text>
    <rect x="16" y="148" width="9" height="16" fill="url(#pv1-b)" class="pv-cursor"/>
  </svg>`,
  // 01 Every day: the dependency list checked again; now and then a new advisory.
  "01": `<svg class="pro-visual" viewBox="0 0 320 180" aria-hidden="true" focusable="false">${STEEL_DEFS("pv2")}
    <line x1="8" y1="120" x2="312" y2="120" class="pv-line"/>
    ${Array.from({ length: 12 }, (_, i) => `<rect x="${12 + i * 25}" y="108" width="18" height="24" fill="url(#pv2)" stroke="rgba(0,0,0,0.3)"/><path d="M${16 + i * 25} 120 l4 4 l7 -8" class="pv-tick"/>`).join("")}
    ${[4, 9].map((i) => `<line x1="${21 + i * 25}" y1="100" x2="${21 + i * 25}" y2="62" class="pv-line pv-dash"/><rect x="${9 + i * 25}" y="38" width="24" height="24" transform="rotate(45 ${21 + i * 25} 50)" fill="url(#pv2-b)"/>`).join("")}
    <text x="8" y="160" class="pv-mono pv-dim">every day: what you shipped</text>
    <text x="8" y="22" class="pv-mono pv-dim">a new advisory: you hear</text>
  </svg>`,
  // 03 Every month: the report, with one month looked at closer.
  "03": `<svg class="pro-visual" viewBox="0 0 320 180" aria-hidden="true" focusable="false">${STEEL_DEFS("pv3")}
    <line x1="8" y1="150" x2="312" y2="150" class="pv-line"/>
    ${[96, 82, 104, 64, 50, 38].map((h, i) => `<rect x="${20 + i * 48}" y="${150 - h}" width="30" height="${h}" fill="${i === 3 ? "url(#pv3-b)" : "url(#pv3)"}" stroke="rgba(0,0,0,0.3)"/>`).join("")}
    <circle cx="179" cy="70" r="26" class="pv-lens"/><line x1="198" y1="89" x2="222" y2="113" class="pv-lens-h"/>
    <text x="8" y="174" class="pv-mono pv-dim">months</text>
  </svg>`,
};

const ORD = (n) => `${n}${n === 1 ? "st" : n === 2 ? "nd" : n === 3 ? "rd" : "th"}`;
const PROOF = [
  ["npm", "npm malware"],
  ["pypi", "PyPI malware"],
  ["library", "JS injection bugs"],
  ["secrets", "Leaked secrets"],
];

/** The ranks from bench/public/published.json: Penthera against the best other free tool. */
function proof(pub) {
  if (!pub?.benchmarks) return "";
  const rows = PROOF.map(([key, label]) => {
    const b = pub.benchmarks[key];
    if (!b) return "";
    const tools = b.rows.filter((r) => !r.excluded);
    const us = tools.find((r) => r.kind === "penthera");
    const best = tools.filter((r) => r.kind !== "penthera").sort((a, c) => c.score - a.score)[0];
    if (!us || !best) return "";
    // The rank interval (bench/public/rank-intervals.json) says how sure the place is.
    const tied = tiedPhrase(RANK_INTERVALS.penthera[key]);
    const pct = (v) => Math.max(2, Math.round(Math.max(0, v) * 100));
    return `<li class="pro-proof-row">
              <p class="pro-proof-k">${esc(label)}</p>
              <p class="pro-proof-rank"><span>${ORD(us.rank)}</span> of ${tools.length}${esc(tied)}</p>
              <svg class="pro-proof-bars" viewBox="0 0 100 14" preserveAspectRatio="none" aria-hidden="true" focusable="false">
                <rect x="0" y="0" width="${pct(us.score)}" height="6" fill="url(#pro-bar-b)"/>
                <rect x="0" y="8" width="${pct(best.score)}" height="6" fill="url(#pro-bar-s)"/>
              </svg>
              <p class="pro-proof-v"><span>Penthera ${us.score.toFixed(2)}</span> <span>${esc(best.tool)} ${best.score.toFixed(2)}</span></p>
            </li>`;
  }).join("\n            ");
  return `<section class="pro-panel band pro-proof" aria-labelledby="pro-proof-title">
          <p class="label">Measured in public</p>
          <h2 id="pro-proof-title">Ranked against the free tools.</h2>
          <svg class="pro-defs" aria-hidden="true" focusable="false"><defs><linearGradient id="pro-bar-b" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5a5aff"/><stop offset="0.55" stop-color="#0000ed"/><stop offset="1" stop-color="#0000b8"/></linearGradient><linearGradient id="pro-bar-s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="0.45" stop-color="#d3d9e0"/><stop offset="0.55" stop-color="#8f98a6"/><stop offset="1" stop-color="#e3e8ee"/></linearGradient></defs></svg>
          <ol class="pro-proof-list">
            ${rows}
          </ol>
          <p class="pro-proof-note">Four public datasets other people built, on a half we sealed before we started. Penthera against the best other free tool on each. Where a range follows the rank, Penthera's rank fell in that range in 95% of bootstrap redraws. <a href="/benchmarks">Every tool, intervals and limits</a></p>
        </section>`;
}

const MARK = `<svg class="pro-mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><defs><linearGradient id="pro-steel" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="0.35" stop-color="#c9cfd8"/><stop offset="0.55" stop-color="#6b7380"/><stop offset="0.8" stop-color="#e3e8ee"/><stop offset="1" stop-color="#9aa3b0"/></linearGradient><linearGradient id="pro-core" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6b6bff"/><stop offset="0.55" stop-color="#0000ed"/><stop offset="1" stop-color="#0000a8"/></linearGradient></defs><path d="M16.00 0.40 L16.99 13.60 L21.94 10.06 L18.40 15.01 L31.60 16.00 L18.40 16.99 L21.94 21.94 L16.99 18.40 L16.00 31.60 L15.01 18.40 L10.06 21.94 L13.60 16.99 L0.40 16.00 L13.60 15.01 L10.06 10.06 L15.01 13.60Z" fill="url(#pro-steel)" stroke="rgba(255,255,255,0.55)" stroke-width="0.4" stroke-linejoin="miter"/><path d="M16.00 11.80 L20.20 16.00 L16.00 20.20 L11.80 16.00Z" fill="url(#pro-core)"/></svg>`;

const slider = ({ name, label, min, max, step, value, unit, hint }) => `
          <div class="pro-slider">
            <label for="pro-${name}">${esc(label)}</label>
            <div class="pro-range"><input type="range" id="pro-${name}" name="${name}" min="${min}" max="${max}" step="${step}" value="${value}"><output for="pro-${name}" data-unit="${unit}">${unit === "$" ? `$${value}` : `${value} ${unit}`}</output></div>
            <p class="pro-hint">${esc(hint)}</p>
          </div>`;

/** The page's <main> content. `version` pins the install line. */
export function proMain({ version, pub = null }) {
  const mail = esc(waitlistHref());
  return `
  <div class="pro-h" data-h>
    <div class="pro-sticky">
      <div class="pro-track">
        <section class="pro-panel pro-hero" aria-labelledby="pro-title">
          <canvas class="pro-canvas" aria-hidden="true"></canvas>
          <div class="pro-hero-text">
            <ul class="pills" aria-label="Penthera, Pro, an experiment"><li><a href="/">Penthera</a></li><li>Pro</li><li>An experiment</li></ul>
            <h1 id="pro-title">${MARK}Penthera Pro</h1>
            <p class="pro-lede">Rules decide. Pro keeps the record.</p>
            <p class="pro-cta"><a class="btn btn-steel" href="#join" data-track="pro-hero-waitlist">Join the experiment</a><span class="pro-scroll-hint" aria-hidden="true">scroll →</span></p>
          </div>
        </section>

        <section class="pro-panel band band-invert pro-why" aria-labelledby="pro-why-title">
          <p class="label">An open question</p>
          <h2 id="pro-why-title">Is the free tool enough?</h2>
          <p class="pro-big">Penthera is free and stays free. Pro is an experiment, not a sale: it measures whether teams need anything beyond the free agent. If they do, the income keeps Penthera maintained beyond one part-time person, and pays independent reviewers and outside experts to critique its rules. If they don't, the free tool is the whole product, and that's a fine answer.</p>
        </section>

        <section class="pro-panel band pro-stack" aria-labelledby="pro-stack-title">
          <p class="label">What it is</p>
          <h2 id="pro-stack-title">Rules decide. We show our work.</h2>
          <p class="pro-big">The free Penthera agent runs in your CI, and Pro keeps what it found. Every finding comes from a written rule: a model can propose a problem, but a rule has to confirm it. Every result is signed, and anyone can check it with <code>penthera evidence verify</code>, free.</p>
        </section>

        ${CARDS.map(([n, h, p]) => `<section class="pro-panel band band-invert pro-card-panel" aria-label="${esc(h)}">
          <span class="pro-num">${n}</span>
          <h2>${esc(h)}</h2>
          <div class="pro-visual-wrap">${VISUALS[n]}</div>
          <p class="pro-big">${esc(p)}</p>
        </section>`).join("\n        ")}

        ${proof(pub)}

        <section class="pro-panel band pro-stays" aria-labelledby="pro-stays-title">
          <p class="label">What goes up, and what doesn't</p>
          <h2 id="pro-stays-title">Your code stays in your CI.</h2>
          <ul class="pro-list">
            <li><b>Opt-in only.</b> <code>penthera --publish</code> sends a signed bundle: findings, the dependency list (SBOM), the evidence manifest and site check results. Never source code.</li>
            <li><b>Without <code>--publish</code>, nothing leaves your machine.</b> That is how the free agent works today.</li>
            <li><b>Bring your own model.</b> Use the AI reviewer you already pay for: <code>penthera verify</code> keeps what the rules confirm, and the rest stays labelled unverified. We don't resell model access.</li>
          </ul>
        </section>

        <section class="pro-panel band band-blue pro-price-panel" aria-labelledby="pro-price-title">
          <p class="label">What we'd test</p>
          <h2 id="pro-price-title">From about <span class="spec-big">$100</span> a month per team.</h2>
          <p class="pro-big">A person, if you want one: an optional quarterly review with a written note. Assessments of one app or one release are quoted on their own.</p>
          <p class="pro-self">Nothing is for sale. The hosted parts are planned, and they get built only if the waitlist shows a need. No check ever moves behind a paywall. Pro is not a certification: it shows what was checked and found, with the evidence.</p>
          <p class="pro-self">Rather run it yourself? <code>npx penthera@${esc(version)} init --yes</code> sets up the same checks in your own CI, free.</p>
          <p class="pro-research"><span>In research</span> Checks your agents can call and pay for, one at a time, each with a signed verdict.</p>
        </section>

        <form class="pro-form" novalidate>
          <section class="pro-panel band pro-calc" id="calc" aria-labelledby="pro-calc-title">
            <p class="label">Your numbers</p>
            <h2 id="pro-calc-title">What does security cost you now?</h2>
            ${SLIDERS.map(slider).join("")}
            <p class="pro-result" aria-live="polite"><span class="pro-result-n" data-cost>$1,800</span> a month of your team's time, <span data-fte>0.13</span> of a full-time role. Pro starts at about $100 a month, and takes the routine watching off your plate.</p>
            ${slider({ name: "budget", label: "What you'd consider spending a month", min: 0, max: 2000, step: 25, value: 0, unit: "$", hint: "$0 is a real answer: it tells us the free tool is enough. Goes into your email, nothing else." }).replace('class="pro-slider"', 'class="pro-slider pro-budget"')}
          </section>

          <section class="pro-panel band pro-join" id="join" aria-labelledby="pro-join-title">
            <p class="label">Waitlist</p>
            <h2 id="pro-join-title">Would you use it?</h2>
            <fieldset>
              <legend>I am</legend>
              <div class="pro-chips">${ROLES.map((r, i) => `<label class="pro-chip"><input type="radio" name="role" value="${esc(r)}"${i === 0 ? " checked" : ""}><span>${esc(r)}</span></label>`).join("")}</div>
            </fieldset>
            <fieldset>
              <legend>I'd want</legend>
              <div class="pro-chips">${WANTS.map((t) => `<label class="pro-chip"><input type="checkbox" name="want" value="${esc(t)}"><span>${esc(t)}</span></label>`).join("")}</div>
            </fieldset>
            <label class="pro-q" for="pro-note">Anything else <span>(optional)</span></label>
            <textarea id="pro-note" name="note" rows="2" maxlength="600" placeholder="Your stack, your app, what keeps you up at night"></textarea>
            <p class="pro-send"><button class="btn" data-variant="default" type="submit" data-track="pro-waitlist">Join the experiment</button><a class="pro-plain" href="${mail}" data-track="pro-waitlist-plain">or email ${esc(WAITLIST_MAIL)}</a></p>
            <p class="pro-note">Each email counts as one data point in the experiment. The button opens an email to Daan, who builds Penthera, with your answers and numbers filled in. You send it; nothing is stored on penthera.org. Daan replies to every one.</p>
          </section>
        </form>
      </div>
      <div class="pro-progress" aria-hidden="true"><span></span></div>
    </div>
  </div>`;
}
