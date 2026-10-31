# Site brief

> **Project page.** For "what is the Penthera site for, and what was decided?"

The source of truth for the landing page in `site/`. Decisions made with the
maintainer on 2026-10-21; change them here first, then in the page.

## Reader and job

One reader: a developer who ships with AI coding tools (Claude Code, Cursor,
Codex) and has never heard of Penthera. They arrive from a README, a post or
a star. The page has one job: get them to run `npx penthera`, or to try the
check in the page first.

## Positioning (approved, used verbatim)

- Hero line: "Check it before they wreck it"
- Tagline (2026-10-31): "Make your app more secure for free"
- One plain line: "Penthera is a free, open-source security scanner and fixer
  for your app. It checks your AI setup too"
- Fixer line, always near "fixer": "It fixes what it can with your OK. For the
  rest, it tells you or your coding agent how, then checks the fix"
- Short line: "Free, open-source security scanner and fixer for your app. Checks your AI setup too. Measured in public."

## Direction: Poster

typesafe.ai in spirit, in Penthera's own 1-bit look (`penthera ui` after #63):

- Ground `#000` / `#fdfdfa`, ink, and `#0000ed` as the only colour. Greys are
  dither patterns, never flat.
- One assertion per screen, a lot of empty paper, a dithered field cut from
  the walkthrough frames.
- Display type: Helvetica Neue, tight. It is a system font, so nothing is
  downloaded; Arial is the fallback where it is missing. Departure Mono
  (self-hosted, OFL) for commands, labels and numbers, as in the dashboard.
- **The one bold move:** the browser check is the only window on the page,
  drawn like a `penthera ui` window. Everything else is poster.
- Theme follows the system on the first visit; a toggle overrides it and is
  remembered in localStorage (no cookie).

## Structure

A story in ten chapters (2026-10-22, restructured after caveman.so's
structure, not its voice). Each chapter opens with a numbered eyebrow and one
assertion; sections that repeated each other were merged.

1. Hero: the problem ("AI coding tools ship faster than anyone can check"),
   then the title, subline, `npx penthera` and the 12-second loop.
2. The answer: "yo, is my app safe?" before and after (a real scan), then a
   spec table: For, Runs, Works with, Price.
3. What it checks: one window with four panes (your app, dependencies, AI
   tooling, a live URL), each with a count read from the rules, bold lead-ins
   and its command. Then the browser check, the one window you can use.
4. How to trust it: three principles (rules decide, offline, measured in
   public), then the E10 benchmark with its caveats first.
5. Current limitations, on its own dithered grey band: what it does not
   do, what ROADMAP.md plans for each limit, and the planned integrations
   (AI app builders such as Base44, preview deployments), each marked
   planned. Links to the methodology, the FAQ and the roadmap.
6. The tour: three steps in the dashboard, side by side (since 2026-10-29;
   before that, the walkthrough video and two stills).
7. How it compares: where each tool goes further, in one line each; the
   full sourced table folds out below it.
8. Get started: the CLI, the Agent Skill and the MCP server, each with a copy
   button; prompts and per-client MCP configs below.
9. Before you install: the FAQ. The EU-rules section and Open R&D are answers
   here now.
10. For agents: `llms.txt`, `llms-full.txt`, the Markdown docs, `server.json`,
   the skill, `AGENTS.md` (once it exists), the sitemap and `security.txt`.

Decided with the maintainer, 2026-10-22: the problem line is a kicker above
the title (the title stays the h1); the browser check stays under "What it
checks"; chapters keep a numbered eyebrow and an assertive h2; the
per-client MCP configs are collapsed in a `<details>`.

Decided with the maintainer, 2026-10-23: the limits leave the trust band
for a grey band of their own (a 2 px checker, so still a dither, not a flat
grey), with a roadmap line per limit; the comparison shows its summary and
folds the table; the hero pills are blue highlighter marks.

Decided with the maintainer, 2026-10-23, later: tighter and more varied.
The style is "futuristic yet brutalist and typographic". Square corners and
hard type stay; a few surfaces now catch light: brushed-metal plates in
the old Apple manner, lit by one light from above that follows the pointer
on a mouse (mixed from each palette's ground and ink) for the trust
principles, benchmark counts, roadmap lines, ways in and prompts; polished
gradient type for the price and the counts; light falling on the blue band;
soft blue gradients on the primary buttons. This replaces "greys are dither
patterns, never flat" for those plates. The bottom blur stays as it is.
Secondary detail folds away: the benchmark chart and the agent prompts sit
behind toggles, like the MCP configs and the comparison table.

Decided with the maintainer, 2026-10-29 (direction A, "the poster is the
check"): the first screen is the live check. "Is your site/app safe?" in
display type over the field and a glowing Check; the approved title stays
the h1, set as a Departure Mono kicker above it. On the right, a metal card
labelled Example shows the live check's own report of the test server, made
at build time on loopback, never a number written by hand; your result
replaces it in the same place, and the left side becomes the hand-off above
the fold (Prompt to fix, `npx penthera <url>`, `npx penthera --repo .` and
Star on GitHub). The problem line, the pills, the lede and the loop follow
below the first screen. The dots sit behind the card, never behind the
headline.

Decided with the maintainer, 2026-10-29, later (home polish): the problem
gets a section of its own after the poster, on a flat grey (`--slab`,
`#e6e6e1` in light and `#1f1f1f` in dark, both measured in `styles.css`),
with section padding above and below. This is the one flat grey on the page;
the limits band stays dithered. The problem line is display type at the h2
scale (40 to 88 px, line-height 1, tracking -0.04em, balanced) and keeps its
marker strokes, now 0.88em bands inside a 1em line, so the lines sit tight.
One order, spaced on the 8 px scale: problem, 40, pills, 24, lede, 40, the
two ways in, then the loop a section step below. The note under the
buttons was dropped on review: the poster already offers the code scan. "See it work"
drops the walkthrough video (the loop is enough) for three light-theme shots
of `penthera ui` side by side, numbered 1 to 3: start a check, see what to
fix first, approve a fix. They are made from the real dashboard with demo
data by `site/tools/tour-shots.mjs` and show light in both themes. After
review each is cropped to its key area (the Check my app window, the verdict
with the first problem, the fix dialog with its diff) at device scale 2, so
it reads at a third of the page; no lightbox.

Decided with the maintainer, 2026-10-29 (footer and Pro): no divider lines
anywhere on the site. Space, grounds and shared heights separate things; the
rule under the Pro kickers, the lines between Pro panels and the line above
the footer are gone, and Pro's progress bar fades out at the end of the row.
Every page, the homepage included, now has the same footer
(`site/frame.mjs`), a map of the whole site built from what the build
renders, so new pages show up in it by themselves and a test fails if a
built page is missing:

- a status line with a breathing blue LED ("Built from Penthera <version>.
  Runs offline. Rules decide.") beside the bar's three controls (theme,
  Star with its count, Download);
- four groups under numbered Departure Mono labels: Product, Research (with
  each benchmark and each approved post set in, in mono), Trust, Elsewhere;
- a 1-bit ramp, from a blue gradient cell through ordered dither to empty
  paper, on a row of its own: the footer's only dither, never behind text;
- the wordmark as a plate across the whole measure, polished steel (chrome on
  black, gunmetal on paper) with blue light under it, linking to the top;
- the facts in mono: MIT, scan only what you own, no cookies or third-party
  requests.

The bottom veil still switches off over the footer.

## Anti-references

- Security-vendor pages: dark gradients, shields, padlocks, "threat
  landscape" copy, a "Book a demo" button.
- AI-startup pages: glowing orbs, logos-of-trust walls, testimonials.
- A scanner that keeps what it finds. The live check stores nothing and
  publishes no per-site pages.

## Constraints

- No third-party scripts, trackers or cookies; only Vercel's cookieless Web
  Analytics and Speed Insights, served from the same origin. All assets are
  served from the same origin.
- CSP `connect-src` lists the two Vercel counters and `/api/check` on
  penthera.org, nothing else. The page sends only the address you type, to
  penthera.org's own function.
- The live check (decided with the maintainer, 2026-10-23): one function,
  `api/check.mjs`, described in `/openapi.json`, under the terms at `/terms`
  (`docs/live-check-terms.md`). Passive only: what one browser visit loads
  (robots.txt, the page, up to 14 files it references, `security.txt`,
  public DNS). No deeper scan online, not even for verified owners: probing
  paths on a site from penthera.org would make us the ones probing. Deeper
  testing runs with `npx penthera` on the visitor's own machine.
- Zero abuse: a consent modal with slide to scan before every first check of
  a site, `"consent": true` required by the API, limits per visitor and per
  site, the target's robots.txt opt-out for `Penthera-QuickCheck`, and a
  User-Agent that links to the terms. Every request goes through the guard in
  `api/_lib/guard.mjs`. Nothing is stored or logged; a count of scans may
  come later, never the results.
- The rule code is the CLI's (`lib/`), so the site and `npx penthera` agree.
- Penthera Pro at `/pro` (decided with the maintainer, 2026-10-28; `/upkeep`
  redirects there). It proposes, it does not sell: a security partner for
  software built with agents, priced like managed upkeep ($100–300 a month
  per team while we test, assessments quoted separately), and one line on
  agent-to-agent paid checks marked "In research". The page is a horizontal
  poster: the page scrolls down as usual and a pinned row slides left
  (`site/pro.js`); with no script the panels stack. The header is a canvas
  sketch, dithered ASCII in brushed steel and Penthera blue, no rainbow; it
  goes quiet behind the heading instead of putting boxes behind the type.
  Steel controls with glossy blue selected states, iOS-style, square
  corners. The calculator takes only the reader's own numbers (hours,
  hourly cost, budget) and, like the waitlist, only fills in an email the
  reader sends: nothing is stored.
- Pro, second pass (2026-10-28): Pro is mostly automated, priced from about
  $100 a month per team while we test, with a person as an optional add-on.
  /pro leads with "Rules decide. Pro keeps the record." and a day, week, month
  rhythm (dependency watch, site checks, signed report); it says plainly that
  the hosted parts are planned. No "pentest" wording in Pro copy. The landing
  page has a "Go Pro" plate before About: machined steel, the Pro mark, "What
  you shipped, checked again every day.", a shimmer and a pointer light
  (`site/gopro.js`), still with reduced motion.
- Pro is an experiment, not a sale (decided with the maintainer,
  2026-10-28). Penthera stays free and complete; Pro measures whether teams
  need anything beyond the free agent. If they do, the income pays for
  maintenance beyond one part-time person: independent reviewers, and outside
  experts who critique the rules. If not, the free tool is the product. So:
  no Pro pitch in the README or in the live check's result. /pro opens with
  "Is the free tool enough?", the Go Pro plate says "An experiment, not a
  sale" and its button reads "Join the experiment", and each waitlist email
  counts as one data point. The money rules are in GOVERNANCE.md#money.
  The waitlist must be able to say "no": the budget slider starts at $0
  with no default above it, and "Nothing more: the free tool is enough" is
  one of the answers.

Decided with the maintainer, 2026-10-30 (navigation and footer labels): the
site has a bottom dock, the steel rail, chosen from three options. It is an
opaque metal plate with no backdrop blur. The footer keeps its four groups and
set-in sub-links, and drops the numbers: each group's label is a rotated pill
in its own finish (Penthera blue, steel, gunmetal, the palette's other blue).
The ticker moves in steps of about 2 px and rests while the URL field has
focus, because its smooth transform was the main cause of slow typing.

Decided with the maintainer, 2026-10-30 (first screen): option 2 of three, with
narrower side margins. The field fills the first screen under the bar's hard
edge, and the question and example float in one panel of heavy glass. The scan
button is the only blue action there.
