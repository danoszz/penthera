# The local dashboard: `penthera ui`

`penthera ui` opens a dashboard in your browser for what Penthera knows about
your projects: where each one stands, what each finding means, what changed
since the last scan, your dependencies and AI tooling, and evidence for an
auditor. It can also run scans and the fix loop for you, stopping at every
diff. It runs on `127.0.0.1` only, reads only the folders you give it and
`~/.penthera`, and never contacts the network.

| Dark | Light |
|---|---|
| ![Overview, dark theme](../assets/dashboard/overview-dark.jpg) | ![Overview, light theme](../assets/dashboard/overview-light.jpg) |

## Start it

```bash
penthera ui --open                       # current folder, reports in ./reports
penthera ui --project ~/code/shop --project ~/code/api --reports ~/code/shop/reports
penthera ui --demo                       # fake data, nothing read from disk
```

| Option | Default | What it does |
|--------|---------|--------------|
| `--port <n>` | `0` (random free port) | Port on 127.0.0.1 |
| `--open` | off | Open the one-time URL in your browser |
| `--project <dir>` | the current folder | A folder the dashboard may read and run in. Repeat for more |
| `--reports <dir>` | `<first project>/reports` | Where report JSON is read from, and where runs started here write theirs |
| `--demo` | off | Realistic fake data and a scripted fix loop. For a first look, screenshots and docs |

It prints a URL with a one-time token. Open it once: the token is swapped for
a session cookie and stops working, so a second browser (or a link that leaked
into history) gets a 403. Restart `penthera ui` for a new link. Ctrl-C stops
the server.

## User stories

Each story names who it is for, what they want and why. Each one has a
feature in the dashboard and a screenshot from `penthera ui --demo`.

**1. First run, nothing scanned yet.** *As a solo founder the week before
launch, I want the dashboard to tell me what to do first when there is no
data yet, so that I am not staring at empty charts.* The overview turns into
a three-step start: scan your app, check your dependencies, audit your AI
tooling. Each step opens Run with the right mode and your project folder
filled in.

![Story 1: the Welcome screen with three steps](../assets/dashboard/story-first-run.jpg)

**2. Run a scan from the UI.** *As a developer who does not live in the
terminal, I want to start a scan from the page and watch it work, so that I
know it ran and where the report went.* Run has four modes: scan app, check
dependencies, audit AI tooling, fix loop. A URL that is not on this machine
needs its hostname typed back first. Output streams into a terminal window;
when it finishes, "What next?" offers the obvious next steps.

![Story 2: a scan streaming in the terminal window](../assets/dashboard/story-scan.jpg)

**3. Let the agent fix things, one approved diff at a time.** *As a founder
with no security engineer, I want Penthera to propose fixes and apply only the
ones I approve, so that nothing changes in my code without me seeing it.* The
fix loop stops at every diff with a dialog: the recipe, the files, what the
fix closes, what memory knows about this recipe, and the diff itself. Apply
(`y`), Skip (`n`) or Stop the loop (`q`). Verified fixes are committed on a
local branch; failed ones are reverted. Nothing is pushed.

![Story 3: the approval dialog for a fix](../assets/dashboard/story-loop.jpg)

**4. Understand one finding.** *As a product owner who is not a security
expert, I want one finding explained in plain words, so that I can decide
whether it matters today.* The detail panel opens with "In plain words": how
serious it is, how sure Penthera is (and what that confidence level means),
what to do, and the OWASP mapping. Below it: what was seen, the evidence, the
sources, and the exact fix diff.

![Story 4: a finding explained in plain words](../assets/dashboard/story-finding.jpg)

**5. Compare over time.** *As a tech lead after a release, I want to compare
two scans of the same project, so that I can see what got fixed and what is
new.* History picks the most interesting project by default, compares the
previous scan with the latest (or any two you choose), and lists new, fixed
and still-open findings in three columns. Below them, a timeline draws every
finding as a bar across the scans (S1, S2, ...): hatched while it is still
open, an outline once it was fixed.

![Story 5: history comparing two scans](../assets/dashboard/story-history.jpg)

**6. Export evidence for an auditor.** *As the person who answers the NIS2
questionnaire, I want a package an auditor can check without trusting me, so
that the evidence holds up.* Evidence creates a bundle from the latest scan
of a project (JSON, Markdown, SARIF, the auditor, owner and developer reports,
and a manifest with a SHA-256 per file), verifies it straight away, and lets
you download the auditor report as Markdown.

![Story 6: a new bundle, verified, with downloads](../assets/dashboard/story-evidence.jpg)

**7. Check what a dependency change can do.** *As a developer reviewing a
pull request that bumps the lockfile, I want to see which packages gained new
capabilities, so that I catch a malicious update before it runs.* Dependencies
shows the capabilities in the tree, the capability diff against your base,
typosquats, and every install firewall decision.

![Story 7: the capability diff](../assets/dashboard/story-deps.jpg)

**8. Trust my AI tooling.** *As someone who installs skills and MCP servers
into Claude Code and Cursor, I want to know whether any of them hide
instructions or changed since I reviewed them, so that my agent is not working
for someone else.* AI tooling shows the A to F grade, hidden content with the
decoded text, and drift against `penthera.lock`.

![Story 8: grade, hidden content and lock drift](../assets/dashboard/story-ai-tooling.jpg)

**9. Know where to start this week.** *As a solo founder on a Monday morning,
I want one place that says what to fix first and what changed since the last
scan, so that I do not have to read every report.* The overview opens with a
"This week" window: fix first (every critical and high), new since the last
scan, and fixed since the last scan, across all projects. Each line opens the
finding.

![Story 9: the This week window](../assets/dashboard/story-week.jpg)

**10. Work in daylight.** *As someone who reads reports on a bright screen, I
want a light theme, so that the dashboard is comfortable outside a dark room.*
The `◐` button in the menu bar (and Settings) switches between the black
terminal and the white paper theme. The first visit follows your system
setting; the choice is remembered in this browser.

| Narrow, dark | Narrow, light |
|---|---|
| <img src="../assets/dashboard/narrow-dark.jpg" alt="Overview at 390px, dark" width="280"> | <img src="../assets/dashboard/narrow-light.jpg" alt="History at 390px, light" width="280"> |

## Where the data comes from

| Screen | Source |
|--------|--------|
| Overview | The latest scan report per target in the reports folder, plus trend and time to fix from local memory |
| Findings | The same reports. The fix preview runs the fix recipes against the project folder, read-only |
| Run | Live runs started from this page; past `loopRun` files; memory stats |
| History | Every scan report of one project in the reports folder |
| Dependencies | `penthera deps -o reports/deps.json` and `penthera install <pkg> --dry-run --json > reports/install.json` (or Run → Check dependencies) |
| AI tooling | `penthera agents . -o reports/agents.json` (or Run → Audit AI tooling) |
| Evidence | Bundles below the reports folder, written with `--evidence` or from this screen |
| Settings | Theme, egress mode for scans started here, data locations, memory chain status |

The reports folder is read one level deep for `*.json` (anything that is not
a Penthera report is ignored) and two levels deep for evidence bundles.
Symlinks are skipped. A memory chain that does not verify is shown as broken
and its contents are not used, the same rule scans follow.

## Running things from the page

Run calls the same functions as the CLI (`executeScan`, `scanDeps`,
`scanAgents`, `runLoop`) with the same rules. The fix loop needs a clean git
tree on a branch, works on a local `penthera/fix-<yyyymmdd-hhmm>` branch, runs
only allow-listed local git commands with hooks off, is always offline with
egress limited to the URL's host, and never pushes. On top of that:

- The project folder must be inside one of the `--project` folders.
- A URL that is not on this machine (anything but `localhost`, `127.x.x.x`,
  `[::1]` and `*.localhost`) needs its hostname typed back before the run
  starts. Only scan what you own or have written permission to test.
- One run at a time. Closing the tab does not stop a run; come back to Run and
  it reattaches. Stop finishes the current step, and the fix branch holds only
  verified commits.
- Reports land in the reports folder (`loop-<timestamp>.json`,
  `deps_<timestamp>.json`, and so on), so every screen picks them up.

## Security model

The dashboard is a web server on your machine, so any page open in the same
browser can send it requests. Every request passes, in this order:

1. **Host check.** The `Host` header must be exactly `127.0.0.1:<port>` or
   `localhost:<port>`. This blocks DNS rebinding, where `attacker.example`
   re-resolves to 127.0.0.1 so the attacker's page can read the response. It
   runs before the token check, so a rebinding page cannot even redeem the
   link.
2. **Path check.** No dot segments, encoded dots or slashes, backslashes or NUL
   bytes. Static files come from an allowlist built at startup; no part of a
   request path is ever joined onto a filesystem path.
3. **Session.** The one-time URL token is exchanged for an `HttpOnly;
   SameSite=Strict` cookie and a redirect to `/`, so the token leaves the
   address bar. Every request, static files included, needs the cookie.
   Requests without it are rate-limited (429 with `Retry-After`).
4. **Origin.** Every `POST` needs an `Origin` equal to the server's own (and
   `Sec-Fetch-Site: same-origin` when the browser sends it) and a JSON body, so
   a cross-site form or `fetch` cannot change anything.

Every response carries:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';
  font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self';
  frame-ancestors 'none'; require-trusted-types-for 'script'
X-Frame-Options: DENY            X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer     Cache-Control: no-store
Cross-Origin-Opener-Policy / -Resource-Policy / -Embedder-Policy
```

There are no CORS headers, and `OPTIONS` gets a 405. The page has no inline
script or style, loads nothing from another host (no CDN, fonts, analytics or
chart library), and never turns data into HTML: finding titles and evidence
come from the sites and repos you scanned, so they are only ever set as text.
Report downloads are served as `text/markdown` attachments from the same
checks; the audience is one of `auditor`, `owner` or `developer`, nothing else.

Penthera scans its own dashboard clean with `--profile standard`, signed in and
not; `tests/ui.test.js` runs that scan on every test run, alongside tests for
the Host check, the token and cookie, Origin, the headers, the rate limit and
path traversal.

## Design

A 1-bit desktop with a terminal inside. The window chrome comes from the Mac
of the early 90s, and the layout from a planning board the maintainer keeps in
the same style (every section a pinstriped window with its date on the right,
bold-ruled columns, a Gantt with dashed milestones): a menu bar, pinstriped title bars with close and zoom boxes,
a dithered desktop, rounded push buttons where the default one wears a thick
ring, and alert dialogs with a double frame. The voice, the `▸` progress
lines, the numbered "What next?" and the `#0000ed` block-letter wordmark come
straight from the CLI and its demo GIF, so the terminal, the README and the
dashboard read as one product.

- **Black, white and patterns do the work.** Severity is a word plus a
  pattern swatch (solid, hatched, half-tone, dotted, empty), and bars are drawn
  with shade characters `█ ▓ ▒ ░ ·`. Charts fill with hatching and dithering,
  not colour.
- **One accent.** `#0000ed` marks the active screen, the default button,
  selection, links and chart lines. On black it measures 2.2:1, so there it is
  only a fill (white text on it, 9.5:1), a frame or a glow; text in that hue
  uses the tint `#7a7aff` (6.1:1). On white, `#0000ed` is text-safe (9.3:1).
- **Green** is kept for the cursor, the prompt and "OK".
- **Calm where it counts.** Pinstripes only on real windows and dialogs; data
  sits in hairline group boxes, one stat strip, and tables with figure captions
  that say where each number came from.
- **Both themes pass WCAG AA** for every text node on every screen (measured in
  the browser, composited). Light text uses a 0.6 ink step where the dark
  theme uses 0.5, because 0.5 measures 3.6:1 on paper.
- **Motion.** The output types itself out and the cursor blinks. With
  `prefers-reduced-motion`, both stop and output appears whole. Screens switch
  with `1`-`8` and have no transition.
- **Keyboard.** `1`-`8` screens, `/` filter findings, `j`/`k` move through
  findings, `y`/`n`/`q` answer a diff. Every control is a real button or link;
  the approval dialog takes focus when a diff arrives; screen readers get each
  log line whole, never letter by letter.
