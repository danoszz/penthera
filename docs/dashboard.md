---
title: "The local dashboard: penthera ui"
sidebarTitle: "Dashboard"
description: "penthera ui opens Penthera in your browser: whether your app is ready to ship, what to fix first, in plain words, and the fix loop that proposes a change and waits for your OK."
---

> **Starter.** For "can I see it all in one place?"

`penthera ui` opens Penthera in your browser: whether your app is ready to
ship, what to fix first, in plain words, and the fix loop that proposes a
change and waits for your OK. It looks like a small 1-bit computer: a menu
bar over three windows. It runs on `127.0.0.1` only, reads only the folders
you give it and `~/.penthera`, and never contacts the network.

| Simple, dark | Advanced, light |
|---|---|
| ![Simple mode in the dark theme: the verdict, problems in plain words, and one problem open](https://github.com/danoszz/penthera/raw/main/assets/dashboard/ui-dark.jpg) | ![Advanced mode in the light theme: a project with its tabs, the triage matrix and a finding open](https://github.com/danoszz/penthera/raw/main/assets/dashboard/ui-light.jpg) |

## Start it

```bash
penthera ui --open                       # current folder, reports in ./reports
penthera ui --project ~/code/shop --project ~/code/api --reports ~/code/shop/reports
penthera ui --demo                       # fake data, nothing read from disk
```

| Option | Default | What it does |
|--------|---------|--------------|
| `--port <n>` | `0` (random free port) | Port on 127.0.0.1 |
| `--open` | off | Open the one-time URL in your browser, through a launcher file only you can read, so the token is not on a command line |
| `--project <dir>` | the current folder | A folder the dashboard may read and run in. Repeat for more |
| `--reports <dir>` | `<first project>/reports` | Where report JSON is read from, and where runs started here write theirs. The default folder must not be a symlink; name a symlinked folder here to use it on purpose |
| `--demo` | off | Realistic fake data and a scripted fix loop. For a first look, screenshots and docs |

It prints a URL with a one-time token after the `#`, which the browser never
sends over the network. Open it once: the page swaps the token for a session
that lives in that tab (a reload keeps it, a new tab or browser does not), and
the token stops working, so a second browser or a link that leaked into
history is refused. Restart `penthera ui` for a new link. Ctrl-C stops the
server.

## First visit: setup

The first time a browser opens the dashboard, a three-screen setup runs (run
it again from **Penthera ▸ Set up…**):

1. What Penthera does, in two sentences, and the rule: only check apps you own
   or have written permission to test.
2. **Simple** or **Advanced**. Simple answers "is my app secure, and what do I
   do?" in plain words with one button at a time. Advanced shows everything.
   Switch any time in the Penthera menu or Settings; the choice is remembered
   in this browser.
3. Your project: the folder (one of the `--project` folders) and, optionally,
   where the app runs. **Check my app now** starts a first scan; **Skip** closes
   setup. Closing it early keeps Simple.

![Setup, choosing Simple or Advanced](https://github.com/danoszz/penthera/raw/main/assets/dashboard/ui-setup.jpg)

## The view

**Menu bar.** The Penthera menu (the wordmark; the P alone on small screens)
holds About, Set up, Settings, the mode and the theme. Simple mode adds
**Check** (Check my app, Fix problems for me, the running check) and **View**.
Advanced has **File**, **Scan**, **Fix**, **Evidence** and **View** instead.
Every item shows its shortcut. On the right: the run in progress (blue, "Fix 1
of 3 waiting for you", when a change waits), and **Offline** or **Online** for
scans started here (click to switch).

**Projects** (left, `[` to hide). **New scan…** on top, then "All projects"
and every project with its A to F grade, open problems and last check. A
project with a run in progress shows a blinking square.

**The document** (centre). For a project, or all of them:

- **The verdict**: one sentence as the headline that answers "can I ship?",
  such as "Not ready to ship: 1 critical problem to fix first.", with the age
  of the check, the counts to fix and fixed, and the score out of 100 as a
  10 × 10 grid of pixels (for all projects, the lowest score). One button is
  blue: **Fix problems for me…** in Simple, the first finding in Advanced.
  While a problem is open in the inspector, its **Fix it for me…** is the blue
  one instead.
- **Simple**: the problems, in plain words (Critical, Serious, Worth fixing,
  Minor), "Fix first" before "When you have time", then what was fixed since
  the check before, folded into one line. No paths, categories or charts.
- **Advanced**: five tabs (`1` to `5`). **Findings** has what changed since
  the last scan, a triage matrix of severity against how sure Penthera is
  (Confirmed, Likely, Needs a person; pick a cell to filter) and the full list
  (`/` searches, `j` and `k` move). **Dependencies** has the capability diff,
  typosquats and install firewall decisions. **AI tooling** has the grade,
  `penthera.lock` drift and hidden-content hits. **History** has open findings
  per scan, every run, the commits the fix loop made and the memory chain.
  **Proof** has the hosts the last scan contacted and evidence bundles: create,
  verify, and download the auditor, owner or developer report.

A run streams into the centre in **check and fix** mode: the side windows
step aside, and **Back** at the top left (or `Esc`) returns to the project. In
Simple mode it is one sentence ("Fix 2 of 3
is waiting for you to approve it.", "Done. 2 fixes applied and checked, 1
undone.") with the raw output folded under "Show what it is doing". In Advanced
it is the transcript, with a gutter square per step: filled when done, hollow
on the step in progress.

**The inspector** (right, `]` to hide) shows one thing. With a problem picked:
in Simple, what is wrong, how sure Penthera is, what to do and how to check
the fix, then **Fix it for me…**, with the evidence and the code change behind "Show the details"; in
Advanced, the same in plain words plus where, the evidence, sources and the
fix-recipe diff. `Esc` goes back. With nothing picked it shows the **halftone
field**: dark with dots when something serious is open, plain paper when
nothing is. The dotted desktop between the windows follows the same rule.

**Every change waits in a window.** When the fix loop has a change, a
pinstriped window opens over a heavy blur: "Penthera wants to change 1 file to
fix this:", the problem, what it will do, and the change (folded in Simple).
**Apply** (`y`), **Skip** (`n`) or **Stop** (`q`). Closing the window decides
nothing; the change stays waiting, in the transcript and the menu bar. A diff
over 60,000 characters is cut, and the window says so; Apply (and `y`) then
stays off until you tick that you have not seen all of it. Every Apply names
the SHA-256 of the diff it showed, and the server applies nothing else.

![A change waiting for a decision](https://github.com/danoszz/penthera/raw/main/assets/dashboard/ui-run.jpg)

Below 1180px the inspector becomes a drawer; below 760px the projects window
does too. A tap outside closes them.

| Narrow, dark | Narrow, light, a problem open |
|---|---|
| <img src="https://github.com/danoszz/penthera/raw/main/assets/dashboard/narrow-dark.jpg" alt="Simple mode at 390px, dark" width="280" /> | <img src="https://github.com/danoszz/penthera/raw/main/assets/dashboard/narrow-light.jpg" alt="A problem in the drawer at 390px, light" width="280" /> |

## User stories

| Story | Where it lives |
|---|---|
| *As someone who is not a programmer, I want to know if my app is secure without learning security words.* | Simple mode: the verdict sentence, problems as Critical, Serious, Worth fixing or Minor, and one button at a time. |
| *As a solo founder before launch, I want one sentence that says whether I can ship.* | The verdict at the top of every project. |
| *As a first-time user, I want to be walked through setting up my project.* | The three-screen setup on the first visit. ![First run](https://github.com/danoszz/penthera/raw/main/assets/dashboard/ui-start.jpg) |
| *As a founder with no security engineer, I want fixes applied only when I approve them.* | The approval window: Apply, Skip or Stop on every change; verified fixes land as local commits on a separate branch, failed ones are undone, nothing is pushed. |
| *As a developer, I want to start a scan and be stopped before I hit a host I do not own.* | New scan…: a remote hostname must be typed back before the run starts. |
| *As a product owner, I want one problem explained in plain words.* | Pick it: the inspector leads with what is wrong, how sure and what to do. |
| *As a returning user, I want to see if something is waiting for me wherever I am.* | The menu bar: "Fix 1 of 3 waiting for you". |
| *As a tech lead, I want to triage by how serious and how sure.* | Advanced ▸ Findings: the triage matrix. |
| *As a tech lead after a release, I want to see what changed.* | "Since the last scan" and Advanced ▸ History. |
| *As the person answering the NIS2 questionnaire, I want evidence an auditor can check.* | Advanced ▸ Proof: create and verify a bundle, download the auditor report. |
| *As a developer reviewing a lockfile bump, I want to see what packages gained.* | Advanced ▸ Dependencies. |
| *As someone who installs skills and MCP servers, I want to know if any hide instructions or drifted.* | Advanced ▸ AI tooling. |
| *As a keyboard user, I want every action without the mouse.* | Every menu item shows its shortcut; the menus, tabs and windows follow the WAI-ARIA patterns. |

## Running things from the page

**New scan…** (or `n`) opens a window: what to run, the folder, an optional
URL and the offline switch. In Simple mode it offers two things, "Check my
app" and "Fix problems for me"; Advanced offers scan, dependencies, AI tooling
and the fix loop. It calls the same functions as the CLI (`executeScan`,
`scanDeps`, `scanAgents`, `runLoop`) with the same rules. The fix loop needs a clean git
tree on a branch, works on a local `penthera/fix-<yyyymmdd-hhmm>` branch, runs
only allow-listed local git commands with hooks off, is always offline with
egress limited to the URL's host, and never pushes. On top of that:

- The project folder must be inside one of the `--project` folders.
- A URL that is not on this machine (anything but `localhost`, `127.x.x.x`,
  `[::1]` and `*.localhost`) needs its hostname typed back before the run
  starts. Only scan what you own or have written permission to test.
- One run at a time. Closing the tab does not stop a run; open it from the
  menu bar or the project's History tab and its transcript replays and
  continues. Stop finishes the current step, and the fix branch holds only
  verified commits.
- Reports land in the reports folder (`loop-<timestamp>.json`,
  `deps_<timestamp>.json`, and so on), so every screen picks them up. A write
  is refused when the reports folder (or `evidence/` in it) no longer resolves
  to the folder checked at startup, and evidence bundles are built in a
  private temp folder and renamed into place.

### AI mode

A scan of a project folder has an **AI mode** switch, off. Turning it on
opens a sheet, on every new scan: a picture of where your code goes (your
code, Penthera, Ollama on this computer, and "internet" crossed out), the
model picker, the same Model / Reads / Sends / Decides lines the terminal
shows, and two buttons of equal weight, "Use `<model>` on this computer" and
"Not now" (Esc). A model that runs on ollama.com turns the last box into
"ollama.com" and needs the host typed before its button works. The server
asks Ollama for the model's route itself, refuses an AI run without that
consent or with an older consent text, and logs each consent locally.
A run shows an "AI · local" (or "AI · ollama.com") tag that opens to say
which model ran where; when it ends, the model's unverified proposals are
folded away under their own heading and are not counted anywhere else.
Settings lists the consent log. See [ai-mode.md](ai-mode.md).

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
3. **Session.** The one-time token sits in the URL fragment, so it never
   reaches a server or a log. The page posts it to `/api/session` once, gets
   a session id back, removes the token from the address bar and keeps the id
   in that tab's `sessionStorage`. Every `/api` request sends it as
   `Authorization: Bearer`; the server keeps only its SHA-256 and compares in
   constant time. There is no cookie: cookies are not bound to a port, so
   every other server on 127.0.0.1 you visit would receive one. The run
   transcript is read with `fetch`, not `EventSource`, so it carries the
   header too. The page and its scripts are served without a session (they
   hold no data). Requests without a session are rate-limited (429 with
   `Retry-After`).
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

Limits: a request body over 64 KB gets a 413, a request must arrive within 30
seconds, and an idle connection closes after two minutes (the run transcript
excepted; it sends a keep-alive line instead). At most 16 transcripts stream
at once, and the 20 most recent finished runs are kept for replay.

Penthera scans its own dashboard clean with `--profile standard`, signed in and
not; `tests/ui.test.js` runs that scan on every test run, alongside tests for
the Host check, the token and bearer session, Origin, the headers, the rate limit and
path traversal.

## Design

System 1-bit, blue ink: ink, paper and `#0000ed`, and nothing else. It should
feel like a security instrument from a calmer era of computing, honest about
what it knows.

- **Windows.** Every pane is a window with a 1px frame and a title bar. The
  window that holds focus has the solid title bar, so you can see which one
  `j`, `k` and `Esc` act on. Only floating windows (setup, New scan, About,
  the approval) have the hard 3px shadow, over a heavy blur. The approval alone
  is pinstriped: pinstripes mean "waiting on you".
- **No greys.** Shades are dither patterns: solid, hatched, half, sparse,
  dotted, empty. Severity is a word plus its pattern, never colour alone.
- **One accent.** `#0000ed` marks selection, the default button (with the
  classic outer ring), the focus ring, chart lines and links, and the menu bar
  when a change waits for you. On black it measures 2.2:1, so there it is only
  a fill with white on it (9.5:1), a frame or a ring; text in that hue uses
  `#7a7aff` (6.1:1). On paper `#0000ed` is text-safe (9.3:1). Green is retired:
  OK is a ✓ and a word.
- **Type, three roles.** [Departure Mono](https://departuremono.com) (OFL,
  self-hosted, 11 and 22px) for chrome, labels and numbers; `ui-monospace` for
  paths, evidence, diffs and transcripts; the system sans for sentences meant
  for people.
- **The logo, once per surface.** The horizontal wordmark in the menu bar (the
  P mark below 760px), the P on a blue tile as the favicon, the wordmark large
  in About, setup and the first-run screen. Never the mark and the wordmark side
  by side, never in a window's title bar.
- **The halftone field.** The one strange element, and it carries data: its
  density is the open risk. Blobs are seeded by the project, so each keeps its
  shape. Drawn on a canvas once per size or theme change, never animated.
- **Both themes pass WCAG AA** for every text node in every state (Simple and
  Advanced, every tab, a finding open, settings, menus, setup, New scan,
  About), measured in the browser, composited.
- **Motion.** Almost none. Run output types itself out and the cursor and the
  live squares blink; with `prefers-reduced-motion` all of that stops. With
  `prefers-reduced-transparency` the blur becomes a plain dark backdrop.
- **Keyboard.** `n` new scan, `/` search, `j`/`k` findings, `1` to `5` tabs
  (Advanced), `[`/`]` side windows, `y`/`n`/`q` answer a change, `Esc` closes a
  menu, the detail, the search or a drawer. Every control is a real button or
  link; dialogs trap focus and give it back; screen readers get each log line
  whole.

The screenshots in `assets/dashboard/` come from the demo data:
`node scripts/dashboard-screenshots.mjs` regenerates them with a local Chrome.
