# Changelog

All notable changes to Penthera are documented here. Versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [2.1.2] - 2026-10-31

### Fixed

- **`penthera agents ./some-skill` scans the skill.** A folder you name with
  `SKILL.md` at its root, in any casing, used to report `Nothing to assess` and
  read nothing, even with a download-and-run line in it. It now gets the same
  rules and findings as a skill under `skills/<name>/`, scripts included. A
  direct path to a `SKILL.md` scans its folder. Any other file is an error
  instead of an empty run. A file or folder Penthera could not read, or a file
  over the size limit, gets a high finding, so such a skill never grades A.
  Dependency and virtual environment folders are not read: they are listed
  under Not read and do not lower the grade. `--pin` on a skill folder leaves its own
  `penthera.lock` out of the hash, so the next run does not report the skill as
  changed.
- **Project scans do not change.** `penthera agents`, `penthera agents .` and
  the full path of your working folder ignore a `SKILL.md` at the root, as
  before. So do `--aibom` and the GitHub Action with its default `path`.
- **The MCP `audit_ai_tooling` tool takes more in `path`.** Besides a project
  folder, it now accepts a skill folder or a `SKILL.md` inside the workspace.
  The tool's description is unchanged, so clients that pin it see no change.
- **A run that read no agent config no longer looks clean.** The terminal
  report said `No findings` and `Clean scan, no issues found` next to `Nothing
  to assess`, and `--markdown` said `No security findings detected`. Both now
  say this is not a clean result. SARIF stays free of results and carries the
  same message as a warning notification on the run.
- **`penthera.lock` is never read or written through a symbolic link.** A linked
  lock is reported as a corrupt lock, at medium, and `--pin` refuses to follow it.
- Terminal output strips control characters from finding titles and paths. A
  linked `bin/` in a skill's virtual environment is no longer followed. Large
  skill files are hashed in chunks. `--aibom` hashes only regular files inside
  the repo.
- **The `/pro` page scrolls sideways again.** Its script picked up the bottom dock instead of the page's panels, so the horizontal layout never started.
- **Reports no longer read as clean on a run that fails.** A critical or high
  finding in a test fixture or build output printed "Nothing to fix" and exited
  1. Another tool's finding or a required tool that did not run printed "Clean
  scan" in the terminal and "No security findings detected" in Markdown. The
  exit codes stay the same, so a live-format key in a fixture still fails CI.
  The brief says `Review`, with a line that says why the run fails, and names
  the tool and file for another tool's finding. The terminal, Markdown and
  audience reports give that reason when Penthera's own findings do not explain
  the exit code, and SARIF carries a notification when a required tool did not
  run.
- **`--repo <missing path>` exits 2.** It used to read as clean and exit 0.
- **`--help` no longer prints escape codes to a pipe.** The help of every command
  honors `NO_COLOR` and uses color only on a terminal.
- **`dist/` and `build/` in a skill you name are no longer likely noise.** They
  are the skill's own code.

### Site

- The homepage title and share cards are back to the approved wording: "Penthera: your open-source cyber security agent".
- **Unknown API paths answer in JSON.** `/api` and anything under it that is not a route return a 404 with `error.code`, `error.message` and `error.hint`, the shape `POST /api/check` uses.
- **The live check says when to retry.** A rate-limited check now carries `Retry-After`, set to the longest wait among the limits it hit, and the OpenAPI spec states the rate limits and how versions and breaking changes work.
- **`/server.json` is on the site.** It is the MCP Registry manifest from the repo: a local npm package over stdio, with no hosted endpoint.
- **New `/contact` page,** with public channels: email, GitHub and private security reports.
- **The homepage's structured data adds an Organization** with the public contact email, and no street address or phone. `llms.txt` now says what Penthera does not do, and the OpenAPI fields all declare a type.
- **The home page types and moves more freely.** The news ticker now moves in
  steps of about 2 px and stops while the URL field has focus or is off
  screen. The hero's field has a layer of its own. In Safari on a 14-inch
  MacBook Pro, with the URL field focused, GPU use fell from 25% to 11% and
  WindowServer from 45% to 22% of a core.
- **Every page has a bottom dock.** A steel dock fixed to the bottom of the window links Research, Benchmarks, Blog and Pro, on every screen size. It never moves, so no scroll speed can lose it. On the homepage the plate opens from its center once the hero has scrolled away, and the GitHub star and Download show inside it.
- **The first screen is calmer.** The hero's field fills the screen, and the
  question and an example result float above it in one glass panel. The panel is a
  card that overlaps the grey section and runs past the bottom of the window.
  The scan button is the one blue action, and the report after a check uses
  the same glass.
- **Every report ends with something to do.** Copy the fix prompt, download the
  report as Markdown (made in your browser, nothing stored), or copy the full
  scan command.
- **Motion is calmer and cheaper.** Buttons press to 0.97, dialogs fade in, and the star on the
  Go Pro plate glows with an opacity fade.
- **The footer is easier to read.** Each group has a label of its own in blue,
  steel or gunmetal, sub-pages are set in, and long labels are shorter. A
  hovered link is white on blue in both themes, 9.45:1 instead of 2.1:1 in the
  light theme.

### Docs

- Every command, MCP config and workflow example pins `penthera@2.1.1`, the
  new `latest`, and the action examples pin the v2.1.1 commit. The roadmap and
  README show 2.1.1 as the current release, and the upgrade test in the install
  matrix starts from 2.1.1. `penthera init` still writes the v2.1.0 pin until
  the next release.
- Pages that said the 2.1.0 agent rules ship in the next release now say they
  shipped. `AGENTS.md` and the integrations page name the redirect that
  `scan_url` allows within the target's registrable domain.
- The Agent Skill no longer tells agents to lead with a grade line that the
  brief does not have. It now leads with the verdict line and says where the
  A–F grade is.
- `/trust` lists the services behind penthera.org as a list. The table showed
  as one line of raw pipes.

## [2.1.1] - 2026-10-30

### Security

- **`scan_url` over MCP now stays in scope on every request and redirect hop,
  with or without `--offline`.** It reaches the target and hosts you listed with
  `--allow-host`. A redirect may also move within the target's registrable
  domain. It refuses any other host and names it under **Not checked** and in
  `blocked_hosts`. It now uses the vendored Retire.js snapshot, never a download.
- **`penthera agents` gives no grade when it finds no agent config.** It used to
  report A, 100 and `Nothing to fix`. It now reports `Nothing to assess`, and the
  CLI, reports, brief, MCP, `init` and dashboard all show no grade. A project
  with any agent config is graded as before.

### Added

- **E20-R study tooling (research).** A runner and analysis for the planned
  front-door follow-up, tested on loopback only: a fixed response classifier
  (challenge, block, origin error, page), stored header evidence, a seeded order
  across cohorts, and intervals that account for one organization owning several
  domains. It refuses to leave loopback until the protocol is registered. The live
  check's requests and scores do not change.

### Fixed

- **`init` now pins the action to v2.1.0.** The old v2.0.0 pin skipped the scan
  in `mode: deps` and still reported success.
- **A clean single-page app no longer gets a false critical.** The
  CVE-2025-29927 check fired on a 200 alone, and a single-page app answers 200
  on every path. Two of the three places that run it now report only when the
  header steadily changes the answer: the status, or a stable body. The third,
  the `--adaptive` check, already compared. The Next.js debug endpoint check now
  needs a Next.js home page, the Next.js source map check needs a JSON body, and
  the `/docs` check needs the page to name Swagger, OpenAPI, ReDoc or RapiDoc.
  `--profile quick` and MCP `scan_url` use the same checks.
- **Exit 0 now says what it means.** The terminal report ends with "No critical
  or high rule fired. This run does not prove login, access rules or payments
  are right."
  The agent brief lists the same limit under Not checked. `docs/before-you-publish.md`
  no longer says "Publish" for exit 0, and its checklist adds `npm audit`.

### Docs

- **E20 study (draft):** the source address is not published, for the
  maintainer's privacy; owners can ask us privately whether a request was
  ours. The app or login page check is adopted for both cohorts, and the
  study page lists it. Hosting platforms are named only for groups of 20 or
  more sites.
- **E20 registered (29 Oct 2026):** the Tranco top 1000 (list ZJ8PG) and the
  two newest YC batches with at least 100 companies (Fall and Summer 2026,
  416 sites, from a pinned public mirror of YC's directory) are stored and
  hashed, with the exclusion list. Nothing has been sent to a study site yet.
- **E20-R runs once.** Amendment 1 drops the second pass, before any data, and the
  study page says so.
- Every command, MCP config and workflow example pins `penthera@2.1.0`, the
  new `latest`. The roadmap and README show 2.1.0 as the current release, and
  the upgrade test in the install matrix starts from 2.1.0.

## [2.1.0] - 2026-10-29

### Added

- **`penthera agents` checks five more ways agent config runs code
  ([ADR 0002](docs/decisions/0002-agent-setup-gaps-and-pr-check.md)).**
  New rules, each with a test on a defanged fixture:
  `task-folder-open` (a `.vscode/tasks.json` task with `runOn: "folderOpen"`,
  medium, critical when it downloads and runs code); `hook-local-script` (a hook that runs a script
  file, low when the script is in the project and was read, medium when it
  is not); `registry-redirect` (`npm config set registry`, `--registry`,
  `.npmrc`, `NPM_CONFIG_REGISTRY`, `YARN_REGISTRY`, `npmRegistryServer`,
  `pip --index-url`, `--extra-index-url`, `-i` and `PIP_INDEX_URL` pointing
  anywhere but the public npm, Yarn and PyPI registries over HTTPS; low for a
  `localhost` registry, a scoped `@scope:registry` and vendor indexes such as
  `download.pytorch.org`, at most medium for `--extra-index-url`; one finding
  per file at the severity of its worst line, and scope or extra index read
  from the flag or key, never from the URL); `env-code-injection`
  (`NODE_OPTIONS` with `--require` or `--import`, `LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONSTARTUP` and similar, in an MCP
  server's `env`, a hook, a task or the Claude Code settings `env`); and
  `mcp-auto-approve` (Cline `autoApprove`, Roo Code `alwaysAllow`, Gemini CLI
  `trust: true`, Claude Code `enableAllProjectMcpServers` and VS Code
  `chat.tools.global.autoApprove`). It now also reads `.gemini/settings.json`,
  `.roo/mcp.json`, `.vscode/tasks.json` and `.vscode/settings.json`.
- Fixed: skill folders no longer skip `__pycache__`, `build` and `dist`, so
  compiled code there is reported. A `.pyc` is low only when it is Python's
  ordinary cache of the `.py` next to it (the `__pycache__` name, a
  timestamp-based header and the same source size), reported once per
  `__pycache__` folder; any other `.pyc`, a hash-based one included, is high.
  `node_modules` and `.git` are still skipped, and the result now says so.
- Fixed: a folder counts as a Python virtual environment only when it has a
  `pyvenv.cfg` with `home =`, a `python` in `bin/` or `Scripts/` and a
  `site-packages` folder, so an empty `pyvenv.cfg` or a folder named `venv`
  no longer hides anything. A real one is reported (new rule `skill-venv`,
  medium); its packages and binaries are listed under Not checked, and its
  other files and text scripts are still scanned.
- Fixed: `penthera.lock` is now version 2, which pins every file in a skill
  except `node_modules` and `.git`, `dist`, `build`, `__pycache__` and
  virtual environments included. A version 1 file is still compared the
  2.0.0 way, so upgrading never reports a changed skill; an info finding asks
  you to re-pin with `penthera agents --pin`. A lock of an unknown or newer
  version is not compared, and an info finding says so.
- Fixed: hooks written as `"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh`, the
  form Claude Code documents, now resolve to the script, so the hook rules
  read it, a path with a space in it included, and so does `npx tsx
  script.ts`. `node_modules/.bin/*` counts as a package binary, not a missing
  script.
- Fixed: `penthera agents` no longer reads a hook script, a config file, an
  instruction file (`CLAUDE.md`, `AGENTS.md` and the rest) or an agent folder
  (`skills/`, `.cursor/rules`, `.claude/commands`, `.github/instructions`,
  `plugins/`) that resolves outside the project (or the plugin folder), by
  absolute path or through a symlink; it lists them under Not checked. Parse
  errors no longer quote the file's content.
- Fixed: the pre-commit hook now runs the agent rules on staged
  `.vscode/tasks.json`, `.vscode/settings.json`, `.gemini/settings.json` and
  `.roo/` files.
- Fixed: `penthera agents --home` reads Cline's and Roo Code's MCP settings
  from the global storage of VS Code, VS Code Insiders, VSCodium, Cursor and
  Windsurf, so their `autoApprove` and `alwaysAllow` keys are checked there
  too. A scan of a given home folder reads only that folder, never the real
  `%APPDATA%`.
- Fixed: `penthera init` no longer writes a workflow or `.gitignore` through a
  symlink, a dangling one included, and creates no folder outside the project
  before it refuses.
- Fixed: a long run of spaces after `registry` in an `.npmrc` no longer slows
  the scan, the pre-commit hook or the MCP tool (the match was quadratic).
- Fixed: the "Not checked" part of an agents result no longer says nothing
  was skipped. It always says MCP tool descriptions are not read, and it
  names agent config on disk that no rule covers yet (Codex, Cursor hooks,
  Windsurf, Kiro, OpenCode, dev containers and others).
- Fixed: no finding carries the OWASP MCP03 "Tool Poisoning" label any more.
  No rule reads MCP tool descriptions, so hidden text in skills now maps to
  ASI01 only, and a changed pin to MCP04 and ASI04.
- Fixed: the `task-folder-open` finding now says what current VS Code does:
  `task.allowAutomaticTasks` defaults to `off`, yet a trusted workspace still
  gets a one-time notification, and Allow turns automatic tasks on for every
  trusted workspace.
- **The agent config check on every pull request, in one file.**
  `docs/examples/github-actions-agents.yml` runs
  `npx --yes penthera@2.0.0 agents` on pull requests and pushes to `main`,
  uploads SARIF to code scanning and stays report-only until you opt in to
  failing the job. `penthera init` offers to write it as
  `.github/workflows/penthera-agents.yml` when the repo has agent config. It is
  shown as a diff first and never committed.

### Detection

- **Provider keys in client JavaScript.** A URL scan now reads the scripts the
  home page loads from its own site (up to 10, 2 MB each) and reports provider
  keys left in them, such as one set in a `NEXT_PUBLIC_` or `VITE_` variable.
  Keys are shown masked. A Google key next to Firebase config is reported at
  low, because Firebase web keys are public by design. Scripts on other sites
  are never requested, and a redirect is followed only to the same site on
  https or with `www.`. Scripts past the first 10 or over 2 MB are not
  checked. Contributed by @divya-o.
- **Clerk secret keys, named as Clerk's.** Clerk's secret keys use the same
  `sk_live_` and `sk_test_` prefixes as Stripe's, so a leaked Clerk key was
  reported as a Stripe key, and a Clerk test key not at all. A key assigned to
  `CLERK_SECRET_KEY` (in `.env`, JSON or YAML) is now reported as a Clerk
  secret key: critical for a live key, high for a test key, which still opens
  the development instance and its users. Publishable keys (`pk_`) stay
  unreported. On the CredData dev half, precision and recall are unchanged.

### Changed

- **AI disclosure in commits is the `AI-Assisted` trailer alone.** A
  `Co-Authored-By` line for the AI is no longer required; the provenance check
  still rejects an AI co-author line without an `AI-Assisted` line.
  CONTRIBUTING, AGENTS.md and the generative AI page say so.
- **The plugin and the repo's MCP config pin a stable release.**
  `plugin/.mcp.json` and `.mcp.json` start `penthera@2.0.0`, not the release
  candidate. The docs and examples that pinned `penthera@1.8.1` or `latest` now
  pin 2.0.0. The internal audit accepts the newest stable pin in these two
  files while the package is a release candidate.
- **Docs: a GitHub Action snippet that is valid YAML.** `docs/commands/action.md`
  shows the action pinned to the v2.0.0 commit SHA, with its name in quotes.
  The name contains a colon, so the unquoted snippet on the Marketplace page
  fails to parse. The page also says that `mode: agents` runs `npm ci` for its
  one dependency. The README now shows "Start in 30 seconds" before the
  benchmark tables and drops the dated "new in 1.9.0" labels.
- **A smaller npm package.** The package no longer ships `CHANGELOG.md`.
  Nothing reads it at run time, and the full history stays on
  [GitHub](https://github.com/danoszz/penthera/blob/main/CHANGELOG.md). This
  takes the package from 2,570 KB to 2,445 KB unpacked (945 KB to 896 KB
  packed). Scans, rules and output are the same.
- **The first screen of [penthera.org](https://penthera.org) is now the live
  check.** "Is your site/app safe?" sits over the field and the Check button,
  with the title kept as the page's h1 in a small kicker above it. On the
  right, an example result card shows real output: the site's own passive
  check, run at build time against the test server in
  `tests/fixtures/mock-server.js` on loopback. Your result replaces that card
  in the same place. The left side then lists the next steps above the fold:
  Prompt to fix, `npx penthera <url>`, `npx penthera --repo .` and Star on
  GitHub. A clean result gets the same next steps. On a phone, Prompt to fix
  sits inside the card, and Star on GitHub stands in for the commands you
  would run on a laptop. The check itself is unchanged: passive, nothing
  stored, the same consent and slide to scan.
- Two new cookieless event labels, named in
  [docs/privacy.md](../docs/privacy.md): `copy {what: "repo-result"}` and
  `link {to: "github-star-result"}`, for the two new buttons next to a
  result. The live check's terms now say what is counted, as privacy.md does:
  that a check ran and whether it returned a report or an error, never the
  address, the score or anything you type.

### Fixed

- **The live-check terms now say what the page counts.** They said the page
  does not record that a check ran; it does send a cookieless count of checks
  (report or error), as the privacy page already said. It never records what
  was checked.
- **`penthera agents`: a git source counts as pinned only with a full commit.**
  An MCP server launched from `git+https://…`, `git+ssh://…`, `github:owner/repo`
  or `owner/repo` was treated as pinned. It now needs a full 40-character commit
  SHA (`#<sha>` for npm, `@<sha>` for uv and pip). A tag or a branch can be moved
  to other code, so `uvx --from git+https://…@v1.2` and `npx github:owner/repo#main`
  are reported as `mcp-unpinned`.
- **The Penthera skill pins its own CLI.** `skills/penthera/SKILL.md` and its
  preflight script run `npx -y penthera@2.0.0`, and `allowed-tools` pre-approves
  only that pinned command.

### Site

- **The blog is live: [penthera.org/blog](https://penthera.org/blog).** Two
  posts, approved 28 October: how we benchmarked Penthera against the free
  tools on a sealed half of each dataset, losses included, and what we learned
  scoring 10 free secret scanners on CredData, where Penthera came 2nd. Every
  number in them comes from `published.json` or a cited source, and the build
  checks it.
- **penthera.org/research/e20:** what the E20 study requests from a site, how
  to opt out with robots.txt, what is kept, and who to contact. It goes live
  before any study visit.
- **A research page: [penthera.org/research](https://penthera.org/research).**
  Every pre-registered study with its status (Registered, Running, Result or
  Draft), the result files, the case studies and the blog posts, newest first,
  each dated. The public benchmark is the featured card, with each rank given
  with its interval. The build reads it all from the repo and fails when a
  headline's source no longer says what the headline states. A study that says
  it is not registered is always shown as Draft. Also in the footer, the
  sitemap and `llms.txt`, as `/research.md` for agents.
- **Search and filters on /research.** The page opens on the newest six
  entries, with a button to show them all. Chips filter by type (studies,
  results, case studies, posts) and a study by status, each with its count,
  and a search box filters titles, summaries and study IDs as you type. A
  filtered view keeps its query in the URL, so you can share it. Without
  JavaScript, and for crawlers and agents, the page still lists every entry.
  Each study now appears once: E17 is one entry, with its 29 Oct re-run as a
  note.
- **E21, drafted and not registered:** would the free, offline rules have
  flagged known server-side bugs in open-source code before they were
  exploited? Vulnerable and fixed commits, scanned in local checkouts, no AI
  model run, $0. Candidate CVEs are listed for the maintainer to confirm.
- **One footer on every page, with a map of the whole site.** penthera.org's
  homepage, landing pages, Pro, Research, the benchmarks, the blog, Trust and
  Terms now end the same way: the theme switch, Star and Download, then every
  page in four groups (Product, Research, Trust, Elsewhere), a 1-bit dither
  ramp and the wordmark in polished steel. The map is built from the pages the
  build renders, so a new page or approved post appears by itself, and a test
  fails if a page is missing. /pro loses the line under its section labels and
  between its panels, and long links in blog posts no longer widen the page on
  a phone.
- **Pro is now an open experiment, and the landing page asks the question.**
  Penthera stays free and complete. A "Go Pro" plate on the landing page and
  the rewritten /pro ask whether teams need anything beyond the free agent,
  such as daily checks of what they shipped, weekly site checks and signed
  reports. The waitlist measures the answer: nothing is for sale, and no check
  moves behind a paywall. If there is a need, the income pays for
  maintenance, independent reviewers and outside experts who critique the
  rules ([GOVERNANCE.md](GOVERNANCE.md#money)). The README and the live
  check's result no longer point to Pro. The plate shimmers and catches the
  light under the pointer, and keeps still with reduced motion.
- **The home page states the problem on its own, and shows the dashboard in
  three steps.** "AI coding tools ship faster than anyone can check." now
  opens a section of its own on a flat grey, set tight in display type, with
  the pills, the lede, the two ways in and the 12-second loop below it. "See
  it work" drops the 80-second walkthrough video for three light-theme shots
  of `penthera ui` side by side: start a check, see what to fix first, and
  approve a fix as a diff. The shots come from the real dashboard with demo
  data (`site/tools/tour-shots.mjs`), cropped so each reads at a third of
  the page.
- **Blog figures show in the post.** The precision-recall plot in the secret
  scanner post and the dev-to-test plot in the method post are now inline,
  with alt text and a caption, served from `/blog/figures/`. They stay white
  plates in the dark theme too.
- **The home page is lighter on your machine, with the same look.** The
  dithered field in the hero draws at up to 60 frames a second while the
  pointer moves and 20 while it only drifts, instead of every display frame
  (120 on ProMotion screens), and skips the columns its mask hides. The metal
  plates' pointer light no longer forces a style pass per plate and only
  touches the plates it can reach. The bottom blur gives each of its six
  layers only the strip its mask shows, and is hidden once faded out. The
  12-second loop, the Go Pro plate's glow and the footer's LED pause off
  screen, and the LED breathes by opacity instead of repainting its glow. On the hero,
  main-thread time while idle drops from about 45% to about 6%.
- **A trust page: [penthera.org/trust](https://penthera.org/trust).** How
  Penthera itself is built and released, with a link for every claim: npm
  provenance from CI, a person approving every release, one runtime
  dependency, the weekly OpenSSF Scorecard, CodeQL on every pull request, no
  telemetry, and who runs penthera.org. It holds no certification and says
  so. From `docs/trust.md`, linked from every page footer.

### Docs

- **Before you publish an app an AI built.** A new page for people using app
  builders. It lists what Base44, Lovable, Replit and Netlify already check
  before publish, from their own docs. Then it shows how to add Penthera as a
  second check that runs on your own machine, with the exit codes to act on.
- **Readable page names on docs.penthera.org.** Each published docs page now
  carries its title, a short sidebar name and a one-line description in front
  matter, so the docs site shows "Set up" and "MCP server" instead of "Init"
  and "Mcp", and search engines get a description. The duplicate heading is
  gone; the Markdown mirror, llms-full.txt, /terms and /trust put the title
  back as a heading. Stale "1.9 release candidate" notes are removed from the
  docs index.
- **E14 step 2, the registered result: Penthera plus the free tools on the
  sealed test half.** Penthera 2.1.0-rc.2 with gitleaks and trufflehog finds
  11 points more CredData rows than Penthera alone (H1 holds) but loses 9
  points of precision, beyond the registered 0.02 margin (H2 fails). With
  Semgrep and CodeQL it finds 9 more of 64 SecBench.js bugs (H4 holds), at 4
  findings per package instead of 1. By the pre-registered rule, `--giants`
  keeps Penthera-first as its default. Every other tool matched its E11b
  numbers exactly before any combination was computed. In
  `bench/public/RESULTS.md` and the E14 pre-registration.
- **E17, a check that Penthera works unplugged.** A pre-registration and a
  runner that runs each offline command with the network blocked, twice, and
  once with it allowed, and compares the results. It also records the child
  processes a command starts, since the guard sees only Node. A manual
  workflow runs it on Ubuntu. The pilot found no outside connections and the
  same JSON every time; the evidence check's printed timestamp and URL scans
  without `--offline` are the exceptions, written up in
  `bench/offline/RESULTS.md`.
- **E17 registered result: no network at run time, same result every time.**
  On macOS and Ubuntu, repo scans, `agents`, `deps`, `brief`, evidence
  bundles and URL scans with `--offline` made no outside connections and gave
  the same result twice, and the same with the network blocked or allowed.
  The evidence check's printed timestamp is the one line that changes. Limits
  are in `bench/offline/RESULTS.md`: `git` runs outside the guard, and URL
  scans without `--offline` download the Retire.js database.
- **README and the trust page say what E17 showed,** for the commands that
  passed only, with its limits.
- **E20 draft protocol: how safe is the web's front door?** A passive check
  of the Tranco top 1000 and of the companies in the two most recent Y
  Combinator batches (E20b), with the live check's own rules, published as
  aggregates only. The maintainer's decisions of 29 Oct are in: lists fetched
  and hashed on registration day, a fixed rate of 4 sites at a time with a
  1 second pause, `User-agent: *` with `Disallow: /` honored as an opt-out,
  and a hand-written exclusion list (adult, gambling, health, government,
  sites of people at risk) hashed with the lists. Not registered yet, and
  nothing has been sent to any site. The runner, `bench/front-door/run.mjs`,
  works on loopback only until the protocol is registered and both the list
  and the exclusion list match the hashes recorded in it
  (`docs/research/prereg/E20-front-door.md`).
- **The live check's passive report takes study options:** skip referenced
  files, skip the secret rules, its own User-Agent and robots.txt name, and
  (for the study only) honor a robots.txt `*` group. The live check itself is
  unchanged.
- **E20 protocol, revision 2 (still a draft, nothing sent to any site).**
  Verified prior work and an honest list of what E20 adds; decision rules
  for every hypothesis, a Bonferroni-corrected family of 11 claims, a
  10-point smallest difference that matters and a power statement; the
  Menlo principles, measurement norms, Dutch, EU and US legal reasoning, a
  harm table and an incident plan; a self-review checklist in place of an
  outside review, listed as a limit. The runner now records decisions,
  a seeded bootstrap for the median, Benjamini–Hochberg q-values for
  secondary differences, a one-per-site sensitivity view and the hosting
  platform, and removes email addresses from raw records before they are
  written. An optional sub-measure (one linked login or app page, same site
  only, headers only) is in the runner and tested on loopback, and stays off
  until the maintainer adopts it.
- **Which ranked tools are barely in the contest, and what a malware flag
  means.** The README summary and the benchmark pages now name the ranked
  tools that score below 0.10 (on npm, 3 of the 5 others; on PyPI, 4 of 7),
  and say what share of Penthera's malware flags would be right if 1 package
  in 1,000 were malicious: about 2.7% on npm at the top of the false-alarm
  interval, 1.6% on PyPI at the measured rate (0.9% at the top). Exploratory,
  computed from `published.json`; the registered ranking is unchanged.
- **GOVERNANCE.md: who decides, how releases happen, and what happens if the
  maintainer stops.** One maintainer, part-time. The rules that don't move
  (rules decide, no run-time downloads, authorized targets only), sponsors
  buy no influence, every release approved by a person with two-factor
  authentication, and a plan for handing over or archiving.
- **Benchmark ranks now carry their rank interval.** Where a point rank is
  less sure than it reads, the README, penthera.org, the blog and the results
  files now say "1st of 6, tied 1st to 3rd" (npm), "1st of 8, tied 1st to
  3rd" (PyPI) and "1st of 8, tied 1st to 4th" (SecBench.js), with a note on
  what the range means. Secrets stays "2nd of 10": its interval is one place.
  The intervals come from an exploratory bootstrap done after the registered
  ranking (`bench/public/rank-intervals.json`); a test checks that each one
  contains the published rank and that the README matches what
  `publish.mjs` writes.
- **Secrets by F0.5 and F2.** Penthera is 2nd by F1, 1st by F0.5 (0.82
  against deepsecrets 0.80) and 2nd by F2 (0.68 against 0.77), computed from
  the published precision and recall.
- **E17 normaliser, a logged deviation.** The registered key pattern also
  removed `hasParams` and `deps.format`, which are analysis output. The
  runner now removes an exact list of volatile paths and reports the old
  pattern next to it. Re-run on macOS on 29 Oct 2026: same verdict. In
  `bench/offline/RESULTS.md` and § 9 of the E17 pre-registration.
- **The docs build as a Mintlify site.** `docs/docs.json` gives them the same
  five journeys as the docs index (new, AI coding tools, CI, auditors,
  research), in Penthera's colours. Mintlify's checker passes: three pages
  that MDX couldn't parse are fixed, and links that leave the docs folder now
  point to GitHub, so they work on GitHub and on the docs site alike.
  `references.md` now writes plain links instead of `<url>` autolinks.
- **The research notes and benchmark posts meet the project's research
  standard.** Each of the seven notes in `docs/research/` and the two posts in
  `blog/` now opens with its question, method, result and limits, and ends
  with how to reproduce it, threats to validity, APA references that link to
  [references.md](../docs/references.md), and a log of changes. 19 sources,
  each checked against its publisher, DOI, CVE record or author page on
  2026-10-29, were added to `docs/references.bib`. Three figures are drawn
  from data in the repository by `docs/research/figures/runtime-strings.mjs`
  and `blog/figures/make.mjs`. No result or number changed.
- **Every research protocol and result page now meets the same standard.**
  Each pre-registration (E1, E8, E10, E11, E11b, E14, E15, E17, E21) and both
  results pages open with an abstract: question, method, result or "no
  result yet", and limits. Registered protocols keep their registered text;
  the additions are dated and marked as added after registration. New:
  APA 7 citations for the statistics and datasets the studies use (20
  entries, each checked against Crossref, arXiv or the dataset's own
  repository), reproduction tables with commits, commands and licenses,
  "what the result means" sections, and revision logs. E11's notes correct
  CredData's code license (Apache-2.0, not MIT). Four figures, drawn by
  `node bench/public/figures.mjs` from committed data, show the E11
  hypotheses, the E11b secret and malware results, and the E14 arms.
- **An exploratory re-analysis of the public benchmarks, after the
  registered one.** [bench/public/RESULTS.md](../bench/public/RESULTS.md)
  adds intervals that resample CredData by repository, recall over every
  true row and every malicious package next to the registered in-scope
  recall, and a log of what each tuning pass on the dev half changed. No
  registered number, rank or verdict changes. `node bench/public/reanalysis.mjs`
  rebuilds it from the local per-item files, with no download.
- **A results-file checklist.** [docs/research/results-checklist.md](../docs/research/results-checklist.md)
  lists 19 reporting items from STARD 2015 and the ACM SIGSOFT Empirical
  Standards, each with where it lives in our files. A test checks that every
  results file links it or has an abstract, data and code, limits and
  changes.
- **Scope-free secrets recall on the site and blog.** The secrets benchmark
  page and the CredData post now say that, counted over every true
  credential row, Penthera's recall is 0.25 and it would place 5th by F1.
  The registered ranking counts in-scope rows and is unchanged.
- **E11b disclosures.** The npm malware table shows the rate over all
  `malicious_intent` packages next to the registered payload row. E11b's
  deviations log a fix that landed 15 minutes before the split was sealed
  (`litellm`) and the pass-limit question for library mode.
- **Fixed:** an unclosed entry in `docs/references.bib` had hidden one
  reference and shown another under the wrong anchor.
- **Two drafts for review: `penthera watch` and E15.** The watch spec
  describes re-checking what you shipped on a schedule in your own CI, against
  advisory data (CISA KEV, EPSS, npm and PyPI) that ships offline in signed
  packs with each release. The E15 pre-registration plans to measure whether
  static agent checks find prompt injection hidden in skills, rule files and
  MCP tool descriptions, and states in advance that plain persuasive text is
  expected to be missed. Neither is built or registered yet.
- **Penthera's daily notes on X are linked** from the README and the site
  footer (x.com/penthera_org). The footer link is counted like the other links,
  with the label "x-footer", as the privacy page lists.

## [2.1.0-rc.2] - 2026-10-28

### Added

- **The agent brief: one short reply for your AI assistant.** After a scan,
  assistants used to write their own summary of a long report, and had to sort
  out the noise themselves. The brief does that with rules: a verdict (`Fix
  now`, `Review` or `Nothing to fix`), then Act on, Check first, Likely noise,
  Not checked and Next. Hits in gitignored files, build output and test
  fixtures are grouped as likely noise, repeats collapse into one line, and
  every finding is counted once. A scan prints it when stdout is not a terminal
  (an agent calling the CLI; `PENTHERA_BRIEF=0` turns that off), or anywhere
  with `--brief`. Also in the JSON report (`brief`), as `--audience agent`, as
  the text of every MCP tool result, and merged across scans with `penthera
  brief repo.json deps.json agents.json`. The MCP server and the Agent Skill
  ask the assistant to keep the brief's sections and put its own view under
  "My read". See [docs/commands/brief.md](docs/commands/brief.md).

### Fixed

- **Fewer false findings in repo scans, and action plan steps that fit.** A
  run on a Next.js and FastAPI monorepo showed these, and each now has a test:
  - "Hardcoded password" no longer fires on style values (`pass:
    'text-emerald-400'`, `var(--success)`) or on a `pass` key next to `fail` or
    `warn`, which is a map of check outcomes. On the CredData dev half, recall
    and precision are unchanged.
  - The `eval` check skips folders git ignores and Next.js build folders under
    another name (`.next-dev`).
  - A Node.js advisory that names TLS gets the step "Upgrade the runtime", not
    "Fix the TLS configuration".
  - Keys in files git ignores get their own low step (check whether the file
    was shared), not "purge it from git history".
  - `eval`, `exec` and `innerHTML` findings get the code-execution step, not
    "Review and remediate this finding".
- **`penthera agents` says what a permission really allows.** A pre-approved
  script in `/tmp`, `/var/tmp` or `/dev/shm` is now its own rule,
  `permission-tmp-script`: any local process can replace the file. "With any
  arguments" now appears only when the grant has a `*` or no arguments, and an
  exact command such as `Bash(bash ./scripts/check.sh)` is no longer reported.
- **Reports leave out what does not apply.** Dependency and agent-config reports
  no longer print an empty OWASP WSTG table, and only URL scans show
  "Reachable".
- **The coverage ledger covers the `eval` check.** A new row says how many files
  it read, how many were over its size limit, and how many sat in folders it
  skips.
- **`--giants`: a private key two tools report is one finding.** Penthera
  reads a secret's value back from the reported line to merge it with other
  tools' findings, and a line inside a private key block has no value on its
  own, so gitleaks' and Penthera's report of the same key stayed apart. When
  either finding has no value, they now merge on file and line; two different
  values on one line still do not. Found in E14's dev half and logged as a
  deviation in its pre-registration.

### Site

- **/upkeep is now /pro: Penthera Pro, a security partner for software built with agents.** The page proposes rather than sells: the agent stays free, and Pro adds a person who sets it up with you, reads what it finds and does assessments when you need one, for $100–300 a month per team while we test. It scrolls sideways as you scroll down, opens with an ASCII header you can move through, shows its benchmark ranks against the free tools (from the same data as /benchmarks), and has a small calculator for what security costs your team now. The waitlist and the calculator only fill in an email you send: nothing is stored on penthera.org. `/upkeep` redirects to `/pro`.

### Docs

- **E14 step 1, the dev half: Penthera plus the free tools.** A new harness,
  `bench/public/giants.mjs`, reruns gitleaks, trufflehog, Semgrep and CodeQL
  through E11b's pinned runners, keeps their per-item hits, and builds the
  pre-registered arms with the merge code `--giants` ships. On the dev half
  every tool reproduces its E11b numbers. The union finds 2.6 points more
  CredData rows at about 12 points less precision (11 before the secret-merge
  fix; the precision test fails either way), and two more SecBench.js
  vulnerabilities while the median findings per package goes from 1 to 4; the test half is
  untouched. Results and the logged deviations are in `bench/public/RESULTS.md`
  and the E14 pre-registration.
- **Roadmap: upkeep in your own CI, this month.** `penthera watch` on a schedule
  in the GitHub Action, a readable evidence report, `verify` for more AI
  reviewers, offline new-CVE alerts with KEV and EPSS, a fresh-malware holdout,
  and setup pages per agent. The roadmap also lists 2.1.0-rc.1 on npm's `next`
  tag.

## [2.1.0-rc.1] - 2026-10-27

### Added

- **`--giants`: run the free scanners you already have, in one report.** After
  its own scan, Penthera runs the tools installed on your machine (gitleaks,
  TruffleHog, Semgrep with your local rules, osv-scanner, Trivy and Checkov
  for `--repo`; nuclei with your templates and the ZAP baseline for a URL)
  and folds their findings into the terminal report, JSON, Markdown, SARIF
  (one run per tool) and the evidence bundle, each labelled with the tool, its
  version and its rule. `--with` and `--without` pick tools,
  `--giants-online` adds pip-audit and TruffleHog key verification, and
  `penthera giants` lists what you have. A new "Coverage by area" table says
  which areas another tool covered; an area with no tool is "not covered",
  never clean. Nothing is downloaded or installed: tools come from `PATH`
  outside the scanned project, run without a shell, with a timeout, an output
  cap, a minimal environment and, on macOS and Linux where available, the
  network denied. CodeQL runs only with `--with codeql`, after a licence
  notice. Other tools' critical and high findings count toward the exit code
  unless the policy file says `giants.failOn: never`; the new `giants` policy
  key can also require, limit or forbid tools. The default merge is
  Penthera-first until experiment E14 reports, and no accuracy claim is made
  for the combination before then. Docs: `docs/commands/giants.md`.

### Changed

- **The Claude Code plugin now installs from a small `plugin/` folder.** It holds
  the Penthera skill, the pinned MCP server, a README, the licence and an icon,
  and nothing else: no `package.json`, no `bin/`, no test fixtures. It is also
  the folder Anthropic's plugin directory reviews. The skill now pre-approves only
  Penthera's own commands (`penthera`, `npx -y penthera`, `npx --no-install
  penthera`) and reading files; Claude asks before it edits a file or runs
  anything else. A test keeps the folder's copy of the skill identical to
  `skills/penthera`.

### Fixed

- **The GitHub Action's `mode: deps` exited before scanning on every release
  from 1.5.0 to 2.0.0, and the job reported success with no PR comment and no
  SARIF.** No dependency was checked in those runs. If you use `mode: deps`,
  move your pin to 2.1.0-rc.1 or later. The cause: the CLI loaded the `yaml`
  package on every command, and the action's checkout has no `node_modules`.
  The resulting `ERR_MODULE_NOT_FOUND` exits 1, which the action read as
  "findings". Deps and URL scans no longer load `yaml`. The action now fails
  the job when Penthera writes no report. Tests cover both: an action run that
  writes no report fails, and deps and URL scans run from a copy without
  `node_modules`.
- **`penthera init` pins the workflow to v2.0.0**, the newest stable release
  before this one, not v1.6.1. v2.0.0 still has the `mode: deps` problem
  above, so move that pin to 2.1.0-rc.1 or later. A test fails when the pin
  falls behind `CHANGELOG.md`.
- **Nothing unread is reported as clean.** When packages in the lockfile are not
  installed or cached, `penthera deps` says how many were not read and how to
  read them (`npm ci --ignore-scripts`). It prints "Not checked" instead of
  "Clean scan" when it read none. `init` grades that area `–`, not `A`. The PR
  comment says "N of M packages scanned".
- **No arguments without a terminal** (an agent, CI, a pipe) prints three
  commands to run, `init --yes --dry-run`, `init --yes` and `--repo .`, instead
  of an error and 150 lines of help. The exit code is still 2.
- **`--giants` names what ran.** "Running gitleaks..." shows only for a tool
  that is installed. A missing tool is listed as `not installed`, with its
  install command. An area where Penthera's own rules read files is "covered",
  and the row says what Penthera read, for example `Penthera (7 files)`.
- **The owner report no longer says every serious finding is "things an
  attacker could use today".** It says "if they are real", and it says how many
  sit in test or fixture files.

### Site

- **Share images of the public benchmarks.** `scripts/media/` now makes the
  benchmark cards in Instagram square and story sizes, scatter charts of the
  results, and a light set: a branded main image, paper-style figures with 95%
  Wilson intervals, and screenshots of the CLI, the local dashboard and
  penthera.org. Every number comes from `bench/public/published.json`.
- **The public benchmarks have their own pages.** [penthera.org/benchmarks](https://penthera.org/benchmarks)
  and one page each for secrets, npm malware, PyPI malware and JavaScript
  injection bugs, built from `bench/public/published.json` when the site is
  built. Each page shows every tool with its rank, score, 95% interval and
  counts, the tools that were not ranked and why, where another tool does
  better than Penthera, and the limits first. Each carries schema.org Dataset
  markup, a Markdown copy for agents and its own share card.
- **The homepage says what Penthera is in its title and description**, and its
  benchmark cards link to the pages. The sitemap dates every URL.
- **`llms.txt`, `llms-full.txt` and `/index.md` lead with the four public
  rankings.** The bundled lab numbers are labelled as regression checks.
- **`docs/compare/README.md` no longer says no page compares detection.** It
  points to the public benchmark and says which of the compared tools are in it.
- **A blog, built from Markdown in `blog/`.** Posts publish only once Daan sets
  `approved:` to a date; a draft is checked and never shipped. Published posts
  get `/blog`, an Atom feed at `/blog/feed.xml`, BlogPosting markup, sitemap
  and `llms.txt` entries, and a footer link. Numbers in a post come from
  `published.json` as placeholders, or must appear in its listed sources. Two
  drafts wait for review: how the benchmark was run, and the secret-scanner
  results.
- **penthera.org counts checks and installs, without cookies.** Vercel Web
  Analytics now records a few named events: a check ran (report or error), a
  copy button was used (which one), a link to GitHub or npm was followed. An
  event carries its name and one fixed label, never the URL or host checked,
  the score, or anything typed. [Privacy](docs/privacy.md) says so, and a test
  keeps it that way.

- **Penthera Upkeep, in validation: a waitlist page.** [penthera.org/upkeep](https://penthera.org/upkeep)
  describes a possible paid service (scheduled checks, fix pull requests a
  person approves, a monthly evidence report) with the prices being tested.
  Joining is an email to daan@penthera.org, so the site stores nothing. The
  free tool stays complete and MIT; nothing is taken out of it. The live check
  result and the README link to it.

### Docs

- **Research plan: E15 as a candidate experiment.** It measures whether
  Penthera's agent audit catches indirect prompt injections hidden in skills,
  rule files and MCP tool descriptions, using the 95 attacks released with a
  2026 public red-teaming competition, and how often it flags normal files.
  The expected limit is stated in advance: hidden and obfuscated payloads are
  caught; plain persuasive text is not.
- **Roadmap: three new checks and a wider benchmark field.** Supabase tables
  without row-level security; known vulnerabilities ranked by CISA's Known
  Exploited Vulnerabilities list and EPSS, shipped as data in the signed rule
  packs so ranking stays offline; Python code rules moved up, parsed with
  Python's syntax tree. E13's field includes every free tool in scope that runs
  offline, newer ones such as StingWard too, whatever their result.
- **Roadmap: one first pass, with the best free tools.** Penthera will run the
  free scanners you already have (gitleaks, trufflehog, Semgrep, osv-scanner,
  pip-audit, trivy, checkov, nuclei, ZAP) where they are better or cover more,
  and fold their findings into one report. Experiment E14 tests whether the
  combination beats each tool alone. Bundling or auto-installing other
  scanners is listed as not planned.
  The spec (`docs/research/spec-giants.md`) is approved and E14 is
  pre-registered, before any code or combined count.

## [2.0.0] - 2026-10-25

Everything in [2.0.0-rc.1](#200-rc1---2026-10-25) below, plus:

### Fixed

- **No more password alarms in translation files.** A translation's
  `"password": "Passwort"` is the word in another language, not a secret.
  Files under an `intl/` folder, and files named for a language and region
  (`de-DE.json`, `pt_BR.yml`), now get only the fixed-shape rules, as `locales/`
  and `i18n/` already did. Found by running the release candidate on ten real
  open-source apps: one of them went from 24 high findings to 7.

### Site

- **Copied commands always install.** While main carries a release candidate,
  the site and its mirrors pin the latest stable release instead of a version
  npm doesn't have yet.

### Docs

- **Penthera in your coding tool:** one page with the setup for Claude Code,
  Cursor, VS Code, Codex, Gemini CLI, Antigravity, Windsurf, Cline, Zed,
  JetBrains, Kiro and Continue, and the two routes for browser app builders
  (Lovable, Bolt, Base44, Replit, v0): the live check on the published URL, and
  GitHub sync plus the CLI or the Action. The site's Get started section has a
  new fold for app builders.

## [2.0.0-rc.1] - 2026-10-25

### Upgrading from 1.9

2.0 is a major version because the default scan finds more, so a CI gate that
passed on 1.9 can fail after the upgrade. Nothing was removed.

- The secret scan reads more files: key files, PHP, C#, `.properties`,
  `.conf`, `.xml`, Terraform state, and docs (fixed-shape rules only).
- Library mode turns on by itself for a publishable npm package (`main`,
  `exports` or `bin`, not `private`, no app framework). Turn it off with
  `--no-library`.
- New malware signals in `penthera deps`: code that runs what it downloads,
  HTTP tarball dependencies, Python code that runs at import time.
- A secret finding lists every line it hit (`lines` in JSON, `relatedLocations`
  in SARIF). Finding ids are unchanged, so baselines keep working.

Why: on a sealed half of four public datasets, 2.0 ranks #1 of the free tools
on npm and PyPI malware, tied #1 on JavaScript library injection bugs and #2
on leaked secrets ([results](bench/public/RESULTS.md)).

### Added

- **Library mode for `--repo`: the parameters of exported functions count as
  untrusted.** A shell command built from one is reported as
  `command-injection` at `potential` confidence and severity high; a function
  that only runs its argument is reported at medium, with the note that callers
  must not pass untrusted input. It turns on by itself for a publishable
  `package.json` (an entry point, not private, no app framework), or with
  `--library`; `--no-library` turns it off. On the SecBench.js dev half,
  command-injection recall went from 0 of 49 to 40 of 49 (0.82, 95% CI 0.69 to
  0.90); it flagged none of 150 benign npm packages and nothing new in 16 app
  repositories ([scan.md](../docs/commands/scan.md#library-mode-scanning-a-package)).
- **More shell and eval shapes in every repo scan.** `exec` under any binding
  of `child_process` (`cp.exec`, `child_process_1.exec`, `{ exec: run }`,
  `promisify(exec)`, Babel's `(0, _cp.exec)`), shelljs `exec`, `spawn`,
  `execFile` and execa with a `shell` option or `sh -c`, indirect
  `(0, eval)(x)`, and `new Function` with a dynamic body in any argument. A
  regex literal that contains a quote no longer hides the code after it from
  the sink check.
- **Gemini CLI extension.** `gemini extensions install
  https://github.com/danoszz/penthera` adds Penthera's MCP server, pinned to
  1.9.0, from `gemini-extension.json`. The internal audit keeps its version in
  sync.
- **README:** a stat strip, one real before/after (penthera.org from 95 to 100
  with two DNS records), npm downloads, stars and star history, and the Claude
  Code plugin and Gemini CLI install routes.

### Detection

- **Library mode follows one helper call and values kept on `this`.** When an
  exported function passes a parameter to a named function in the same file,
  that function's parameter is followed too, one call deep, and the finding
  names the helper. A parameter a constructor or setter stores on `this` is
  followed into the other methods of the same class or prototype, and so is an
  instance an exported factory returns (`return new Stat(dir)`). Members copied
  onto `exports` in a `for...in` loop or with `Object.assign(module.exports,
  api)` count as exported. On the SecBench.js dev half, command-injection
  recall went from 40 to 46 of 49 (0.94, 95% CI 0.83 to 0.98), with no new finding in 150 benign npm packages or 16 app
  repositories ([scan.md](../docs/commands/scan.md#library-mode-scanning-a-package)).
- **One long line no longer hides a file from the code-sink check.** A file is
  skipped as minified only when lines over 5,000 characters hold more than half
  of it, so a generated parser with one long table line is read. On the
  SecBench.js dev half, code-injection recall went from 10 to 11 of 16 (0.69,
  95% CI 0.44 to 0.86).
- **`penthera deps` reads more of what an install hook runs.** It checks the
  command strings inside the file a hook runs (downloads, pipes to a shell,
  DNS or raw-socket senders), follows one hop to a script that file starts
  (`spawn("node", [file])`, `fork(file)`), treats `require()` of a decoded
  module name as obfuscation, and reads `process["env"]` like `process.env`.
  Running a shell from a hook is still not risky on its own: build hooks do
  that all the time.
- **New finding: a package that runs code it downloads.** A network call
  whose response reaches `eval`, `Function` or `vm` a few lines later is
  reported at high severity, with no install hook needed. A distance limit
  keeps a fetch helper and a template compiler in one bundle apart, and a
  module loader that tags the script with `sourceURL` is not counted.
  `Function.constructor(...)` now counts as dynamic code, and a whole copy of
  the environment passed to a call (`post(url, { ...process.env })`) as bulk
  environment access.
- **New finding: an entry file that sends command output out.** A file the
  package loads (`main`, `module`, `exports`) that runs a recon command
  (`whoami`, `ls`, `$(...)`) and sends the output with curl, a DNS lookup or a
  socket is reported at medium severity, with no install hook needed.
- **New finding: a dependency installed from a URL.** A `dependencies` or
  `optionalDependencies` entry that is an `http(s)://` tarball on a host
  other than the npm registry, GitHub, GitLab or Bitbucket is reported at
  medium severity. Git specs, aliases and `devDependencies` are left alone.
- **Fewer false alarms on Python `setup.py`.** Build code is now risky only
  when it downloads and runs: a shell next to network code, a download or
  send command, a recon command such as `whoami`, or decoded code. Running
  git, a compiler or a build tool, or `exec` of a local version file, is
  still reported as an install script, at low severity.
- On the E11b dev split, malicious npm packages that carry a payload go from
  0.66 to 0.83 flagged (69 to 87 of 105), with no new false alarm on 150
  popular npm packages or on 2,072 other packages from a local npm cache.
  False alarms on 150 popular PyPI packages drop from 11 to 1, while
  malicious PyPI packages go from 113 to 112 of 149 flagged.
- **New finding: Python code that reaches the network when imported.** A
  module whose module-level code, or a local function that code calls, makes
  a network call or runs a download or send command is reported at medium
  severity. Only modules an import can load count: top-level modules and
  files in a folder with an `__init__.py`. Tests, scripts, examples, docs,
  `setup.py`, `__main__.py` and code under the `__main__` guard do not.
- **New finding: a chat bot token or webhook key next to network code.** A
  Python library file that holds a chat bot token or a webhook URL with its
  key, and has network code, is reported at high severity. The finding does
  not repeat the key.
- **"Runs code it downloads" now covers Python.** A file that downloads to
  disk and, within 15 lines, starts the file or makes it executable, or runs
  a response with `exec`, is reported at high severity.
- **More Python obfuscation forms.** A statement hidden after 150 or more
  spaces, `exec` of an encoded literal through a renamed decoder, and `exec`
  reached through `builtins` now count.
- **`setup.py` helpers are followed further.** Penthera reads the helper
  modules `setup.py` imports three levels deep, prefers a package over a
  module of the same name as Python does, finds code under `src/`, and counts
  `pip install` run from build code as risky.
- On the E11b dev split, malicious PyPI packages go from 112 to 138 of 149
  flagged (0.75 to 0.93), with 1 false alarm on 150 popular PyPI packages
  before and after, none on 150 popular npm packages, and no new finding on
  221 other wheels from a local uv cache.
- **The password rule reads key names by their words.** It finds a password
  under a quoted key (`"password": "…"`, `'db_pass' => '…'`) and under a key
  with a prefix or suffix (`old_password`, `password1`, `adminPassword`,
  `DB_PASSWORD`), with `:`, `=`, `=>` or `:=`. Keys that are about a password
  rather than holding one (`password_hash`, `LABEL_PASSWORD`,
  `allow_empty_password`) are skipped.
- **Fewer false alarms on passwords.** Stored hashes (`$2b$…`, `{SSHA}…`),
  variable references (`$DB_PASS`, `#{password}`), booleans, labels and
  translated words, names (`keystore.password`), published defaults (`admin`,
  `changeit`), keyboard and counting sequences (`123456`, `qwerty`) and test
  values (`test123`) no longer count as a hardcoded password. Files in a
  translation folder (`locales/`, `i18n/`) get the fixed-shape rules only, as
  docs do.
- **Passwords in config files without quotes.** In YAML, `.properties`,
  `.env`, `.ini`, `.conf`, TOML and `.cfg` files a bare value counts too
  (`POSTGRES_PASSWORD: …`, `spring.datasource.password=…`). References
  (`${DB_PASSWORD}`, `{{ … }}`, `ENC(…)`, `env(…)`), YAML tags and aliases,
  paths, URLs and numbers do not.
- **The generic API key rule reads key names by their words too.** It finds
  API keys, API tokens, client secrets, auth tokens and AWS secret access
  keys under quoted, prefixed and suffixed keys (`"apiKey":`,
  `STRIPE_API_KEY`, `client_secret`), and bare values in config files. Names
  and stand-ins (`my_api_key`, `sk_test_…`), plain words, digits only and
  public or publishable keys no longer count.
- **More private-key shapes.** DSA keys, encrypted PKCS#8 keys
  (`ENCRYPTED PRIVATE KEY`) and PGP private key blocks are found, and so are
  keys built by string concatenation (`"-----BEGIN …\n" +`) or written on one
  line inside a JSON string. A key still needs its base64 body.
- **A file with many secrets lists them all, up to 200.** The scan stopped
  looking after 50 hits of one rule in a file, while a finding lists up to 200
  lines. It now looks for as many as it can list.
- **More provider token formats.** AWS temporary access keys (`ASIA…`, from
  STS) are found next to long-term ones (`AKIA…`), and so are every GitHub
  token prefix (`gho_`, `ghu_`, `ghs_`, `ghr_` and fine-grained
  `github_pat_`, not only `ghp_`), Stripe restricted live keys (`rk_live_`)
  and Postman API keys (`PMAK-`). AWS's documented example keys (they spell
  `EXAMPLE`) and runs of `X` don't count.
- **Tokens and secrets under more names.** The generic API key rule also
  finds OAuth access, refresh and ID tokens, bearer and session tokens,
  OAuth 1 token secrets, consumer, app, signing, webhook and cookie secrets,
  and a key named just `token` or `secret`. Because these names also hold
  test data and words, the value has to look generated: 16 characters or
  more, mixed character classes, not words, an email, a reference, an elided
  example or a typed run like `123456`. Pagination cursors (`next_token`) and
  names (`secret_name`) don't count.
- **reStructuredText, AsciiDoc and `.markdown` files are read as docs.** As in
  `.md` and `.txt`, only the rules that match a fixed shape (provider keys,
  private keys) run on them.
- **The secret scan reads more files.** It now reads key files (`.pem`, `.key`,
  `.p8`, `.ppk`), PHP, C#, `.properties`, `.conf`, `.xml` and Terraform state,
  plus any file without an extension that starts with a private-key header. In
  `.txt` and `.md` it runs only the rules that match a fixed shape (provider key
  prefixes and private keys), because docs are full of example passwords.
- **Fewer false alarms on secrets.** A private key must have its base64 body,
  so docs that only name the header, or elide the key as `...`, no longer count.
  A value that is just the key's name (`password = "password"`) and AWS's
  documented example access key are treated as placeholders.

### Changed

- **CI:** the install matrix's upgrade test now starts from 1.9.0, the
  version on npm `latest`.
- **Package size budget raised to 900 KB packed / 2.4 MB unpacked** for the
  E11b round-2 detection work (library mode's helper hop, more secret token
  formats, the PyPI malware passes). Still one runtime dependency.
- **A root `.mcp.json`** offers Penthera's own MCP server, pinned to 1.9.0, to
  agents that open this repository, and lets directories such as
  cursor.directory detect it. The internal audit keeps the pin in sync.
- **A secret finding lists every line it hit.** The scan still reports one
  finding per rule and file, so baselines and suppressions keep their ids, but
  the finding now carries `lines`, its description names the other lines, the
  terminal shows `+N more`, and SARIF lists them as related locations. A file
  with ten keys now shows ten places to fix.

### Fixed

- **No false litellm alarm.** Host indicators from the rule packs now match
  whole hostnames only, and every occurrence is checked. The attacker domain
  `litellm.cloud` no longer fires on `litellm.cloudflare_api_key` in the
  benign litellm 1.106.3, which E11 found. Subdomains, URLs and a host at the
  end of a sentence still match.
- **`--json` to a pipe no longer cuts the report off.** The CLI exited right
  after writing, so on a pipe (`penthera --json | jq`) any report over 64 KiB
  arrived truncated and was not valid JSON. It now exits once stdout has drained.

### Site

- **HSTS preload** on penthera.org, so browsers can ship it as HTTPS-only.

### Docs

- **E11: Penthera on public benchmarks.** A pre-registered study
  (`docs/research/prereg/E11-public-benchmarks.md`) and a runner
  (`npm run bench:public`, in `bench/public/`) score Penthera on datasets other
  people labelled: Samsung CredData for the secret scan, SecBench.js for
  code-execution sinks, and DataDog's malicious npm and PyPI packages, against
  a popular-package baseline, for the dependency scan. Results, with Wilson
  intervals, limits and rule ideas, are in `bench/public/RESULTS.md`. On
  CredData, secret precision is 0.58 [0.55, 0.60] and in-scope recall 0.27
  [0.26, 0.29], mostly because `.txt` and `.md` files are not read. On
  SecBench.js, no library command injection was found (0 of 96). The
  dependency scan flags 0.80 [0.75, 0.84] of malicious PyPI and 0.44 [0.39,
  0.50] of malicious npm packages, and 0.08 [0.06, 0.12] of popular PyPI and
  0 of 300 popular npm packages. Malware
  samples are only read as text, under `/private/tmp`, and deleted after the
  run. No rule changed.
- **E11b: a sealed dev/test split for improving on E11.** A draft amendment
  (`docs/research/prereg/E11b-improvement-study.md`) fixes the split, its
  SHA-256 hashes, the scoring units, the guards and the targets before any
  rule is tuned. `npm run bench:public -- --split dev` scores only the dev
  half; the test half runs once, at the end. The dev baseline and reference
  runs of gitleaks, detect-secrets and GuardDog are in
  `bench/public/RESULTS.md`.
- **E11b: eight more secret scanners on CredData dev.** TruffleHog,
  Nosey Parker, Kingfisher, ripsecrets, secretlint, Whispers, deepsecrets
  and CredSweeper run pinned, offline and scored the same way as gitleaks and
  detect-secrets. The table and its limits are in `bench/public/RESULTS.md`.
  CredSweeper was trained on CredData, so its row is not comparable.
- **E11b: seven more free tools on the DataDog malware set (dev).** ClamAV,
  YARA with YARA-Forge core, OSSGadget detect-backdoor, malcontent,
  Bandit4Mal and Aura run pinned, offline and static only, next to GuardDog,
  each flagging at its own default level
  (`bench/public/competitors-malware-tools.mjs`). OSV-Scanner with an offline
  OpenSSF malicious-packages snapshot is shown but not ranked: it looks up
  packages already reported, it does not detect. Packj was skipped: it needs
  the registry at scan time.
- **Ready for the Docker and Cline MCP catalogs.** `llms-install.md` gives
  Cline the `cline_mcp_settings.json` block, the Node.js 22 requirement and
  what the tools may do. `docs/commands/mcp.md` shows how to run the server in
  a container, where client roots are host paths: the server drops roots it
  cannot find and falls back to `--root`, now covered by a test. The Docker
  image's description is the approved one-liner, and `site/tools/logo.mjs`
  renders the 400 × 400 logo at `assets/penthera-logo-400.png`.
- **Public benchmark results, near the top of the README and on penthera.org.**
  On a sealed half of four public datasets, against up to ten free tools each:
  #1 on npm and PyPI malware, tied #1 on JavaScript library injection bugs,
  #2 on leaked secrets. Every table, interval and caveat is in
  `bench/public/RESULTS.md`; the README and the site are generated from the
  same numbers file. The walkthrough video moved below the star history.
- **README: dropped "One real fix".** The penthera.org before/after was a
  marketing example, not evidence. The README now leads with what it is and
  how to start.
- **README:** a status per part (stable, beta, experimental) and "Verify it
  yourself" with `npm audit signatures` and `penthera rules list`.

## [1.9.0] - 2026-10-23

Everything in [1.9.0-rc.1](#190-rc1---2026-10-22) below, plus:

### Security

- **Active modes ask before they start, and are rate-limited.** `--deep`,
  `--fuzz`, `--adaptive`, `--all` and `--profile deep` now need a
  confirmation bound to the target, as METHODOLOGY.md already promised;
  before, `--deep` only printed a warning. In a terminal Penthera asks (a yes
  for a target on this machine, the hostname typed back for any other).
  Without a terminal, pass `--confirm-target <host>`; a missing or mismatched
  host stops the run with exit code 2 before any request. This also covers
  the login burst and SQL error check that now run only under `--deep`. The
  wizard's deep and custom scans go through the same gate. Scripts that run
  active modes in CI need the new flag.
- New `--rate <n>`: one requests-per-second cap per scan, shared by all
  concurrent probes. Active scans default to 10; other scans have no limit
  unless set; `--rate 0` removes it. Waiting for a slot does not count toward
  a request's timeout or its measured duration, so timing-based checks are
  unaffected. The report records the cap as `egress.rateLimit`.

### Changed

- **`penthera ui` looks and reads like penthera.org.** The verdict is the
  headline, the score is a 10 × 10 grid of pixels, and each screen has one
  blue button. A run opens in check and fix mode, with Back at the top left
  (or `Esc`). The report and the plain-words box are brushed-metal plates lit
  by the pointer; the light is off with reduced motion and on touch screens.
  The inspector now says how to check a fix, and Simple mode folds what was
  fixed into one line. Nothing the dashboard reads, runs or sends changed.
- **Fresh screenshots and recordings.** The dashboard screenshots, the
  80-second walkthrough, the README loop, the terminal clips, the site's hero
  loop and the link-preview reel show the current dashboard and CLI. The reel
  now ends on the live-check share card.

### Fixed

- **A file that disappears mid-scan no longer stops the repo scan.** A SQLite
  `-wal` file deleted while `--repo` walked the tree crashed it with `ENOENT`.
  The walker now checks names before it stats an entry and skips any entry
  that is gone, or is no longer a regular file, by the time it is read.
- **Virtualenvs, Python tool caches and note vaults are skipped.** `venv`,
  `.venv`, `site-packages`, `__pycache__`, `.tox`, `.nox`, the mypy, pytest
  and ruff caches, `.obsidian`, and any folder with a `pyvenv.cfg` are no
  longer scanned for secrets. On the Python repository that found this, 42 of
  45 critical and high findings were third-party code in a venv.
- **The secret scan follows `.gitignore`.** In a git work tree, ignored folders
  are skipped like `node_modules`. A key in a single ignored file (the usual
  local `.env`) is still reported, at low with `localOnly: true`, since it is
  never committed.
- **Large files are scanned instead of skipped.** Files are read in 8 MB
  chunks that overlap, up to 512 MB per file (was a 16 MB skip), with the
  same line numbers as before. Runs of 512 or more base64 characters (inlined
  images, fonts) are blanked before matching, so `AIza...` or `AKIA...` shapes
  inside image data are no longer reported.
- **The coverage ledger matches what the secret scan read.** Files in a
  folder the scan skips (a virtualenv, a tool cache, a folder git ignores)
  are listed as "in a folder the secret scan skips", not as read.
- **The `.env.local` template matches again.** Its regex used an inline
  `(?m)` flag, which JavaScript rejects, and an unbounded repeat the regex
  guard refuses, so a served `.env.local` was never reported. The multiline
  flag now goes in the matcher's `flags`, and a test checks that every
  built-in template regex compiles and passes the guard.
- **A single-page app no longer reads as a leaked file.** The URL scan's
  sensitive-file check reported `/.env.production`, `/actuator/env` and
  others as "contains sensitive data" when an app served its index.html for
  every path and that page named `API_KEY` or similar. HTML pages no longer
  count for that check; `/phpinfo.php` and `/server-status` are recognised by
  their own page text instead.
- **No more critical "command-injection" for a Map lookup and a regex.** In a
  repo scan, `results.get("/robots.txt")` counted as a route and
  `/re/.exec(s)` as a shell exec. A route now needs a handler after its path,
  and `.exec(` counts only on `child_process`, `cp` or `shell`, or as a bare
  `exec(`. A route that passes request input to `child_process` still fires.
- **penthera.org:** the check-and-fix report starts below the header at every
  window size, instead of overlapping the logotype on wide screens.
- **penthera.org:** the share image and the link-preview reel carry a content
  hash in their URL, so X, LinkedIn and others pick up a changed card at once
  instead of showing a cached one.

### Site

- **Two landing pages, one search question each.** `/website-security-check`
  lists every check the live check runs and every request it sends;
  `/lovable-bolt-app-security` says what it finds in an app built with
  Lovable, Bolt or Base44, and what it cannot see, such as Supabase row level
  security. Both lead to the live check, are in the sitemap and `llms.txt`, and
  are linked from the footer. They are Markdown files in `site/pages/`.
- **IndexNow.** The key file is served at the site root, and
  `node scripts/indexnow.mjs` submits the sitemap's URLs after a deploy. It is
  run by hand, never by the build.
- **A 9:16 share card** for TikTok, Reels and Stories:
  `site/media/social/story.png` (1080 × 1920).
- **More npm keywords** for search on npmjs.com: `mcp-server`,
  `model-context-protocol`, `agent-skill`, `security-scanner`, `vibe-coding`,
  `secrets`, `website-security`, `security-headers`.
- **Current limitations, with what is planned for each.** The limits have a
  grey band of their own on penthera.org, with a roadmap line per limit,
  planned integrations (AI app builders such as Base44, Lovable and Bolt;
  preview deployments) marked as planned, and links to the methodology, the
  FAQ and the roadmap. The comparison now shows where each tool goes further
  and folds the full table behind a toggle. The hero labels are blue
  highlighter marks, and the problem line above them is marked line by line.
- **Only production builds on Vercel.** Pull request previews are skipped to
  save build hours; `node site/serve.mjs` serves the same site, headers and
  live check locally.
- **penthera.org tells one story, and agents can read all of it.** The page
  now runs problem, answer, what it checks, how to trust it, a numbered tour,
  the comparison, three ways to start (CLI, Agent Skill, MCP server, each
  with a copy button), "Before you install" and a "For agents" section.
  Sections that repeated each other are merged: the EU rules and Open R&D are
  FAQ answers, the walkthrough opens the tour. The build now also writes
  `llms-full.txt` (README.md and the user docs as one file), each docs page
  as Markdown under `/docs/`, `sitemap.xml`, `robots.txt` and
  `/.well-known/security.txt`, all from the repo. On a 375 px phone the
  comparison table no longer widens the page to 731 px.
- **A live security check on penthera.org.** Type an address, confirm it
  is your site and slide to scan. You get a score, the failures first with
  evidence, a fix and a command to verify it, and a prompt for your coding
  agent built from the checks you pick. The check is passive, only what one
  browser visit loads: headers, TLS, cookies, secrets and vulnerable
  libraries in the page and its scripts, SRI, mixed content, SPF, DMARC, CAA
  and security.txt. Nothing is stored, site owners can opt out in
  robots.txt, and the terms are at `/terms`. Deeper testing stays on your own
  machine: `npx penthera <url>`. The API is described in `/openapi.json`.
- **A clearer page.** Eight chapters, each answering one question once, and
  an About chapter. The drag-and-drop file check is gone. Brushed-metal
  plates lit by one light that follows the pointer, gradient numbers, a lit
  blue band and soft gradient buttons.
- **Ready for agents.** A Markdown version of the homepage at `/index.md`,
  Markdown 404s for agents that ask for it, JSON-LD, and a When to use
  section in llms.txt.
- **Every version pin on penthera.org comes from `package.json`.** The MCP
  configs and `llms.txt` pinned `penthera@1.9.0`, which is not on npm, so an
  agent that followed them failed. The build now fills in the package version
  (1.9.0-rc.1 today) everywhere, notes that the MCP server is on npm's `next`
  tag while the version is a release candidate, and a test fails if a pin is
  written into the page by hand.

### Docs

- **Docs reorganized around five journeys.** [docs/index.md](../docs/index.md)
  now starts from who you are: I'm new, I use AI coding tools, I run it in CI,
  I need evidence for an auditor, I'm a researcher. The five `docs/use-cases/`
  pages are folded into the command pages that answer the same question, and
  `docs/archive/` is removed (git history keeps it).
- **A shorter README.** What it is, a 30-second start (CLI, skill, MCP), what
  it checks, and how far to trust it, with the benchmark and E10 caveats next
  to the numbers.
- **`AGENTS.md`** for coding agents working on or with Penthera: commands,
  layout, the rules CI enforces, and pinned versions.
- **Correct version pins.** MCP examples pin `penthera@1.9.0-rc.1` (npm `next`)
  until 1.9.0 ships; CI examples pin 1.8.1 instead of 1.7.0. CONTRIBUTING,
  ROADMAP and SECURITY describe the 1.9 release candidate.
- **Try a release candidate with `npx penthera@next`**, not an install: an
  installed rc stays pinned in the lockfile. The Claude skill says so too.

## [1.9.0-rc.1] - 2026-10-22

Release candidate for 1.9.0, on npm's `next` dist-tag (`npm install penthera@next`).
New: `penthera mcp` (an MCP server for coding agents, local and read-only by
default), opt-in AI mode where a local model proposes and Penthera's rules
verify, new detection rules, and default scans that send no attack payloads.

### Added

- **Coverage ledger** in every `--repo` report (terminal, Markdown, JSON
  `coverage`): which files each check read, which it did not and why, and the
  source files no code analysis looked at. It reads only file names and sizes,
  and is the first step toward an opt-in AI mode.
- **AI mode, opt-in and experimental: `penthera --repo . --ai`.** A model in
  your local Ollama reads your code part by part and proposes problems no rule
  describes; Penthera checks each proposal with its rules. Confirmed ones mark
  the rule finding "also proposed by AI"; the rest are shown as
  "model-proposed, unverified", apart from rule findings, and never change the
  exit code. Every run asks first (default no), on stderr; runs that cannot ask
  need `--ai-consent local` or `"ai": { "allow": ["local"] }` in
  `penthera.policy.json`, or stop with exit 2 before scanning. Ollama cloud
  models (`-cloud`) are recognised and need a second screen where you type
  `ollama.com`. Secrets are masked before any code reaches the model; budgets
  (`--ai-budget`) are hard stops; consents are logged locally
  (`penthera ai consent`). `penthera ai models` lists models and where they
  run. See [docs/ai-mode.md](docs/ai-mode.md).
- **AI mode in the dashboard.** New scan has an AI mode switch, off; turning
  it on opens the consent sheet on every scan (a picture of where the code
  goes, the model picker, the terminal's exact consent lines, two equal
  buttons; cloud models need `ollama.com` typed). The server checks the
  model's route with Ollama itself and logs the consent. Runs show an
  "AI · local" tag, unverified proposals are folded under their own heading,
  and Settings lists the consent log.
- **`penthera verify <findings.json>`** checks findings from an AI security
  audit against Penthera's rules on your checkout. It reads Cloudflare's
  security-audit skill `findings.json` (schema vendored from commit `c1c8a8c`,
  MIT). A finding a rule agrees with is shown as Penthera's own finding, marked
  "also proposed by" the model; the rest are labelled "model-proposed,
  unverified" and never fail CI. Penthera runs no model and sends nothing
  anywhere. See [docs/commands/verify.md](docs/commands/verify.md).
- **`--audit-seeds <file>`** writes repo findings in the security-audit
  skill's `findings.json` schema, as seeds for an AI audit: each entry is
  `needs_validation`, names its class and the line the rule matched, and is
  checked against the skill's schema before it is written.
- Risky-pattern findings from `--repo` now carry the repo-relative `file` and
  the `pattern` name.
- **`penthera mcp`: Penthera as an MCP server for your coding agent.** Claude
  Code, Cursor, Codex, VS Code and Windsurf can call it over stdio. Add it
  with a pinned version: `claude mcp add penthera -- npx -y penthera@1.9.0 mcp`.
  Six read-only tools: `scan_repo`, `scan_url` (passive only),
  `check_dependencies`, `audit_ai_tooling`, `explain_finding` and
  `runtime_advisories`. Results are structured JSON plus a summary, with
  evidence at `file:line`, confidence labels and each tool's limits.
  - Tools read only inside the workspace roots, and symlinks cannot lead
    out. `scan_url` reaches loopback, or hosts you list with
    `--allow-host`; active modes are not reachable over MCP.
  - Text from scanned files has invisible characters removed and is marked
    as data, so a file cannot steer the agent through the results.
  - Speaks MCP 2026-07-28 and the earlier `initialize` versions. No new
    dependency, no port, no telemetry.
  - `server.json` and `mcpName` for the MCP Registry
    (`io.github.danoszz/penthera`). See `docs/commands/mcp.md`.
- **Secret findings carry the line number**, so reports and SARIF point at
  the line.

### Detection

- Three exposure checks in the default URL scan, each a documented miss in
  the E10 pilot (Juice Shop). All send plain `GET`s, no payloads:
  - a public Prometheus `/metrics` endpoint (medium), matched on the
    exposition format, so an SPA's index page at `/metrics` does not count;
  - browsable directory listings (medium) in folders that `robots.txt`
    disallows and in common upload and backup folders, matched on the
    listing's page title;
  - a stack trace in the error page for a path that does not exist (low),
    matched on Node.js, Python, Java, PHP and .NET frame shapes.
- The header audit reports an `X-Powered-By` header (low, `confirmed`), such
  as Express's default `X-Powered-By: Express`. It was a documented miss in
  the E10 pilot (DVNA). The finding names the value and how to turn the
  header off.
- The secret scan reads Terraform and HCL files (`.tf`, `.tfvars`, `.hcl`).
  A private key inline in a Terraform file was a documented miss in the E10
  pilot (Juice Shop).
- New secret rule: a session signing secret written into
  `session({ secret: '...' })` or `cookieSession(...)`, including a hardcoded
  fallback after `process.env.X ||` (high). Express's documented example,
  `'keyboard cat'`, was a documented miss in the E10 pilot (DVNA).
- The repo scan looks for code-execution sinks in all server code, not just
  route handlers: `eval`/`new Function` with a non-constant argument, `vm`
  calls and `child_process` `exec` with request data in their arguments.
  A taint-lite pass (assignments and destructuring within one file) sets the
  confidence: `likely` when request data reaches the sink, `potential` for an
  `eval` of a value it cannot trace. Before, a repo with an Express `routes/`
  folder stopped before any code-pattern check; three E10 pilot misses (DVNA's
  `exec` in `core/appHandler.js`, Juice Shop's B2B `vm` and profile `eval`)
  came from this.
- The advisories pack knows MongoDB: end-of-life lines from MongoDB's
  lifecycle schedule (4.4 ended 2024-02-29, 5.0 on 2024-10-31, 6.0 on
  2025-07-31, and the interim releases), matched against the official `mongo`
  image in Dockerfiles and compose files and `mongodb` in `.tool-versions`.
  `mongo:4.4.29` in Juice Shop's compose file was a documented miss in the
  E10 pilot. **The pack is unsigned in this change**: the maintainer signs it
  (`scripts/rules/sign-pack.sh`) before release.

### Changed

- **Faster merges for contributors.** Pull requests get a quicker install check
  (Linux and macOS, Node 22), and docs-, site- or benchmark-only changes skip it.
  The merge queue and `main` still run the full matrix (Linux, macOS and
  Windows on Node 22 and 24, plus the upgrade test). Release notes are written
  as fragments in `changelog.d/`, so parallel pull requests no longer conflict
  on `CHANGELOG.md`.
- **The default scan sends no attack payloads to your login.** A URL scan
  used to POST nine logins and an `' OR '1'='1` string to `/api/login`,
  which a CDN firewall (Vercel, Cloudflare) can read as an attack and start
  challenging you. Now `quick` sends no login request, `standard` sends one
  login with invalid credentials (to catch a login that accepts anything),
  and the rate-limit burst and the SQL error check run only with `--deep`.
  The MCP `scan_url` tool follows the same profiles.

### Fixed

- `penthera ui` listens for SIGINT and SIGTERM before it prints that it is
  listening. A signal that arrived in between got the default action and
  killed the process without "Stopped." (seen as a hung CI test; about one
  run in a hundred locally). The test now fails within seconds with the
  child's output instead of hanging for three minutes.
- `--repo` scans of Express, Hono and Fastify apps with a `routes/`, `api/` or
  `server/routes/` folder now get route discovery, trust-boundary and
  risky-pattern checks. That folder was taken for a Next.js API root, no
  `route.js` files were found there, and route analysis stopped. An explicit
  `--api-root` is still used as given.
- **TLS keys anyone can compute.** URL scans report, as critical, any
  certificate in the served chain whose EC public key (P-256, P-384, P-521) is
  k·G for a private scalar k below 1024. The private key then follows from
  the certificate alone. This is the flaw in eMudhra's P-384 intermediates
  ([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449),
  private keys below 256). The check is arithmetic, not a list, so it has no
  false positives and no data to maintain. Research note:
  [docs/research/emudhra-weak-keys-2026-10.md](docs/research/emudhra-weak-keys-2026-10.md).
- **Node.js security release of 21 October 2026** in the `advisories` pack:
  CVE-2026-111497 (Brotli decoder out-of-bounds write, remote code execution)
  and the TLS certificate hostname bypasses CVE-2026-106069, CVE-2026-105483
  and CVE-2026-106072, fixed in 22.23.4, 24.22.1 and 26.12.1, from
  [nodejs.org](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
  Node.js has no server banner, so repo scans find it (`.nvmrc`,
  `.node-version`, `.tool-versions`, `node:` images); 20.x and 25.x are
  reported as end-of-life lines. The pack's signature was removed with the
  change; `npm run rules:check` fails until the maintainer re-signs it.
- **Python start-up code in wheels.** `penthera deps` now finds `.pth` files
  and a shipped `sitecustomize.py` / `usercustomize.py` wherever a wheel puts
  them at the site-packages root, including `<name>-<version>.data/purelib/`
  and `platlib/`, the layout the malicious litellm 1.107.0 used
  ([OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144)). Before,
  only top-level `.pth` files were read, so that wheel's hook was missed until
  it was installed. A `.pth` import of clean code is now medium (was low);
  risky code behind it, or any shipped `sitecustomize.py`, is high. The
  `penthera install` policy holds `startup-hook` for approval by default.
- **PyPI indicators.** A new rule kind, `ioc-pypi-package` (PEP 503 names,
  PEP 440 versions, kept apart from npm names), and a new bundled pack,
  `ioc-pypi-2026`, with the litellm 1.82.7, 1.82.8 and 1.107.0 versions, the
  1.107.0 payload files by SHA-256 and its endpoints. Python scans now run
  `ioc-file` and `ioc-host` rules too. The pack is unsigned until the
  maintainer signs it, so `npm run rules:check` fails until then.
- **The pre-commit hook keeps working when the npx cache is cleaned.** A hook
  installed through `npx penthera` pointed at a copy in npm's cache; once
  that was gone, every commit skipped the check silently. It now falls back
  to the same version through npx (`npx -y penthera@<version> hook run`,
  pinned), and only skips, with a clear warning, when that cannot run either.

### Site

- The FAQ says how to scan your own site behind Vercel's or Cloudflare's
  firewall: allow your IP first, or scan a preview URL.

### Docs

- README, ROADMAP and the research plan describe what is on main for 1.9
  (`penthera mcp`, AI mode, new detection, no attack payloads by default) and
  list the E10 benchmark.

## [1.8.1] - 2026-10-22

A fixes-only release. Runtime advisories are more careful: pre-release builds
are never reported as having the fix, a banner without a distribution token is
at most `potential`, release lines older than a flaw are not reported as
affected, and two more banner formats are read. `penthera ui` now stops
cleanly under `npx`.

### Fixed

- Runtime advisories no longer claim `likely` for a banner that may be a
  patched distribution package. Debian 11 to 13, Ubuntu 24.04 and later, and
  RHEL print plain upstream PHP versions, so a patched Ubuntu 24.04
  `X-Powered-By: PHP/8.3.6` behind nginx or a CDN was reported as critical
  and likely affected. For PHP, Apache httpd, nginx, Python and OpenSSL,
  "affected" and "end of life" findings from a banner with no distribution
  token are now `potential`, with a "check on server" note and the check
  command. Severity is unchanged. Official images and version files are
  upstream builds and stay `likely`. Found by the runtime-strings test set
  (L1 in [#97](https://github.com/danoszz/penthera/pull/97)).

- Runtime advisories resolve Node.js LTS codenames to their release line:
  nvm's `lts/iron` in `.nvmrc` and the node image's `iron`, `jod-alpine`
  and `hydrogen` tags. They read as no version before, so `lts/iron` (Node.js
  20, end of life 30 April 2026) went unreported. Found by the
  runtime-strings test set (B4 in
  [#97](https://github.com/danoszz/penthera/pull/97)).
- Runtime advisories read aiohttp's `Server: Python/3.9 aiohttp/3.8.6`.
  aiohttp prints only the Python release line, and the banner pattern needed
  x.y.z, so an end-of-life Python behind aiohttp went unreported. Found by
  the runtime-strings test set (B3 in
  [#97](https://github.com/danoszz/penthera/pull/97)).
- Runtime advisories honour `introduced` on older release lines. CVE-2021-41773
  and CVE-2021-42013 exist only in httpd 2.4.49 and 2.4.50. Yet
  `Apache/2.2.34` and `httpd:2.2` were reported critical, "end of life, no
  fix", and CentOS 6's `Apache/2.2.15 (CentOS)` was "check on server". A line
  older than the one the flaw was introduced on now gets no verdict for it.
  The end-of-life finding stays. Found by the runtime-strings test set (B1 in
  [#97](https://github.com/danoszz/penthera/pull/97)).
- Runtime advisories read pre-releases correctly. `PHP/8.4.27-dev`, a PHP-8.4
  branch build from before 8.4.27, was taken for a distribution build of
  8.4.27 and reported as having the 21 October fix. Now `-dev`, alpha, beta
  and RC builds (`8.5.0RC1`, `3.15.0rc1`, `4.1.0-beta2`, `php:8.6.0RC4-fpm`)
  sort below their release, so a pre-release of the fixed version is
  affected. A pre-release of the version after the fix (`8.4.28-dev`) is
  "check on server", never "has the fix". Found by the runtime-strings test set
  (B2 in [#97](https://github.com/danoszz/penthera/pull/97)).
- **`npx penthera ui` stops cleanly on Ctrl-C and SIGTERM.** npm forwards
  the signal to penthera right after the terminal delivered it, and the
  second copy could kill the dashboard before it printed "Stopped." and
  closed its server. Repeated signals are now ignored while it stops. This
  was the intermittent macOS failure in the install-matrix smoke check.

### Site

- penthera.org counts anonymous page views and load times with Vercel Web
  Analytics and Speed Insights (cookieless, served from the same origin). The
  CSP now allows connections only to those two paths on penthera.org; the
  browser check still sends nothing, and the page says so. The CLI, the
  dashboard and the npm package have no telemetry, unchanged.
- A shared penthera.org link now plays a 14-second muted reel in iMessage
  and other apps that support `og:video`: setup, an offline scan, the
  verdict, the PHP advisory of 21 October 2026, and the share card.
  `og.png` stays the poster and the fallback; X keeps the image card.
  Rendered by `site/tools/reel.mjs`.

### Research

- Draft protocol for experiment E10: Penthera against six deliberately
  vulnerable apps with public answer keys (Juice Shop, DVNA, NodeGoat, DVWA,
  crAPI, WebGoat), each pinned by commit and image digest. Answer keys in
  `bench/known-vuln/`, frozen before any scan; an opt-in runner
  (`npm run bench:known`, not in `npm test` or the package) starts the apps
  isolated in Docker on 127.0.0.1. A pilot on Juice Shop and DVNA is in
  `bench/known-vuln/RESULTS.md`, marked as a pilot.
- Each of the pilot's 13 standard-run misses is verified in
  `bench/known-vuln/MISSES.md` (all real gaps; none a scoring artefact).
  A re-run after the fixes that followed (#107, #108, #110, #111) is in
  `bench/known-vuln/RESULTS-after-fixes.md`, next to the unchanged pilot:
  pooled standard recall 1/14 to 10/14 at the same precision, flagged as not
  independent, with WebGoat as a held-out app that did not change. The
  runner gains `--out <file>`.

### Docs

- Compared with Cloudflare's security-audit skill: a side-by-side in
  `docs/compare/` and a research note on how Penthera can read its findings,
  re-check them with rules and seed it, plus a proposed experiment (E9).
- The PHP case study and `docs/runtime-advisories.md` cite OpenAI's
  php2shell-checker as an independent cross-check. A test pins that Penthera
  agrees with its table on all 14 PHP branches.
- The website is live at [penthera.org](https://penthera.org): the README links
  it, and the npm package's homepage points to it from the next release.

## [1.8.0] - 2026-10-21

1.8.0 is 1.8.0-rc.1 plus the changes below; there was no separate rc.2
release. Highlights across both: fixes from a second independent security
review, a fix loop that cannot edit the tests that judge it, the redesigned
dashboard (Simple and Advanced mode), release checks on Linux, macOS and
Windows, and now runtime advisories, starting with PHP's critical security
release of 21 October 2026, in a new signed `advisories` rule pack (1.8.0-rc.1
cannot load it). The benchmark gained two PHP cases: precision 0.88 (95% CI
0.69 to 0.96) and recall 0.91 (0.73 to 0.98) on 24 scored findings.

### Added

- **Runtime advisories: is the PHP, Apache, nginx, Node.js, Python or OpenSSL
  you run affected?** URL scans read `Server` and `X-Powered-By` banners, the
  `PHPSESSID` cookie name and `.php` pages. Repo scans read Dockerfile and
  compose images, `.tool-versions`, `.php-version`, `.nvmrc`,
  `.python-version`, `runtime.txt` and `composer.json`. Each product and
  version gets one answer: affected, end of life with no fix, check on server,
  or has the fix (as advertised). A hidden version is never reported as safe.
  A distribution build (`8.1.2-1ubuntu2.19`, or any version behind a `Server`
  header that names a distribution) is never reported as affected, because
  distributions backport fixes under the same version number. Advisories that
  need more than a version (Windows, CGI) stay `potential`. See
  [docs/runtime-advisories.md](docs/runtime-advisories.md).
- **Two rule-pack kinds, `runtime-advisory` and `runtime-eol`**, so a new
  advisory ships as a signed data pack (`--rules`) the same day, without a
  release. End of life is judged by the pack's date, not the scan's clock.
- **A bundled `advisories` pack** with the PHP security release of 21 October
  2026 (CVE-2026-109618 and CVE-2026-109619, both Critical, CVSS 4.0 9.2,
  fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12, from the php-src advisories),
  vendor-checked worked examples (CVE-2024-4577 and CVE-2024-8926 for PHP-CGI on Windows, CVE-2021-41773 and
  CVE-2021-42013 for Apache HTTP Server 2.4.49 and 2.4.50) and end-of-life
  release lines. Benchmark cases for both URL and repo scans.

### Site

- **A landing page in `site/`**, a static site for Vercel: the positioning,
  `npx penthera`, prompts for Claude Code, Cursor and Codex, the hero loop and
  the walkthrough, the limits and the research plan. No third-party scripts,
  analytics or cookies; fonts are self-hosted or system fonts.
- **A check in the browser.** Drop or paste a `package.json`, `.mcp.json`,
  `.claude/settings.json`, `CLAUDE.md` or `AGENTS.md` and Penthera's own
  `lib/` code runs in the tab: the agent-config rules, the secret patterns,
  install scripts, typosquats against the vendored popular list, and the
  bundled IOC pack. `site/build.mjs` bundles `lib/` at build time, so the site
  and the CLI run the same rules; `tests/site.test.js` holds the page to the
  CLI on the agents and deps fixtures. The page is served with
  `connect-src 'none'`, so it cannot send the files anywhere.
- **Runtime advisories in the browser check.** Drop a `Dockerfile`,
  `compose.yaml`, `.php-version`, `.tool-versions` or `composer.json`, or
  paste the response headers `curl -sI` printed for your site (the page never
  contacts it), and `lib/advisories` runs on them: the same findings and
  confidence as the CLI, with "check on the server: distributions backport
  fixes" next to every version-only verdict. `tests/site.test.js` compares
  pasted headers with a URL scan of a loopback server sending the same
  headers, and runtime pins with `runtimeAdvisoriesForRepo`.
- `penthera deps` findings are built in `lib/deps/findings.js` (moved from
  `lib/deps/index.js`, no behaviour change), so the browser check uses the
  same wording.
- `scripts/docs-commands.mjs` also checks every command the site shows.

### Docs

- **New title for the launch:** "Penthera: your open-source cyber security
  agent", in the README, docs index, `penthera --help`, the GitHub Action name
  (which renames its Marketplace listing), the dashboard and the report
  footer.

- **README hero is a 12-second loop** of the terminal and the dashboard
  (setup, an offline scan, Simple and Advanced mode, a fix approved), cut from
  the walkthrough video by `scripts/media/hero-gif.sh`, and it loops without a
  jump. The terminal-only scan clip is now `assets/demo-scan.gif`. The Demo
  media workflow re-cuts the loop on every release.
- **The README diagram is back**, updated: what Penthera checks, where the
  findings go, and that the fix loop asks first and cannot edit its own tests.

## [1.8.0-rc.1] - 2026-10-20

Release candidate for 1.8.0, published on npm's `next` dist-tag
(`npm install penthera@next`). It becomes 1.8.0 on `latest` after it has run
on real projects without a blocking issue.

### Security

Fixes from a second independent review. Most also apply to 1.7.0; upgrading
is recommended.

- **Dependency scans fail closed.** An npm or Python package that could not be
  read in full (a code file over 64 MB, more files than the reader takes, an
  archive with inconsistent sizes or other structural anomalies, a matched
  artifact that cannot be opened) is now `unscanned`: a high "could not be
  scanned" finding that `penthera install` always holds for approval. The
  Python scanner gained this state. Wheels are capped on the bytes actually
  inflated. Pax global headers that set a size or path are refused. Deeply
  nested `uv.lock`/`poetry.lock` files are a parse error, not a crash.
- **The fix loop and `fix --apply` run git hardened.** Commit and tag signing,
  signing programs, attribute files and every configured filter driver are
  overridden on every call (`--attr-source` on git 2.40+). Pathspecs are
  literal. Writes are refused when the repository's own config sets
  `filter.*`, `gpg.*` or `include.*`, or on git older than 2.31; the loop then
  does not start, and its one message names the key and how to go on.
- **The fix loop keeps your uncommitted work.** Dirty files are read with
  `status -z` and re-checked right before every write and commit. Reverts
  restore the exact bytes from before the fix, and only while the file still
  holds what penthera wrote (otherwise the fix is a `conflict` and the file is
  left alone). Commits use `--only`. Plans that touch untracked or ignored
  files are skipped, and every revert step runs even when one fails.
- **`applyDiff` is all-or-nothing and writes only regular files in the repo.**
  Duplicate and nested paths are refused, a failed apply puts back what it
  wrote, files are replaced through a temp file (never written through a hard
  link), NTFS stream names and 8.3 aliases are refused, and added lines may not
  contain control characters. Approval prompts show control characters as
  escapes.
- **The pre-commit hook checks everything it should.** Staged content is read
  by object id from NUL-separated output, type changes are included, files
  with NUL bytes are scanned, and a staged file over 16 MB blocks the commit
  (or warns, with `"largeFiles": "warn"`). `hook install` no longer writes
  through a symlinked `pre-commit`.
- **Secret scanning checks every match.** A placeholder no longer hides a real
  secret of the same rule later in the file. Only regular files are read, with
  a per-file size cap.
- **Dashboard sessions are bound to the page.** The one-time token travels in
  the URL fragment and is exchanged for a per-tab session sent as an
  `Authorization` header; no cookie is set or accepted. Approvals carry the
  sha256 of the diff shown, and a cut diff says so and needs an explicit
  acknowledgement. A symlinked default `reports/` is refused and every write
  re-checks the folder. Event ids keep counting past the buffer; requests,
  bodies (413), finished runs and open streams are bounded. `--open` no
  longer puts the token on a command line.
- **Evidence bundles** are built in a private folder and renamed into place,
  and verification never follows a symlinked folder and caps what it reads.
- **HTTP responses are bounded.** Every body is read with a size cap (counted
  after decompression) and a deadline that covers the body, not just the
  headers. `--offline` compares host and port, and cross-origin redirects drop
  credentials and do not replay request bodies.
- **Linear-time matching on untrusted text.** Agent-config exec patterns and
  other agent and hook checks no longer backtrack on long input. The rule-pack
  regex guard refuses ambiguous alternation and optional items inside repeated
  groups and end-anchored rescans; community templates use the same guard.
- **Hostile repos no longer hang or crash scans**: a FIFO is never read, and
  deeply nested JSON is handled; one unreadable agent config becomes a finding
  instead of aborting the run.
- `--fix-model` never sends a file from outside the repo as context.
- Installing the hook through pre-commit.com no longer runs the test suite:
  the `prepack` script is gone (publishing still runs `npm test`).
- Workflows that push or only read no longer keep credentials in the checkout.
- **The fix loop cannot game its own checker.** A fix diff, from a local
  model or a recipe, may not edit tests, test runner config or the test
  script, Penthera's policy, suppressions, baseline, lock or memory, CI
  workflows, git hooks or lockfiles; `applyDiff` refuses it with `PROTECTED`
  and says to make that change by hand. The loop verifies only against the
  checker the run began with. "Could not fix" is now a recorded outcome
  (`gave_up` in memory, `loopRun.gaveUp`, a summary line): the finding is not
  retried in that run, and a give-up never counts against a recipe. Older
  Penthera versions report a memory chain with `gave_up` events as malformed.

### Added

- Release checks in CI (`.github/workflows/install-matrix.yml`): the packed
  tarball is installed into an empty project and run with `npx penthera` on
  Linux, macOS and Windows with Node 22 and 24 (setup wizard dry run, deps,
  agents, repo scan, the pre-commit hook on a real commit, the dashboard's
  token check, bundled rule pack signatures). An upgrade job installs 1.7.0
  from npm, writes memory and dashboard state, upgrades to the tarball and
  checks the old memory chain still verifies and grows. All of it runs under a
  network guard that fails on anything past loopback.
- Docs as tests: `scripts/docs-commands.mjs` checks every command in the
  README, `docs/` and the skill against `--help` and runs the offline ones on a
  fixture, in `npm test` and against the installed package.
- Provenance check in CI (`scripts/ci/provenance.mjs`): every commit in a pull
  request that names an AI co-author must carry an `AI-Assisted` line, and the
  other way round.

### Fixed

- Windows: `npx penthera` / `penthera init` in a git repository failed with
  "Refusing to write outside the project" for its own `reports/` folder, because
  git prints the repo root with forward slashes. Git roots are now native paths.
  Found by the new Windows install checks.
- `penthera --help` lists `--rules-signers` and `--allow-unsigned-rules`. Both
  worked and were documented in `docs/rule-packs.md`, but the help left them
  out.
- `penthera ui`, Advanced mode: a run's transcript no longer shows a stray
  "null" under its title.

### Changed

- **`penthera ui` redesigned for people who are not programmers.** A first
  visit runs a three-screen setup (what Penthera does, Simple or Advanced, the
  project and a first check). Simple mode, the default, leads every project
  with a one-sentence verdict ("Not ready to ship: 1 critical problem to fix
  first."), lists problems in plain words, explains each one as what is wrong,
  how sure and what to do, and tells a run as one sentence. Advanced keeps
  everything, now as project tabs (Findings, Dependencies, AI tooling, History,
  Proof) with a severity by confidence triage matrix. A menu bar replaces the
  prompt bar and carries every action with its shortcut and the run status;
  runs start from a New scan window; every change waits in its own window
  (`y`, `n`, `q`). New look: a 1-bit "System" register of tiled windows, dither
  patterns instead of greys, `#0000ed` as the one accent, Departure Mono (OFL,
  self-hosted) for chrome, the serif Penthera wordmark, and a halftone field
  whose density is the open risk. Both themes pass WCAG AA in every state.
  `scripts/dashboard-screenshots.mjs` regenerates the docs screenshots.
- Smaller npm package: 797 kB to 657 kB packed, 2.3 MB to 1.7 MB unpacked. The
  package ships only `docs/examples/` (the documentation lives on GitHub, and
  README links resolve there), and the popular-package lists for the typosquat
  check are stored gzipped. No behaviour change.
- Code cleanup, no behaviour change: one git runner (`lib/git.js`), one
  temp-folder helper, one Markdown table-cell escape and one JSON fetch
  helper replace their copies; unused exports and helpers are gone. CI now
  runs `npm run lint` (ESLint, dev-only, minimal rules). Still one runtime
  dependency.

### Docs

- **Penthera is described as an open R&D project with a usable tool:** "an
  open-source cyber security agent you can use today, and verify yourself."
  The README, `docs/index.md`, `package.json`, the plugin and marketplace
  manifests, the Agent Skill (trigger phrases kept), the GitHub Action and the
  repository description carry the approved wording. The README has a "How it
  is measured" section (method, evidence, tool) with Wilson intervals next to
  the benchmark numbers, and stays under 14 KB.
- **One roadmap, one research plan.** `ROADMAP.md` now says what ships next,
  starting with the 1.8.0 feature freeze. `docs/vision-2.0.md` is the research
  plan and holds the quality gates from `docs/plan.md`. `docs/plan.md`,
  `docs/release-plan.md` (v1.2 to v1.4) and the Socket positioning notes moved
  to `docs/archive/`.
- **Every user-facing page names the question it answers**, for a starter ("is
  my app safe to ship?") or a pro ("how do I put it in CI?"), and
  `docs/index.md` has a Start here path from starter to pro.
- **Voice guide** (`docs/voice.md`): plain words, short sentences, numbers with
  intervals over adjectives, limits next to claims, no hype. Every user-facing
  page was edited against it.
- **Release cadence** in CONTRIBUTING: at most one minor release every 2 to 4
  weeks, always through an `-rc.N` on npm's `next` tag, patches for fixes only,
  and a feature freeze before each minor. Current freeze: 1.8.0 = main + #63.
- Fixed stale facts: SECURITY.md's supported versions (1.2.x to 1.7.x), README
  anchors that no longer existed, Agent Skill links into `docs/` that broke in
  the npm package since the docs stopped shipping there, and the partner brief
  and due diligence notes that still called shipped features "in review".
- Limitations stated in full: the methodology's "Known limitations" now covers
  every module (deps, AI tooling, fix loop), the evidence (small sample, wide
  intervals, same-team benchmark, single labeller, uncalibrated confidence
  labels), reproducibility, AI-assisted development, and compliance output. The
  2.0 research program adds "Threats to validity".
- GenAI disclosure: `docs/genai.md` states how Penthera is built with
  generative AI (models, scale, review gates, licensing, logs), the README has a
  short "How Penthera is built" section (107 of 117 non-merge commits up to
  v1.7.0 written with Claude), and CONTRIBUTING requires an
  `AI-Assisted` trailer on AI-assisted commits. Follows NLnet's generative AI
  policy.
- `docs/MANIFESTO.md`: what Penthera is today (and is not), seven design
  decisions with their costs and what would change them, and an FAQ. Written to
  be challenged in Discussions.
- **After the 2026 agent incidents:** `docs/research/agent-incidents-2026.md`
  says what the OpenAI–Hugging Face and Anthropic evaluation incidents mean
  for Penthera, with sources and caveats. `docs/agents-safely.md` is a
  one-page checklist for running AI agents. `docs/research/spec-harness-rules.md`
  specifies planned `harness-*`, `sandbox-*` and `scorer-*` rules (not built
  yet), and the research plan adds E7 and a draft pre-registration for E8
  (do harness guardrails reduce judge tampering?).
- README: a "Building in public" section linking the CHANGELOG, the freeze, the
  research in progress and the roadmap. Counts refreshed (57 references);
  `npm run docs:numbers` now also counts the secret patterns in the core rule
  pack (20, as the README says, not 8).
- `docs/genai.md` covers commits since v1.7.0 and how the agents that build
  Penthera are contained; the manifesto says the fix loop cannot edit what
  judges it.
- `docs/vision-2.0.md`: the plan for 2.0, covering the biggest gaps, an AI roadmap
  (models propose, deterministic checks decide; local models first) and a
  pre-registered research program with sample sizes and safety rules.
- **An 80-second walkthrough video** (`assets/walkthrough.mp4`, with a poster
  and `walkthrough.vtt` captions) shows `npx penthera`, an offline scan of the
  mock server, `penthera ui --demo` in Simple and Advanced mode, one fix
  approved and the owner report. It is linked from the README and
  `docs/index.md`. `scripts/media/walkthrough.mjs` renders it from demo data
  only, and the Demo media workflow re-renders it on every release.
- **The terminal GIFs are re-rendered** in the dashboard's black and white
  look. `scan.tape` now writes the README hero (`assets/demo.gif`) directly
  and scans with `--offline`. The `agents` and `deps --diff` tapes rendered a
  "Cannot find module" error, because they ran `bin/penthera.js` by a
  relative path after changing folder; they use an absolute path now.

## [1.7.0] - 2026-10-19

One view and one command. `npx penthera` now sets Penthera up in a project:
it detects what is there, asks what to check, runs it offline and offers the
hook, the PR workflow and the dashboard. `penthera ui` is a single view with
side panels. The README is rewritten, and the methodology and references
follow APA 7.

### Added

- **`penthera init`, the setup wizard** (also `npx penthera` with no arguments
  in a terminal). It detects the project offline (git, framework, npm and
  Python lockfiles, agent config, a dev server on localhost, an existing hook
  or workflow), asks one checklist question, runs the code, dependency and AI
  tooling checks (and the running app, only after you confirm it is yours),
  then shows the grade per area, the three things to fix first and one report
  folder, `reports/penthera-<date>/`. It then offers, one yes/no each, the
  pre-commit hook, a `.github/workflows/penthera.yml` pinned to the release
  commit SHA (shown as a diff first), `reports/` in `.gitignore`, the fix loop
  and the dashboard. `--yes` takes the safe defaults and never scans a URL,
  runs the fix loop or opens the dashboard; `--dry-run` prints the plan.
  Nothing is committed or pushed. See [docs/commands/init.md](docs/commands/init.md).

### Changed

- **`penthera ui` is one view, like the Claude Code desktop app.** A
  collapsible left sidebar lists projects (grade, open findings, last scan)
  and recent runs grouped by project, with "+ New scan" on top and settings
  behind a gear. The centre is one scrolling stream: the selected project's
  header (grade, severity bar, trend sparkline), what changed since the last
  scan, "Fix first" and the findings; a running scan or fix loop streams there
  as a transcript with Apply / Skip / Stop inline on each diff. A prompt-style
  bar starts scans, dependency checks, AI tooling audits and the fix loop. The
  collapsible right panel stacks Environment (egress, folder, git branch),
  Memory, Dependencies, AI tooling, Evidence and Changes cards, and shows a
  finding's detail when you pick one. `[` and `]` toggle the side panels, which
  become drawers at narrow widths. Calmer chrome, one primary action at a time;
  the themes, `--demo` and every security property are unchanged. New
  `GET /api/env` reads the branch through the agent's hardened git runner.
- `penthera-scan` keeps the URL-first wizard that `penthera` used to open.

### Docs

- README rewritten in the voice of "Penthera: Cyber Security Agent". The
  dashboard screenshots now sit directly under the demo GIF; "Get started" leads
  with one command (`npx penthera`); features are grouped as before you deploy,
  what you build with, and after you ship; and a new "Research and
  methodology" section gives the method, the benchmark numbers, and how to cite
  Penthera. About 12 KB, down from 19 KB.
- `docs/references.md` is rendered in APA 7th edition style from
  `docs/references.bib`, sorted by first author within each topic, with an
  anchor per BibTeX key. Editors for the three Springer proceedings and the NDSS
  proceedings titles were added from Crossref. A test covers the formatter.
- `docs/METHODOLOGY.md` uses APA in-text citations, opens with an abstract and
  a "How to cite" block that mirrors `CITATION.cff`, and now cites every
  reference. A test fails if a citation does not resolve or a reference is
  never cited, and the internal audit checks the "How to cite" version.

## [1.6.1] - 2026-10-19

The GitHub Action gets its Marketplace name. Nothing else changes.

### Changed

- The GitHub Action is listed on the Marketplace as "Penthera: Cyber Security
  Agent". The `uses:` reference is unchanged.

## [1.6.0] - 2026-10-19

Hardening and reach. An independent 360 review found three high-severity bugs, two of them reproduced; all are fixed with regression tests, and the open code-scanning alerts went from 18 to the 2 that need a second maintainer. `penthera deps` now covers Python, `penthera ui` adds a local dashboard (black or white, in the project blue), and every release passes an internal audit first. 1.5.0 was never published to npm; this release includes it.

### Security

- Cleared the open code-scanning alerts. The community-template regex guard
  was itself a polynomial regex; it is now a linear scan, and an invalid
  extractor regex no longer aborts a template. Markdown table cells escape
  backslashes first (one shared helper). `<script>` extraction is a tokenizer
  that accepts any case and junk in closing tags. Release workflow: read-only
  top-level token, hash-verified npm, no dependency cache. Docker base image
  pinned by digest. fast-check property tests fuzz the untrusted-input parsers.

Fixes from an independent 360 review of `main`. The first three were
reproduced; each fix has a regression test that fails without it.

- **High: tar desync hid install scripts from the install firewall and
  `penthera deps`.** A GNU base-256 size field parsed as 0, the reader lost its
  place, and 512 zero bytes then read as end-of-archive, so `package.json` and
  everything after it went unscanned and the package looked clean. The tar
  reader now handles base-256 sizes and pax `size=`, checks every header
  checksum and fails closed on any anomaly (malformed size, truncation, data
  after the end marker). A package whose archive or `package.json` cannot be
  read is reported as "could not be scanned" (high) and always needs approval
  in `penthera install`; a lockfile `hasInstallScript` that the scan cannot
  find is a high finding and is always denied (except the known benign case
  of a package that ships only prebuilt `.node` binaries, like fsevents 2.x)
- **High: `applyDiff` wrote through a dangling symlink out of the repo.** Every
  path component is now `lstat`-ed and any symlink is refused; creates use
  `O_CREAT|O_EXCL|O_NOFOLLOW`
- **High: `.GIT/` bypassed the `.git` guard on case-insensitive file systems.**
  Any path segment that is `.git` in any case, at any depth (plus HFS+ and
  NTFS aliases such as `.git.` and `GIT~1`), is refused, and fix diffs may no
  longer touch `.gitmodules`
- PR comments escape HTML, Markdown links and images, `@` mentions, `#` refs
  and bare URLs in package names, versions, paths and snippets from the
  lockfile, keep code spans on one line, and cap each field at 200 characters
- `penthera evidence verify` no longer passes a signed bundle whose signer was
  not checked: a signature only verifies against `--allowed-signers`, and a
  manifest that declares a signature with no `.sig` fails. Unsigned bundles
  pass with an UNSIGNED warning; new `--require-signature` fails them
- `penthera install` refuses git, hosted-git and tarball-URL specs, and lockfile
  entries resolved outside the configured registries, unless
  `--allow-non-registry` is passed. `npm cache add` runs with `--ignore-scripts`
- `penthera install` applies with `npm ci`, so npm installs exactly the
  reviewed lockfile and cannot re-resolve before scripts run
- `penthera deps` now honours `--audience`, `--report-template`, `--evidence`
  (with `--sign-key`) and `--baseline`, and rejects scan-only flags such as
  `--memory` with a clear error instead of ignoring them
- Gzip and tar size limits are enforced while unpacking (`maxOutputLength` on
  gunzip, per-file and total caps in the tar reader)
- The pre-commit hook reads `penthera.policy.json` and `penthera.suppress.json`
  from the git index, warns when an unstaged copy is being ignored, and never
  follows a staged symlink in agent config out of the repo
- `--base` refs are validated (no leading `-`, a plain ref charset) and passed
  after `--end-of-options`, in `penthera deps` and in the GitHub Action's fetch
- `git status` and friends on a scanned repo (fix apply, evidence bundle git
  info, `--base` reads) run with `core.fsmonitor=false`, no hooks and no
  transports
- The Action only edits marker comments posted by `github-actions[bot]`
- `--offline` no longer makes DNS TXT/MX lookups for SPF/DMARC
- Report citations now cover `dependency-risk`, `license`, `agent-config` and
  the machine-audit categories; `license` findings get their own remediation
- Docs: `docs/plan.md` lists only what v1.5.0 shipped; top-level `--help`
  lists `penthera hook`

### Added

- **Signed rule packs** (`lib/rules/`, [docs/rule-packs.md](docs/rule-packs.md)):
  detection data (secret formats, hidden-instruction and exec patterns, IOC
  lists, typosquat targets, Nuclei-compatible templates) ships as versioned
  directories. Each pack has a `pack.json` index of SHA-256 hashes, signed
  with `ssh-keygen -Y sign -n penthera-rules`. Penthera verifies the signature
  (in Node; ssh-keygen is not needed at run time), then every hash, the schema
  and every regex, before it loads anything. Packs arrive bundled in a release,
  or by path with `--rules <dir>` (plus `--rules-signers <file>` for your own
  keys). Unsigned packs are refused unless `--allow-unsigned-rules`, which
  warns loudly. Nothing is ever fetched
- `penthera rules list` and `penthera rules verify <dir>`; tooling in
  `scripts/rules/` (`build-pack.mjs`, maintainer-only `sign-pack.sh`,
  `check-bundled.mjs`). The publish workflow now refuses to stage a release
  whose bundled packs are not signed by a key in `lib/rules/allowed_signers`
- ReDoS guard for data-supplied regexes (`lib/rules/regex-guard.js`): length
  cap, no backreferences or lookaround, no nested quantifiers, no alternation
  under unbounded repeats, no unbounded quantifier that every start position
  can rescan, and a backtracking budget for overlapping quantifier chains.
  Fuzz-tested: everything it accepts runs in milliseconds on adversarial
  input. The v1.1.1 template guard moved here too, rewritten from a regex
  (itself polynomial on hostile pattern strings, flagged by CodeQL) into a
  linear scan that also catches deeper nesting
- Bundled `core` pack: 12 AI-provider key formats, the credential-path
  instruction pattern, two exec patterns and the `.env` template moved out of
  code. Behaviour is identical; a test compares against a snapshot of the old
  built-ins
- Bundled `ioc-2025-2026` pack (**unsigned in this PR; the maintainer signs it
  before release**): s1ngularity/nx versions (GHSA-cxm3-wv7p-598c), Shai-Hulud
  (StepSecurity's list, exfil URL, `bundle.js` by hash), Shai-Hulud 2.0 (Wiz
  Research's CSV, loader file names) and postmark-mcp 1.0.16 to 1.0.18 with its
  exfil domain. `penthera deps` reports hits as critical `deps-ioc` findings
  that cite the source, wherever the package sits in the tree, installed or not
- **Internal testing audit** (`npm run audit:internal`), the release gate:
  tests, benchmark drift, a self-scan against `audit/baseline.json`, a CLI
  smoke matrix, package contents and size, zero third-party egress offline,
  supply chain and version/docs checks, written to `audit/REPORT.md`. Runs
  weekly in CI. See [docs/internal-audit.md](docs/internal-audit.md)
- **Marketing automation that drafts, never posts** (`docs/marketing.md`): no
  social-media tokens, no tracking, no auto-posting; every workflow SHA-pinned
  with least-privilege permissions and a `workflow_dispatch` dry run
  - Release post drafts: `publish.yml` writes a LinkedIn (~600 characters) and
    an X/Bluesky (≤280) post from the CHANGELOG section to the job summary and
    a collapsed "Share this release" section in the GitHub Release
    (`scripts/marketing/release-post.mjs`)
  - Incident radar (`incident-radar.yml`, daily): new npm and PyPI malware
    advisories from the public GitHub Advisory Database become
    `incident-radar` issues with affected versions, an IOC checklist and a
    draft "check if you're affected" post. Popular packages get their own
    issue (at most 5 per run); the rest are batched into one issue
  - Demo media (`demo-media.yml`): VHS tapes in `assets/tapes/` for a URL
    scan, `penthera agents` and `penthera deps --diff`, re-rendered on release
    and opened as a PR
  - Monthly stats issue (`monthly-stats.yml`): npm downloads, stars, forks,
    skills.sh installs, dependents and merged PRs, with month-over-month
    changes and a draft post
  - Contributor flywheel (`contributor-flywheel.yml`): when fewer than 3
    `good first issue` issues are open, one reminder lists the
    `TODO(good-first-issue)` markers in the code
- **Report footer**: Markdown reports, audience reports, the PR comment and
  the evidence bundle end with one line, "Checked by Penthera, open-source
  security for the apps and AI systems you ship". Never in SARIF or JSON.
  `--no-footer` (or `footer: "false"` in the Action) leaves it off. Evidence
  bundles now include a `README.md`
- **Python support for `penthera deps`** (`lib/deps/python/`): reads `uv.lock`,
  `poetry.lock`, `pdm.lock`, `Pipfile.lock` and `requirements*.txt` (pinned and
  `--hash` lines, `-r` includes, pip-compile `# via` for direct deps), and the
  installed `.venv` / `venv` / `--venv <path>` through `dist-info` `METADATA`
  and `RECORD`, with no pip or interpreter. A Python tokenizer blanks comments
  and docstrings; patterns cover shell, network, env bulk access and
  exfiltration, eval/exec/compile, computed imports, unpickling, native
  extensions, obfuscation (`exec` of base64/zlib payloads, encoded blobs,
  PyArmor) and the same AI-agent indicators as npm. Install-time and
  persistence code: `setup.py` custom commands, `.pth` import lines (scored by
  what the imported module can do), `.pth` files no distribution owns, code that
  writes `.pth` files, and installed files that no longer match `RECORD`. Same
  capability ids, findings, diff, PR comment and SARIF as npm; projects with
  both get one combined report
- `--diff` / `--base` for Python lockfiles. Old versions come from pip's HTTP
  cache (sha256 from the lockfile) or uv's cache (recorded hash), else they are
  marked "not compared"
- PyPI typosquat check against a vendored list of the top 8,000 PyPI projects
  (`lib/deps/popular-pypi.json`, PEP 503 normalised, refreshed at release time by
  `scripts/refresh-popular-pypi.mjs`), including `python-` / `-py` affixes

### Changed

- The live test suites (`pentest-live`, `-recon`, `-adaptive`) are opt-in:
  they run only with `PENTEST_BASE_URL` or a `pentest.config.js`, instead of
  probing whatever listens on `localhost:3000` during `npm test`.

### Fixed

- Repo scans skip nested git repositories and worktrees (any subfolder with
  its own `.git`, such as coding-agent worktrees under `.claude/worktrees`),
  instead of reporting their files as this repo's, and no longer follow
  symlinked folders out of the repo.
- The secret scanner no longer reports a value that is only a template
  placeholder (`apiKey: "${key}"`, `{{ api_key }}`) as a hardcoded secret.
- `penthera-scan --help` and `--version` exit 0 instead of starting the wizard.
- The example workflows in `docs/examples/` pin actions by commit SHA.

### Docs

- README cut from about 45 KB to under 20 KB. It opens with a three-command
  "Try it in 60 seconds" block, a "Who it is for" table, and a "By the
  numbers" block (benchmark, rule and test counts, references, release
  provenance). Per-command detail moved to `docs/commands/` and network use to
  `docs/privacy.md`.
- Use-case pages in `docs/use-cases/`: before launch, teams adopting coding
  agents, open-source maintainers, EU SMEs with NIS2 or CRA duties, agencies.
- Comparison pages in `docs/compare/` for Socket, Snyk, GitHub Dependabot and
  code scanning, OWASP ZAP and Semgrep, framed as using the tools together, with
  sources and a last-checked date.
- `docs/research/socket-positioning-notes.md`: how Socket presents itself and
  what Penthera's docs took from it.
- `npm run docs:numbers` prints the counts quoted in the README.

## [1.5.0] - 2026-10-19

Blocks problems at commit time, adds license policy, and extends the EU
evidence to the Cyber Resilience Act. The GitHub Action is now ready for the
Marketplace as "Penthera Security Review". Penthera also has a clearer
problem statement: open-source security for the apps and AI systems you ship.

### Docs

- Problem statement: "open-source security for the apps and AI systems you
  ship", organised around three moments (before you deploy, what you build
  with, after you ship). README, package, plugin, skill and repository
  descriptions updated. Roadmap gains v1.6.0 "Before you deploy" (preview
  deployment scanning, `penthera ship`) and v1.7.0 "After you ship"
  (`penthera watch`). New `docs/plan.md` sets measurable quality gates to v2.0.

### Added

- **`penthera hook install|uninstall|run`**: a pre-commit hook that checks
  staged content only (the git index): secrets and AI provider keys, the
  `penthera agents` rules on staged `.mcp.json`, `CLAUDE.md`, `AGENTS.md`,
  `.cursor/`, `.claude/` and `skills/`, and, when `package-lock.json` is staged,
  the capability diff against HEAD plus the license policy for the packages the
  commit adds. Blocks on high and critical by default; one line per finding with
  a fix hint and a `penthera.suppress.json` id. An existing hook is kept as
  `pre-commit.pre-penthera`, runs first, and is restored by `uninstall`. Refuses
  to write into a `core.hooksPath` managed by husky or lefthook without `--force`.
  `.pre-commit-hooks.yaml` for pre-commit.com. Configured by a new `hook`
  section in `penthera.policy.json` (`blockOn`, `checks`, `ignore`)
- **License policy**: `penthera deps --license-policy <preset|file>` and a
  `licenses` section in `penthera.policy.json` (`preset`, `allow`, `deny`,
  `allowPackages`, `unknown`). Presets `permissive`, `weak-copyleft-ok` and
  `no-agpl`. A small SPDX expression parser handles `AND`/`OR`/`WITH`,
  parentheses, `+` and `LicenseRef-`, and matches deprecated ids (`GPL-3.0`) to
  their current form. Breaches and `UNLICENSED` are high; missing, custom and
  non-SPDX licenses are medium. Findings use category `license`; the SPDX id
  list is vendored (`lib/deps/spdx.json`). CycloneDX SBOM components now carry
  their license
- **CRA Article 14 reporting helper** (`penthera --cra-init cra.json`,
  `penthera --cra cra.json`, `lib/compliance/cra.js`): for an actively exploited
  vulnerability (24h early warning, 72h notification, final report 14 days after
  a fix is available) or a severe incident (24h, 72h, final report one month
  after the notification). Computes due dates in UTC and local time (hours
  elapsed, days and months on the calendar, DST-safe), flags overdue and late
  reports, drafts each report against Art. 14(2)/(4) with `NEEDS INPUT` for
  missing facts, adds an Art. 14(8) user advisory, and can prefill the affected
  component, purl and CVEs from a Penthera SBOM and scan JSON. NL profile names
  NCSC-NL and the ENISA Single Reporting Platform. Drafts, not the official
  form, not legal advice. Guide: `docs/compliance-cra.md`
- **CycloneDX 1.6 AI-BOM** (`penthera --repo . --aibom aibom.cdx.json`,
  `lib/whitebox/aibom.js`): AI SDK dependencies, model identifiers in code as
  `machine-learning-model` components with `modelCard` and file:line evidence,
  MCP servers as `services`, and Agent Skills and prompt files as hashed `data`
  components. Offline. Tests validate the output against the official
  CycloneDX 1.6 schema, vendored in `tests/fixtures/cyclonedx/` (new dev
  dependency: `ajv`)

## [1.4.0] - 2026-10-19

The biggest release so far, covering the v1.3.0 "AI toolchain" and v1.4.0
"Local loop" milestones together. Penthera now does the routine work of a small
security team on your own machine:
- tests your app;
- vets and guards your dependencies;
- audits your AI tooling;
- fixes what it finds on a local branch and verifies each fix;
- writes reports and evidence for auditors.

It still runs offline, with no telemetry. The first outside contribution, from
@Nurana100, is in this release.

Requires Node 22+. Upgrading from 1.1.x or 1.2.x needs no config changes.

### Added

- **`penthera ui [--open] [--port 0] [--project <dir>] [--reports <dir>] [--demo]`**:
  a local dashboard on 127.0.0.1 (random port, one-time URL), styled as a
  1-bit early-90s Mac desktop with a terminal inside, in dark and light themes.
  Overview (posture per project, severity mix, findings over time, time to
  fix, hosts contacted; a three-step start when there is no data yet),
  Findings (filters, a plain-words explanation, evidence, sources, fix diff),
  Run (scan, check dependencies, audit AI tooling, or the fix loop with an
  Apply / Skip / Stop dialog on every diff, live output over SSE), History
  (new, fixed and still open between two scans), Dependencies, AI tooling,
  Evidence (create a bundle from the latest scan, verify in one click,
  download the auditor report) and Settings. Reads only the chosen folders and
  `~/.penthera`; no network, no new dependencies, no build step. Host check
  against DNS rebinding, one-time token swapped for an HttpOnly SameSite=Strict
  cookie, Origin check and JSON-only bodies on state changes, strict CSP, no
  CORS, rate-limited unauthenticated requests, allowlisted static files.
  Penthera scans it clean. `--demo` seeds fake data. See `docs/dashboard.md`
- **GitHub Action** (`uses: danoszz/penthera@<sha>`, `action.yml`): on PRs that
  change the lockfile it runs `penthera deps --base <PR base>`, upserts one PR
  comment marked `<!-- penthera-deps -->` (edited in place on every push), and
  uploads SARIF. Runs from the action's own checkout with no npx or npm install.
  Fork PRs get the diff in the job summary. Also `mode: agents` and `mode: scan`,
  plus `fail-on`. Example: `docs/examples/pr-dependency-review.yml`
- **`penthera agents [path] [--home] [--pin]`**: an offline, deterministic audit
  of AI developer tooling. It finds and parses `.mcp.json`, `.cursor/`,
  `.claude/`, `.vscode/mcp.json`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
  `.github/copilot-instructions.md` and skill folders; with `--home` also
  `~/.claude` (settings, hooks, permissions, plugins, skills), `~/.claude.json`,
  `~/.cursor/mcp.json` and the Claude Desktop config. Read-only, no network, no
  LLM judge
- Hidden-content engine (`lib/agents/hidden-content.js`): Unicode tag
  characters (decoded), zero-width and bidi controls, variation-selector
  smuggling, whitespace inflation, instructions in HTML comments, text aimed at
  a scanner, base64 blobs (decoded and classified), binaries and archives in
  skill folders by magic bytes, symlinks that leave a skill, and `curl | sh` /
  `eval` style remote execution
- Risky-config rules: unpinned `npx -y` / `uvx` / `bunx` / `pnpm dlx` MCP
  servers, inline secrets in server env/headers/args (via `findSecretsInText()`),
  plain-HTTP remote servers, hooks that auto-approve or pipe to a shell,
  `Bash(*)` and other wildcard permissions, `bypassPermissions`, credential-file
  allows, wildcard `allowed-tools`, and unpinned plugin marketplaces
- `penthera.lock`: `--pin` records SHA-256 hashes of every skill folder, MCP
  server definition, hook and installed plugin; later runs report changed (rug
  pull), new and removed entries
- A–F grade for the agent setup in the terminal and Markdown reports. Findings
  use category `agent-config`, map to OWASP MCP Top 10 and Agentic (ASI) ids,
  and get per-rule SARIF ids (`agents/<rule>`)
- Agent Skill: Workflow 6 ("audit my MCP servers / skills / agent config")
- `docs/METHODOLOGY.md`: threat model, what black-box and white-box scanning
  can and cannot find, the confidence model, false-positive controls, the
  non-destructive default, offline operation, and how new attack techniques
  are adopted (reviewed rules in releases, never fetched at run time). Design
  choices cite published research and standards
- `docs/references.bib` and `docs/references.md`: 48 references, each checked
  against the publisher or standards body, grouped by topic
- Per-finding citations: `lib/references.json` maps each finding category to
  1-3 references. The Markdown report adds a "Why this matters / Sources" line
  per finding and a "Sources" line per action-plan item; SARIF rules get
  `helpUri`, `help` and `properties.references`
- Accuracy benchmark: `npm run bench` scans the mock server, two new local lab
  targets (vulnerable and decoy) and a generated repo fixture, scores precision
  and recall against `bench/ground-truth.json`, and writes `bench/RESULTS.md`.
  Offline and seeded; `npm test` fails if it drops below the CI floor.
  Optional Juice Shop and crAPI targets are documented
- `CITATION.cff`, so GitHub shows "Cite this repository"
- **`penthera deps [path]`**: offline, deterministic dependency risk scanning
  for npm. Reads `package-lock.json` (v1-v3), statically scans every installed
  package and reports what it can do, with `file:line` evidence: install
  scripts (including implicit `node-gyp`), shell, network, writes outside its
  folder, environment reads and bulk access, `eval` / `new Function` / `vm`,
  computed `require`/`import`, native binaries, and obfuscation signals
- **Capability diff** (`--diff <lockfile|dir>`, `--base <git-ref>`): packages
  that are new or that gained capabilities in an upgrade. Old versions come
  from the base tree or npm's local content cache, verified against the
  lockfile integrity, so the diff works offline
- Attack indicators: writes to `~/.claude`, `~/.cursor`, `.mcp.json` or the
  Claude Desktop config, running the `claude` / `gemini` / `q` CLIs (the
  s1ngularity pattern), GitHub token harvesting, and the whole environment
  serialised next to network code
- Typosquat / slopsquat check against a vendored list of ~7,800 popular npm
  names (`lib/deps/popular-packages.json`, from npm-high-impact), refreshed at
  release time by `npm run refresh:popular`. Nothing is fetched at runtime
- `--online` (off by default, the only network use): npm registry metadata for
  fresh versions, brand-new packages, publisher changes and deprecations
- `--pr-comment <file>` and an example workflow
  ([`docs/examples/github-actions-deps.yml`](docs/examples/github-actions-deps.yml))
  that comments the capability diff on PRs that change the lockfile
- Findings use category `dependency-risk` and source `deps-scan`; SARIF
  results now carry a start line when a finding has one
- **`penthera install [pkg...]`**: an install firewall on the `deps` engine.
  npm resolves the new tree in a temporary copy with scripts off
  (`--package-lock-only --ignore-scripts`), new tarballs are fetched with
  `npm cache add` and read back only after an integrity check, and the
  capability diff, new install scripts (with their commands) and typosquats
  are shown before anything in the project changes. `penthera.policy.json`
  (`allow` names/globs, `deny` and `requireApproval` capabilities) decides;
  by default new install scripts, AI-config writes, AI CLI invocation, token
  harvesting, obfuscation, typosquats and unreadable packages need approval.
  Interactive by default, `--yes` for CI (installs only when nothing breaches
  the policy), `--dry-run` to report. On approval the reviewed lockfile is
  installed as is, with `--ignore-scripts` unless the scripts were approved
  (on npm 12+, approved scripts are pinned in `package.json` `allowScripts`).
  An abort leaves the project byte for byte unchanged. npm's registry traffic
  is the only egress, and it is printed
- `scanDeps()` accepts `treeRoot` and a list of cache dirs; the diff output
  carries each changed package's install scripts
- **Fix recipes** (`lib/fix/`, `penthera fix`): deterministic, local fixes for
  common findings, printed as unified diffs. `penthera fix --plan` plans fixes
  for a fresh repo scan or an earlier `-o` report; `penthera fix --apply <id>`
  applies one after a y/N prompt (or `--yes`), then re-scans to verify. Recipes:
  security headers (Next.js, Express, Fastify, Hono), cookie flags, CORS
  wildcard to an allowlist from `CORS_ALLOWED_ORIGINS`, a rate-limit stub on
  login/auth routes, and a hardcoded secret moved to an env var with
  `.env.example` updated (always with the owner action to rotate it)
- `applyDiff()` refuses paths outside the repo (symlinks included), `.git`,
  and dirty or non-git trees unless `--allow-dirty`, and writes nothing unless
  every hunk applies. Planning never writes; nothing is committed or pushed
- Recipes edit only at exact anchors and return no plan when the anchor is
  missing, instead of a risky diff
- Optional `--fix-model <name>` fallback for findings no recipe matches. It
  talks only to Ollama on `127.0.0.1:11434`, is off by default, and labels its
  output `confidence: "needs-human-review"`, `source: "local-model"`
- Fixtures for Next.js, Express, Fastify and Hono under `tests/fixtures/fix/`
- `detectFramework()` is now exported from `lib/whitebox/frameworks.js`
- **Audience reports** (`--audience developer|owner|auditor`): developer gets
  findings with file:line, fix recipe ids or diffs, and sources; owner gets a
  plain-language summary, what to do first, owner actions and the trend from
  memory; auditor gets scope and method (linking `docs/METHODOLOGY.md`),
  confidence labels with provenance per finding, egress and inconclusive
  probes, suppressions with who and why, and NIS2 and OWASP mapping tables.
  The default report is unchanged
- **User templates** (`--report-template file.md`): `{{a.b}}`,
  `{{#each}}`, `{{#if}}`/`{{else}}`, nothing else. Values are HTML- and
  Markdown-escaped; no helpers, code, includes or prototype access. Written from
  scratch (`src/report/template.js`) and fuzz-tested against injection
- **Fix timeline** in the audience reports: found → fixed → verified with time
  to fix, from an agent loop run (`loopRun`) or memory fix events
  (`lib/memory/history.js`, also the owner report's trend)
- **Evidence bundle** (`--evidence <dir>`, `--sign-key <ssh-key>`): JSON,
  Markdown, SARIF, the three audience reports, a custom template report, the
  readiness report and SBOM when requested, and `manifest.json` (tool version,
  command line with secrets redacted, timestamp, target, git commit, SHA-256 of
  every file). Signing uses `ssh-keygen -Y sign -n penthera-evidence`; no new
  dependency. `penthera evidence verify <dir> [--allowed-signers <file>]`
  recomputes every hash, rejects changed, missing, extra and symlinked files,
  and checks the signature. See `docs/evidence.md`
- **`penthera agent --loop`** (`src/agent/`): the local scan → triage → plan →
  patch → verify → learn loop. Fixes are applied one at a time on a local
  branch `penthera/fix-<yyyymmdd-hhmm>`, verified by a re-scan (and the
  project's tests with `--run-tests`), committed when verified and reverted
  when not. Every diff needs `y/n/skip/quit` approval; `--auto low` auto-applies
  only recipes memory shows verified 3+ times with no failures on the
  framework. Stops when nothing fixable is left or at `--max-iterations`
  (default 5). `-o` writes a `loopRun` JSON (iterations, fixes, time per step),
  also appended to memory as a new `loop_run` event
- The loop runs git only through an allow-list of local subcommands with
  `protocol.allow=never`, no lazy fetch and the repo's hooks disabled; it never
  pushes, fetches or opens pull requests. Scans run in one offline egress
  context (the `--url` host only; Ollama on 127.0.0.1 only with
  `--fix-model`). It refuses a dirty tree or detached HEAD unless
  `--allow-dirty`, and Ctrl-C leaves only verified commits on the fix branch

### Docs

- Sharper positioning: "the routine work of a security team, on your own
  machine". The README now opens with what Penthera does for you, why you can
  trust it, and a factual table of how it fits next to Socket, Snyk, GitHub,
  OWASP ZAP and Anthropic's OSS Scanner. The package, plugin, skill and
  repository descriptions match.
- Funding and partnership drafts under `docs/funding/`: an NLnet application
  draft, GitHub Sponsors tiers, a partner brief, and a due diligence checklist.
- CONTRIBUTING: commits are signed off under the Developer Certificate of Origin.
- **`--offline`**: the scan contacts only the target. Recon is skipped, the
  Retire.js check uses the vendored database snapshot, and every other host is
  refused by the HTTP client (redirects may stay within the target's
  registrable domain). Groundwork for the local agent loop.
- **Vendored Retire.js database** (`lib/data/retire-jsrepository.json.gz`,
  72 KB gzipped) with source URL, date and SHA-256 in a meta file.
  `npm run refresh:retire-db` updates it at release time, and
  `npm run refresh:retire-db -- --check` reports drift from upstream. Online
  scans fall back to it when the live download fails.
- **Third-party egress report**: every scan lists the hosts it contacted
  besides the target, in the terminal summary and in a "Network egress" section
  of the Markdown report (`result.egress` in JSON).
- **`--user-agent <ua>`** to override the new default User-Agent.

### Changed

- Every request now sends `User-Agent: penthera/<version>
  (+https://github.com/danoszz/penthera)` instead of Node's default (#7;
  first added by @Nurana100 in #20, our first outside contribution).
- Probe failures (timeouts, connection errors, refused hosts) are recorded as
  `result.errors[]` (`{ probe, url, message, count }`). The terminal summary
  shows "N probes inconclusive", and the Markdown report lists them under
  "Inconclusive probes" (#8).
- All network calls go through one client in `src/utils/http.js`, which owns
  timeouts, the User-Agent and egress policy. The per-module fetch wrappers in
  the crawler, injection, fuzzer, template, recon, parameter, Retire.js and
  adaptive-probe modules are gone.
- **Local learning store** (`lib/memory/`), the memory behind the v1.4 local
  loop. `--memory` records each scan under `~/.penthera/memory/<project-id>/`
  (or `PENTHERA_HOME`) as an append-only, hash-chained event log, then uses it
  to suppress findings marked as false positives and to rank findings within a
  severity. Suppressed findings are listed in their own section with who
  suppressed them and why. Memory is never read from the scanned repo and
  nothing in it is ever executed; a broken chain means memory is not applied.
  See [docs/local-loop.md](docs/local-loop.md) for the threat model
- `penthera memory show | verify | forget [--all] | suppress <id> --reason <text>`
- Optional repo file `penthera.suppress.json` for shared suppressions. Every
  finding it hides is labelled "suppressed by repo file" with its reason

## [1.2.0] - 2026-10-19

The first step toward securing the AI toolchain itself: catch AI provider keys,
harden Penthera's own supply chain, and make CI test what it says it tests. The
[roadmap](ROADMAP.md) now sets out the AI supply-chain and local agent-loop
tracks.

### Added

- **AI provider key detection** in repo scans: Anthropic, OpenAI project and
  service-account keys, OpenRouter, Google (Gemini / Firebase), Groq, Hugging
  Face, Replicate, xAI, Perplexity, LangSmith, and Pinecone. Jupyter notebooks
  (`.ipynb`) are now scanned too. A provider key inside an `api_key = "..."`
  assignment is reported once, under its provider, instead of twice
- `findSecretsInText()` exported from `lib/whitebox/secrets.js`, so the same
  rules can run on any text (groundwork for scanning JS bundles)
- CodeQL and OpenSSF Scorecard workflows, Dependabot for npm and GitHub Actions
  (with a 7-day cooldown before adopting new releases)
- CI check that `package.json`, the lockfile, the skill, and both plugin
  manifests carry the same version
- Roadmap: AI supply-chain audit (`penthera agents`), a fully local
  scan → fix → verify → learn loop, and LLM-endpoint probes. Principles now
  state no telemetry, no auto-push, and no remote learning

### Fixed

- **Modern OpenAI keys were missed.** The old pattern stopped at the hyphen in
  `sk-proj-...` and `sk-svcacct-...`, so the key format OpenAI has issued since
  2024 never matched
- The example scan workflow lived in `.github/workflows/`, so it ran on its
  weekly cron and failed every Monday. It moved to
  `docs/examples/github-actions-scan.yml` and now uses `npx penthera@<version>`,
  so it works when copied into your own repo
- CI ran only 4 of 24 test files; it now runs the full `npm test`
- Removed `tests/pentest-static.test.js`, which tested functions defined inside
  the test file rather than anything Penthera ships
- `.claude-plugin/plugin.json` still said 1.0.0
- `SECURITY.md` listed 1.0.x as supported. It now covers 1.2.x and gives response
  times, scope, and safe-harbor terms

### Changed

- **Node.js 22 or newer is now required.** Node 18 and 20 are end-of-life, and
  the test toolchain (vitest 5) needs 22. CI runs on Node 22 and 24
- GitHub Actions are pinned to commit SHAs, and every workflow declares
  least-privilege `permissions`
- Releases use npm trusted publishing (OIDC, no stored token) and **staged
  publishing**: CI stages each version, and it only goes live after a
  maintainer approves it with 2FA. The workflow also creates the GitHub Release
- The Docker image runs as the unprivileged `node` user on `node:22-alpine`
- README reordered so install and quick start come before compliance. The full
  NIS2 guide moved to [`docs/compliance-nis2.md`](docs/compliance-nis2.md)
- vitest 3 → 5 (clears 8 dev-only advisories), yaml 2.8 → 2.9

## [1.1.1] - 2026-08-16

A correctness release. One of these was a live outage: if you are on 1.1.0,
upgrade.

### Fixed

- **JS dependency scanning was silently dead.** The Retire.js vulnerability
  database URL pointed at a fork that now returns 404, so every scan reported
  "no vulnerable JS libraries" without ever running the check. It now reads from
  upstream RetireJS with a mirror, validates the payload, and when no source is
  reachable it says the check did not run instead of returning a clean result.
  The probe is also excluded from coverage in that case, so a compliance report
  cannot claim supply-chain evidence that was never collected
- **Command injection in the machine audit.** Binary paths read from
  attacker-writable plists were interpolated into a shell string, so a malicious
  persistence entry could execute code inside the scanner. Paths are now argv
  entries and signature checks use the exit status, failing closed
- Two built-in templates fired on any single-page app with catch-all routing:
  the `.env.local` matcher accepted a bare `=` (present in every HTML attribute)
  and the Firebase one accepted any 200 without the word "error", so an
  `index.html` served at those paths was reported as critical
- Time-based SQL and command injection no longer report on a single slow
  response. A candidate delay is re-sampled and only reported when the median
  holds, which a garbage-collection pause or cold start does not survive
- Community template regexes ran unbounded against whole response bodies. A
  catastrophically-backtracking pattern would hang the scanner; patterns with
  nested quantifiers are now refused and input is capped
- Dedupe and baseline comparison used different keys that included severity, so
  re-rating a finding reported it as one resolved plus one new. Both now share
  the audit loop's fingerprint
- A measure with nothing scanned and nothing attested was scored as a gap,
  telling an entity that had not yet filled in the self-assessment that it had
  failed. That state is now reported as not assessed
- The XSS canary was a fixed, fingerprintable string; it is now randomised per
  probe
- XProtect staleness was computed and discarded; it is now reported

### Changed

- The Nuclei loader documents the subset it actually implements and reports per
  template which unsupported features it needs, instead of letting a template
  that cannot match look like a clean pass
- Provenance (confidence, method, collection time) now travels into SARIF, and
  the terminal marks findings a scanner cannot adjudicate

## [1.1.0] - 2026-08-16

NIS2 / Cyberbeveiligingswet readiness work: a hardening pass over the
open-source core, a full offline NIS2 readiness toolkit, and a humanizing pass
that removed AI-writing tells (em dashes and so on) from all public-facing text
and generated documents.

### Added

- **Customer security-questionnaire answerer** (`--questionnaire <file>`): reads a
  questionnaire (one question per line) and drafts an answer for each from the
  readiness evidence, citing the Article 21 measure and what backs it (scan
  probe or attestation). Anything it can't map is marked NEEDS HUMAN INPUT
  rather than guessed. Writes `questionnaire-response.md`
- **Attack chains surfaced in reports**: the adaptive engine's knowledge graph
  already correlated findings (for example an auth bypass that combines with an
  IDOR into cross-user access) but the result was computed nowhere. Chains now
  appear as findings with their path
- **Provenance + honest confidence on every finding**: each finding carries
  `{ source, method, collected_at, confidence }`, with confidence labelled
  `confirmed` / `likely` / `potential` / `needs-human-review` so a heuristic
  isn't presented as a certainty. Shown in the report's Confidence column and in
  JSON (`lib/provenance.js`)
- **Supplier passive rating** (`--suppliers <file>`): point Penthera's passive
  checks (homepage security headers, TLS certificate, SPF/DMARC/MX via DNS) at
  your own suppliers' public domains and get a red/amber/green posture per
  supplier, supply-chain risk screening (measure d). Strictly passive,
  public-data-only, non-intrusive, and documented as such; not a pentest of the
  supplier
- **Remediation / audit-loop tracking** (`--history <file>`): folds each scan's
  findings into a persistent history keyed by a stable fingerprint (severity-
  and count-independent), and reports open vs resolved, median time-to-fix,
  ageing buckets, and drift since last scan, the effectiveness evidence for
  measure f, and a "close the loop" counter to noisy discovery-only scanning
- **SBOM output** (`--sbom <file>`): generates a CycloneDX 1.5 software bill of
  materials from `package-lock.json` / `package.json` / `requirements.txt`,
  offline, with resolved versions and purls. Supply-chain evidence (measure d)
  and the artifact enterprises increasingly require of suppliers
- **Incident-report helper** (`--incident <file>`, `--incident-init` to scaffold):
  computes the NIS2 reporting deadlines (24h early warning / 72h notification /
  1-month final report) from when you became aware, flags overdue ones, and
  drafts each report against the jurisdiction's required content, with
  `NEEDS INPUT` markers for facts you still have to supply. Offline; drafts to
  help meet the deadlines, not a substitute for the authority's official form
- **Policy-pack generator** (`--policy-pack <dir>`): writes proportionate,
  editable Markdown starting points for the core policies NIS2 expects
  (information security, access control, incident response, backup/continuity,
  acceptable use, supplier security, vulnerability management). Pre-filled from
  the jurisdiction's incident deadlines and the readiness gaps; clearly labelled
  as templates, not legal advice
- **NIS2 readiness report** (`--readiness`): combines scan evidence with an
  offline **self-assessment** (`--assessment-init` to scaffold, `--assessment` to
  supply) into a per-measure `met / partial / gap / n-a` report across all ten
  Article 21 measures, with proportionality notes, the jurisdiction's
  incident-reporting deadlines, and **provenance** (`source, method, collected_at,
  confidence`) on every piece of evidence. Writes `<output>-readiness.md`. Works
  offline; jurisdiction data is config (`lib/jurisdictions/nl.json`, NL today)
- Remediation action plan: the report (terminal-adjacent Markdown + JSON
  `actionPlan`) now includes a prioritised, owner-actionable plan, what, why,
  how to fix, rough effort, and whether it's a code change or an owner action
  (rotate a secret, renew a cert, change DNS), replacing the old generic
  recommendations list. Built from a remediation knowledge base (`lib/remediation`)
- Agent Skill Workflow 5 + `references/reporting.md`: generate owner-facing
  documents from a scan, a remediation plan, a prefilled security-questionnaire
  response, and a NIS2 duty-of-care evidence summary, grounded in scan evidence,
  with unbacked/organisational items marked `NEEDS HUMAN INPUT` (never fabricated)
- Email authentication probe (SPF, DMARC, MX via DNS), new `lib/blackbox/email-dns.js`,
  runs in the standard profile for public domains. Flags missing/permissive SPF,
  missing or monitoring-only (`p=none`) DMARC, and nudges DKIM verification. A
  questionnaire staple that was previously uncovered
- `--framework nis2` compliance report mode: a per-scan NIS2 Article 21 coverage
  table (which measures this scan actually exercised, driven by the probes that
  ran) added to the terminal, Markdown, and JSON reports. Frameworks are
  declarative so national transpositions and other regimes can be added as data
- NIS2 / cyberwetgeving compliance section in the README: Article 21(2)(a-j)
  mapped to what Penthera actually tests, with a coverage key and a clear
  "not legal advice / not a certification" disclaimer
- Code of Conduct (Contributor Covenant 2.1), issue templates, and PR template
- `tests/detection-hardening.test.js` covering the secret-scan and SSTI fixes

### Fixed

- Interactive onboarding now attaches the remediation action plan to its report,
  matching the main CLI path (the two had drifted)
- Audit-loop fingerprint no longer merges genuinely distinct findings. Collapsing
  every digit run made different ciphers, TLS versions, library versions, API
  versions, and per-CVE findings look like one item, which distorted the
  measure-f numbers. It now collapses only numeric URL path segments and
  separates dependency CVEs by description
- `updateHistory` no longer mutates the history object passed to it
- Jurisdiction data is loaded once instead of re-read per document
- Secret scanner no longer flags dummy/probe credentials (e.g. the
  `invalid-password-12345` payload Penthera flagged on its own repo); rule
  renamed so the title no longer reads "Password in source in source"
- SSTI probe uses a randomized arithmetic canary instead of `7*7=49`, removing
  the critical false positive on any page containing "49"
- Endpoint calibration compares body length to body length (was body vs
  Content-Length), so the noise filter actually filters default/404 pages
- WSTG coverage now reflects the probes that actually ran, instead of asserting
  every profile probe was exercised; dropped two WSTG IDs that were mapped but
  never tested (CRYP-02 padding oracle, CONF-13 path confusion)
- Login "accepts arbitrary credentials" no longer fires on a bare HTTP 200; it
  requires an actual authenticated response (auth cookie or token) for the
  invalid-credential attempt, so SPA logins that return 200 `{success:false}`
  are no longer false-flagged
- Reflected XSS is only reported when the response is served as HTML; JSON/text
  APIs that echo a payload are no longer flagged as XSS
- Removed the fuzzer's prototype-pollution false positive (it fired on any
  object payload returning 200, because `payload.__proto__` is always truthy)
- Open-redirect false positives (found scanning a real Vercel-hosted site): the
  OAuth and injection open-redirect probes now confirm the `Location` actually
  resolves to the attacker's host, instead of substring-matching. A same-site
  apex→www canonicalization that preserves the payload in the query is no longer
  reported as an open redirect. Also removed the redundant, FP-prone
  "open redirect via callback" built-in template
- Login hardening probe no longer runs against a path that returns a redirect
  (3xx), 404, or 405, not a real login handler, removing a false "no login
  rate limiting detected" on redirected paths

### Changed

- Interactive wizard's remote-host permission prompt now defaults to **no**
- README shows the live CI status badge instead of a hand-written test count;
  live integration tests report as skipped (not passed) without a running target
- Corrected the built-in template count (14, not 17) in docs and progress output

## [1.0.0] - 2026-06-30

First production-ready release.

### Added

- PostHog-style interactive onboarding (`penthera` with no args, `penthera-scan`)
- Scan profiles: `quick`, `standard`, `deep`
- Markdown reports with OWASP WSTG coverage section
- Session-aware scanning (`--auth-cookie`, `--auth-bearer`, `PENTHERA_*` env)
- JWT, IDOR/BOLA, OAuth, client-side auth, and security header probes
- Secret scanning and Express/Hono/Fastify route discovery in repo mode
- Baseline diff mode (`--baseline`)
- Adaptive probe engine in CLI (`--adaptive`)
- Plugin/templates API (`--templates`, `lib/plugins.js`, programmatic exports)
- Agent Skill (`skills/penthera/`) with preflight and report validation scripts
- CI scan job with mock server, SARIF upload, and skill validation
- Staging URL workflow (`.github/workflows/scan.yml`)
- Docker image (`Dockerfile`)
- Documentation hub (`docs/index.md`, `docs/owasp-wstg-coverage.md`)

### Fixed

- URL trailing-slash normalization (double-slash 404 bug)

## [0.2.0] - 2026-04

- Markdown reports, scan profiles, auth tooling, expanded API discovery

## [0.1.x] - 2026-04

- Initial CLI: URL, repo, and machine scan modes
- Built-in templates, TLS, CORS, SARIF export

[1.1.1]: https://github.com/danoszz/penthera/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/danoszz/penthera/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/danoszz/penthera/compare/v0.2.0...v1.0.0
