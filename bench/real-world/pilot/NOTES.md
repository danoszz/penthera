# Pilot notes (2026-10-20)

**Pilot, not part of the pre-registered sample.** Ten projects, two per web-app
framework, listed in [corpus.json](corpus.json) and excluded from the E1 frame.
The pilot ran after E1 was registered (merge commit `d8d50c5`). Its purpose is
to show that the pipeline works and to find protocol problems before the frame
is built. The generated report is [RESULTS.md](RESULTS.md); its labels are
**synthetic** (no person has labelled anything yet), so none of its accuracy
numbers mean anything.

## What ran

| Step | Result |
|---|---|
| Fetch | 10/10 cloned at the pinned commit. npm tarballs: 2,569 fetched, 0 failed. Python wheels: 170 fetched for the one project with a hash-pinned root lockfile |
| Scanner | penthera 1.7.0 from npm, `sha512-8CIYspmPPHZVdJpHQFPA9PPFqsz7OtrZcFZoKOgBlYa9RoNDjmy19XVtwvG3PRGQBUwNMpZdEcuXEnC0F6Q9Pw==` |
| Scan | 10/10 repo and agents scans succeeded; `deps` read 4 projects and found no supported lockfile in 6. **0** network connections refused (none attempted) |
| Units | 215 flagged units and 53,566 unflagged candidates; 95 analysis units and 30 calibration units drawn (pilot sizes: 20 unflagged per category, 6 calibration per category) |
| Label, κ, score | Exercised with synthetic labels only |

## Problems found, and proposed amendments to E1

Each needs a decision before the frame is built. Proposed wording goes into
the pre-registration's Amendments section as a dated amendment.

1. **Routes Penthera never discovers cannot count as misses.** In 1.7.0, route
   discovery for Express, Fastify and Hono looks only in fixed top-level
   folders (`routes/`, `src/routes/`, `api/`, …). In the pilot it found **no
   routes in any of the six Express, Fastify, and Hono projects**, which keep
   routes in monorepo paths such as `apps/server/src/`, and it treated one
   project's `app/api` folder as a Next.js route folder. E1 § 5 draws unflagged
   route and code-pattern units from Penthera's own discovered routes, so
   these misses are invisible and recall would be overstated.
   *Proposed amendment:* draw route and code-pattern units from a frame
   independent of Penthera: every non-test source file anywhere in the
   project that registers a route (a documented, framework-specific pattern
   list: `app.get(`, `router.post(`, `new Hono`, `fastify.route(`, Next.js
   `route.ts` exports, FastAPI decorators), and report the share of those files
   Penthera discovered as its own coverage figure.
2. **Dependency coverage depends on the lockfile type.** `penthera deps` 1.7.0
   reads `package-lock.json` and hash-pinned Python lockfiles. Six of ten
   pilot projects use pnpm, Bun or Yarn lockfiles, or keep the Python lockfile
   below the root, and get no dependency units. *Proposed amendment:* report
   the share of projects with a readable lockfile per stratum, and estimate
   dependency precision and recall only on those, stating it as a scope limit
   (we measure the shipped scanner, not a patched one).
3. **Most secret findings are in test, fixture or example files** (93 of 119
   by path). Level 1 ("correct") and level 2 ("actionable") will diverge
   sharply here, as the protocol expects. No change proposed; the codebook
   needs a worked example for a real-looking credential in a test fixture.
4. **The agent-setup stratum is untested.** The pilot had only web apps (the
   agents scanner still ran on them and found units in three). *Proposed
   amendment:* add two agent-setup repositories to the pilot before the frame
   is built.
5. **Labelling time and the base rate of issues in unflagged units are still
   unknown.** Both come from people labelling the pilot queue. Until then, the
   registered 80 unflagged units per category stand.

## Tooling fixes made during the pilot

- **Penthera bug found:** `penthera --json` truncates its output at 64 KB when
  stdout is a pipe and the scan exits with code 1 (`process.exit` before the
  pipe drains). One pilot project's report was cut off. The runner now writes
  stdout to a file. The CLI itself should be fixed in a separate change.
- `npm` 11 refuses one empty file as both user and global config, and prints
  `npm pack --json` as an object, not an array. `fetch.js` handles both.

## Next steps

1. Decide on amendments 1, 2 and 4; merge them as dated amendments.
2. Both labellers label the pilot queue (`label.js --set calibration`, then
   `--set analysis --force`, since the pilot has no gate) to time the work,
   test the codebook, and estimate the unflagged base rate.
3. Then build and freeze the frame.
