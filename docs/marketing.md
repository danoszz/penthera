# Marketing automation

Penthera is maintained by one person with no budget, so the routine parts of
getting the word out run by themselves. The rule is simple: **automation drafts
and collects, a person posts.**

- No social-media API tokens and no auto-posting. Every post is copied and
  pasted by a person.
- No analytics, tracking pixels or telemetry. The numbers come from public
  pages and APIs that anyone can read.
- Every workflow is SHA-pinned and has least-privilege permissions. Workflows
  that write only open issues (`issues: write`). Only the demo-media workflow
  pushes, and only to a `media/*` branch for a PR.
- Nothing can embarrass the project without a person in the loop: drafts land
  in issues, job summaries, a collapsed release section or a PR.

## What runs

| Automation | When | Output | Workflow / script |
|------------|------|--------|-------------------|
| Release post drafts | Every `v*` tag | LinkedIn (~600 chars) and X/Bluesky (≤280) drafts in the job summary and under "Share this release" in the GitHub Release (the read-only publish job drafts; the release job, which has no checkout, only attaches them) | `publish.yml` → `scripts/marketing/release-post.mjs` |
| Incident radar | Daily 06:00 UTC | One issue per new malware advisory for a popular npm package (max 5 per run); every other new advisory as a comment on one standing batch issue | `incident-radar.yml` → `scripts/marketing/incident-radar.mjs` |
| Product-led footer | Every report | One line at the end of Markdown reports, audience reports, the PR comment and the evidence bundle README | `src/report/footer.js` |
| Demo media | Every published release, on demand | A PR with re-rendered GIFs from `assets/tapes/*.tape` | `demo-media.yml` |
| Monthly stats | 1st of the month, 07:00 UTC | Issue "Penthera this month: <Month YYYY>" with a table, month-over-month changes and a draft post | `monthly-stats.yml` → `scripts/marketing/monthly-stats.mjs` |
| Contributor flywheel | When an issue closes | If fewer than 3 `good first issue` issues are open: one reminder issue listing `TODO(good-first-issue)` markers | `contributor-flywheel.yml` → `scripts/marketing/contributor-flywheel.mjs` |

### Release post drafts

Built from the CHANGELOG section for the tag: the first sentence of the
summary paragraph, then three bullets (bold-titled entries first, Added before
Fixed), then the npm and GitHub release links. The X/Bluesky post is counted
the way Bluesky counts (every character), which also fits X. Run it locally:

```bash
node scripts/marketing/release-post.mjs --tag v1.4.0
```

The npm release is staged, not live, until a maintainer approves it. Post after
approving.

### Incident radar

Reads `/advisories?type=malware&ecosystem=npm` and `ecosystem=pip` from the
public GitHub Advisory Database, published in the last 48 hours. About 20
malware advisories appear every day and most are typosquats nobody installs,
so by default only advisories for packages in `lib/deps/popular-packages.json`
get their own issue (with the checklist and a draft "check if you're affected
with one command" post). The rest go into one standing issue, "Incident radar:
other new malware advisories", one comment per run. Set `mode: all` on a manual
run to open one issue per advisory instead (still at most 5).

State is the issues themselves: an advisory counts as seen when its GHSA id is
in an `incident-radar` issue or a radar batch comment from the look-back
window. There is no state file or branch.

Each issue's checklist: add the IOCs to a rule pack in `lib/rules/` (or the
deps rules until rule packs exist), verify `penthera deps` flags a fixture
lockfile with the package, then post. Do not post before detection is
verified.

### Product-led footer

Human-readable Markdown ends with:

> Checked by Penthera, open-source security for the apps and AI systems you ship · https://github.com/danoszz/penthera

It is never added to SARIF or JSON. Users turn it off with `--no-footer` (CLI)
or `footer: "false"` (GitHub Action).

### Demo media

Tapes live in `assets/tapes/` (see its README). The workflow installs
[VHS](https://github.com/charmbracelet/vhs) with `charmbracelet/vhs-action`,
renders every tape, uploads the GIFs as a workflow artifact and, unless it is a
dry run, opens a PR from a `media/*` branch. It needs **Settings → Actions →
General → Allow GitHub Actions to create and approve pull requests**. PRs
opened by `GITHUB_TOKEN` do not trigger CI; close and reopen the PR to run it.

### Monthly stats

Public sources only:

- npm downloads for the calendar month (`api.npmjs.org`);
- stars and forks at run time and PRs merged that month (GitHub API);
- installs from the public skills.sh skill page;
- dependent repositories from GitHub's dependents page.

Each page is parsed strictly: if the markup changed, the number shows as
`n/a`, never a guess. The issue keeps its numbers in a hidden JSON comment,
and next month's issue reads them back for the change column.

### Contributor flywheel

Write `TODO(good-first-issue): <what to do>` in a comment next to a small,
well-scoped change. When the open `good first issue` count drops below 3, the
reminder issue lists these markers with links. Turn one or two into issues,
then close the reminder. Closing the reminder itself never triggers a new one.

## Dry runs

Every scheduled workflow has a `workflow_dispatch` trigger whose `dry-run`
input defaults to **on**: it prints what it would open to the job summary and
writes nothing.

| Workflow | Dry run |
|----------|---------|
| Incident radar | Actions → Incident radar → Run workflow (`dry-run` checked; optional `mode`, `since-hours`) |
| Monthly stats | Actions → Monthly stats → Run workflow (`dry-run` checked; optional `month`, e.g. `2026-09`) |
| Contributor flywheel | Actions → Contributor flywheel → Run workflow (`dry-run` checked) |
| Demo media | Actions → Demo media → Run workflow (`dry-run` checked: GIFs as an artifact, no PR) |
| Release posts | `node scripts/marketing/release-post.mjs --tag vX.Y.Z` locally |

From a terminal with the GitHub CLI:

```bash
gh workflow run incident-radar.yml -f dry-run=true
```

The scripts also run locally with `--dry-run` (they use your `gh` login for
reads only):

```bash
node scripts/marketing/incident-radar.mjs --repo danoszz/penthera --dry-run
```

## Turning things off

- **One workflow:** Actions → the workflow → "…" → Disable workflow. Or delete
  its file.
- **Release drafts:** remove the "Draft release posts" and "Keep the drafts" steps (publish job) and the two share steps (release job) from `publish.yml`.
- **Footer, for one run:** `--no-footer` or `footer: "false"` in the Action.
  To drop it for everyone, make `footerLines()` in `src/report/footer.js`
  return `[]`.
- **Labels** (`incident-radar`, `monthly-stats`, `contributor-flywheel`) are
  created on the first real run and can be deleted afterwards.

## The weekly 30-minute routine

1. **Incident radar (10 min).** Open the `incident-radar` issues. For a
   popular package: add the IOCs, check `penthera deps` flags a fixture, post
   the draft (LinkedIn, X, Bluesky), close the issue. Skim the batch issue for
   names you recognise, then close it if it is long.
2. **A clip (5 min).** If a demo-media PR is open, watch the GIFs, merge, and
   post the best one as a short clip (Instagram, LinkedIn, X).
3. **Contributors (5 min).** If the flywheel reminder is open, turn one or two
   markers into `good first issue` issues. Reply to new contributors.
4. **Release (5 min, when there is one).** Approve the staged npm package, then
   copy the "Share this release" drafts from the GitHub Release, edit, post.
5. **Monthly (5 min, first week).** Fill in "what shipped" in the stats issue,
   post it, close it.
