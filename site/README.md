# Site

> **Project page.** For "how is the website built, and how do I change it?"

The landing page, a static site for Vercel. The decisions behind it are in
[BRIEF.md](BRIEF.md). It is not part of the npm package.

```bash
node site/build.mjs     # writes site/dist
node site/serve.mjs     # http://127.0.0.1:4173/ with the production headers
```

## What is where

| Path | What it is |
|---|---|
| `index.html` | The page and all its copy. `{{NAME}}` placeholders are measured numbers the build fills in: rule counts, the popular-list size, the benchmark from `bench/RESULTS.md`, and the GitHub star count (the build's one request; `PENTHERA_SITE_STARS=<n>` or `off` to skip it). |
| `news.json` | The ticker at the top: dated, one-line items, each with an https source. The build renders it (and refuses an item without a source); edit it to change the news. A daily workflow proposes new items as a PR; see [The news feed](#the-news-feed). |
| `styles.css` | System 1-bit, as in `penthera ui`. Tokens and contrast measurements are in its header. |
| `theme.js` | Sets the theme before paint. A choice is kept in localStorage, never a cookie. |
| `blog.mjs` | `/blog` and each post, from `blog/`: a teletext newspaper, always light (`data-paper` on `<html>`, respected by `theme.js`). |
| `type.mjs` | `/type`: the type system, drawn from the tokens in `styles.css`. `tests/site-type.test.js` keeps every size on those tokens. |
| `frame.mjs` | What every page shares: the footer, and the steel dock (the bottom navigation), which `build.mjs` puts before `<main>` on each rendered page. |
| `check/` | The browser check. `engine.js` calls `lib/`; `ui.js` is the page script; `copy.js` holds its strings; `field.js` is the hero's live field (a dithered cloud, a pointer lens with a soft glow, and a click shockwave on a canvas; off under reduced motion, where `media/field.png` stays). |
| `check/shims/` | The Node built-ins `lib/` uses, for the browser: an in-memory `fs`, POSIX `path`, a synchronous SHA-256, and `gunzipSync` fed by DecompressionStream. |
| `build.mjs` | Bundles `check/` with `lib/` (rolldown), embeds the rule packs and the popular-package list, verifies each pack's signature, and copies the media. Every version on the page and in `llms.txt` is `{{VERSION}}`, from `package.json`; while it is a release candidate, the MCP sections say so. |
| `agents.mjs` | The files for agents and crawlers, written by the build: `llms.txt` (from `llms.txt` here), `llms-full.txt` (README.md and the user docs as one file), each of those pages as Markdown under `/docs/` with absolute links and npm pins set to the package version, `sitemap.xml`, `robots.txt` and `/.well-known/security.txt` (RFC 9116, expiring 300 days after the build). They use the `homepage` in `package.json` as the origin. |
| `research.mjs` | `/research` and `/research.md`: every study in `docs/research/prereg/` with its status, the result files, the case studies and the approved blog posts, newest first, with the public benchmark as the featured card. Each headline lists the sentences in its source that back it, and the build fails when one is missing. A study whose status says it is not registered is always Draft. |
| `pages/`, `landing.mjs` | Landing pages, one search question each: `/website-security-check` and `/lovable-bolt-app-security`. Each is a Markdown file with a `title` and `description` for search in its front matter; `{{CTA}}` is the button to the live check. The build renders them in the `/terms` frame, writes their Markdown next to them, and adds both to the sitemap and `llms.txt`. A new file in `pages/` is a new page. |
| `<32 hex>.txt` | The IndexNow key, served at the site root. See [After a deploy](#after-a-deploy). |
| `serve.mjs` | A local preview that sends the headers from `vercel.json`. |
| `../vercel.json` | At the repo root, so Vercel needs no settings: install, build (`node site/build.mjs`), output (`site/dist`) and the security headers: CSP with `connect-src` limited to Vercel's two counters, HSTS, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, plus a text `Content-Type` for the Markdown and text files. Its `ignoreCommand` skips every build that is not production (preview with `node site/serve.mjs` instead, or start one by hand in Vercel), and skips production builds when no path the build reads changed, docs included. |
| `stars.json` | The last GitHub star count the build read, used when the API is rate-limited or offline. Set `GITHUB_TOKEN` in Vercel to avoid the anonymous limit. |
| `tools/tour-shots.mjs` | Renders the three "See it work" shots in `media/tour/` (1200 × 750 JPEGs at device scale 2, light theme, each cropped to the part that matters) from `penthera ui --demo` on 127.0.0.1 with a local Chrome: the Check my app window, the verdict with the first problem, and a fix waiting with its diff. Re-run it when the dashboard changes. |
| `tools/social.mjs` | Renders `media/social/og.png` (1200 × 630, the share card for LinkedIn, X and Facebook) and `square.png` (1080 × 1080, Instagram) with a local Chrome. Re-run it when the headline changes. |
| `tools/reel.mjs` | Renders `media/social/reel.mp4`, the 12-second muted loop that iMessage and other apps play for a shared link (`og:video`, with `og.png` as poster and fallback): the opening line, the verdict, a fix applied and checked, the rules deciding and the share card. Cut from `media/film.mp4`; needs Chrome and ffmpeg. Re-run it after the film or the card changes. X shows the image card only. |
| `media/` | The tour's dashboard shots are copied from `assets/dashboard/` at build time. `field.png` (the hero's 1-bit cloud), regenerated with `tools/media.sh`; `dvdzwaag.svg`, the maker's wordmark traced with potrace from Daan's own artwork, used as a mask so it takes the ink. |

## The browser check

`lib/` reads files with `node:fs`. In the page, the visitor's files are
mounted in an in-memory folder (`/repo`) and the rule packs and lists under
`/penthera`, and these functions run unchanged:

- `scanAgents` (lib/agents): MCP servers, hooks, permissions, instruction files
- `scanSecrets` (lib/whitebox/secrets.js)
- `scanPackage`, `findTyposquats`, `loadIocs` and the finding builders in
  `lib/deps/findings.js`, for `package.json`

`tests/site.test.js` builds the engine and compares its findings with the
CLI's on `tests/fixtures/agents/*` and the deps fixture. If a change to `lib/`
needs a Node built-in the shims do not have, the build fails and names it.

The rule packs' signatures are checked at build time with
`lib/rules/sshsig.js`; the build refuses a pack whose signature does not
verify. In the page, `lib/rules/pack.js` still checks every rule file against
the SHA-256 in its `pack.json`.

## The news feed

`.github/workflows/news-feed.yml` runs daily. It reads official,
machine-readable sources, turns what is new into ticker lines, and opens or
updates one PR (branch `news-feed/update`) that changes `news.json` only.
Nothing reaches the page until a person merges that PR.

```bash
node scripts/marketing/news-feed.mjs --dry-run            # print what it would add and drop
node scripts/marketing/news-feed.mjs --since-days 30      # write news.json with a longer look-back
```

| Source | What becomes a line |
|---|---|
| CRA milestones (Regulation (EU) 2024/2847, Article 71) | the day a date applies |
| NCSC-NL advisories (RSS) | first versions rated high likelihood and high impact |
| ENISA EUVD (JSON API) | exploited vulnerabilities in the products below; CVSS 9 or more in the runtimes |
| CISA Known Exploited Vulnerabilities (JSON) | entries for the products below |
| php.net (Atom), nginx (RSS), Node.js (RSS) | security advisories and security releases |
| OpenSSL, Apache httpd (CVE JSON 5) | advisories rated High/Critical (OpenSSL) or important/critical (httpd) |
| GitHub malware advisories for npm (REST API) | packages on Penthera's popular list only |

The products are the runtimes in `lib/rules/advisories/` (PHP, nginx, Apache
httpd, Node.js, Python, OpenSSL) plus npm, GitHub, GitLab and Jenkins, matched
on the source's vendor and product fields. Python has no feed of its own: the
PSF advisory database has no severity, so CPython shows up through EUVD and
the exploited lists. ENISA has no news feed, so ENISA news beyond EUVD is
still added by hand.

Each line is built from fields the source states: a title, a version, a CVE,
a rating. Nothing is summarized, and a line that does not fit in 120
characters is skipped. When two sources report the same thing (same source
URL, same CVE, or the same product on the same day), the first in the table
wins and an item already on the page wins over both.

The merge keeps the newest first and dated items still ahead at the end,
caps the list at 10 (`--cap`), adds at most 5 per run (`--max-new`), and
drops items older than 365 days (`--max-age-days`). A source that fails is
named in the PR and skipped.

Reviewing the PR: open each source and check the line says what it says.
Edit or drop lines on the branch; once a person pushes to it, the workflow
leaves it alone. To turn an item down for good, add its source URL to a
top-level `skip` array in `news.json`.

## Deploying

Import the repository in Vercel and deploy; leave the root directory at the
repository root and the framework preset on "Other". Everything else comes
from `vercel.json` at the root: it runs `npm ci` there (the build reads
`lib/` and uses `rolldown` from the root `package.json`), builds with
`node site/build.mjs` and serves `site/dist`.

## After a deploy

Tell the IndexNow engines (Bing, Yandex, Seznam, Naver and others) that the
site changed. Run it by hand once the deploy is live; it is not part of the
build and CI does not run it:

```bash
node scripts/indexnow.mjs --dry-run   # print the URLs it would send
node scripts/indexnow.mjs             # check /<key>.txt is live, then submit
```

It reads `https://penthera.org/sitemap.xml`, checks that the key file answers
with the key, and sends one POST to `api.indexnow.org`. Google does not use
IndexNow: it finds the sitemap through `robots.txt`. To check either engine's
view, add the site in Google Search Console and Bing Webmaster Tools and
submit `https://penthera.org/sitemap.xml` there once.
