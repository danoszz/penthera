# Penthera's Vercel integration server

> **Project page.** For the maintainer and reviewers asking "what does the Vercel
> integration server do, what does it keep, and how is it deployed?"

This folder is a small server that connects Penthera to a Vercel project as a
Deployment Check. It is deployed on its own, as a separate Vercel project. It
is never part of the npm package, and it has no Penthera version number.

The server does no scanning. Scans run in the user's own GitHub Actions, from a
workflow file the user commits. The server only:

1. exchanges the install code for a Vercel token,
2. lists the projects the user shared, so they can pick some,
3. hands them a GitHub "new file" link with the workflow filled in,
4. registers a Vercel check on each picked project that waits for the
   workflow's commit status, and
5. deletes everything when the user uninstalls.

## What it keeps

One record per installation, and nothing else:

| Field | What it is |
|---|---|
| `configurationId` | Vercel's id for the installation (`icfg_...`) |
| `ownerId` | the team id, or the user or account id for a personal account (`personal` if a transfer to a personal account names none) |
| `ciphertext`, `iv`, `tag` | the Vercel access token, encrypted with AES-256-GCM |
| `keyVersion` | which key encrypted it, for rotation |
| `createdAt` | when it was last installed or transferred. It moves forward, so a replayed older uninstall or transfer event is ignored |
| `sessionNonce` | 192 random bits, made fresh on every install and every transfer. Setup sessions are bound to it |

The store refuses a record with any other field (`lib/store.mjs`). Project
names, repos, emails, deployment URLs and scan results are never stored. Project
ids and names are read live from Vercel to draw the pages, then dropped.

So the stored data is: an installation id, a team or account id, an encrypted
token, a date and a random value. No other data about you or your projects.

Outside the store, Vercel's own request logs for this project record each
request's path and query string. That includes `/install?code=...` (the code is
spent within seconds and works once), the `configurationId`, the `teamId` and
Vercel's `next` URL. Those logs are Vercel's, kept for the plan's default
retention, and we do not export them.

The record is deleted:

- when Vercel sends a signed `integration-configuration.removed` webhook. The
  record goes first, before any other call, so a slow Vercel API cannot stop
  it. A store error answers 500, and Vercel retries for 24 hours.
- by a weekly cron (`/api/sweep`) for any record whose token Vercel answers
  with 401 or 404, in case a webhook was lost. A 403 keeps the record: it can be
  a disabled installation that comes back, or a transfer whose webhook was
  missed. Vercel sends `removed` when either one ends.

The token is encrypted with the configuration id as associated data, so a
ciphertext moved onto another record does not decrypt. The id used to decrypt
is always the trusted one: the store key, the signed session cookie or the
signed webhook. A record whose own `configurationId` differs from that id is
never used, so someone who can write to the store cannot move one
installation's token under another key and have it decrypt. The key lives in a
Vercel environment variable; the data lives in the store. They are in different
systems.

### Why this store

Upstash Redis from the Vercel Marketplace, on its free tier.

- It is the cheapest Vercel-native store that fits: a few writes per install,
  one read per page, a weekly scan. That is far inside the free tier, so the
  €5 cap is not touched.
- It is billed and set up through Vercel, which injects `KV_REST_API_URL` and
  `KV_REST_API_TOKEN`, and it offers an EU region.
- The server talks to it with plain `fetch` over its REST protocol, so there is
  no SDK and no dependency. `package.json` has no dependencies at all.
- Edge Config was the other candidate. It is built for read-heavy config, its
  writes go through the Vercel API with a token of their own, and it is not
  meant for per-user secrets.

The store sits behind four methods (`get`, `put`, `delete`, `ids`), so another
store is one small file. Tests use the in-memory store.

### Why not stateless

The spec's stateless option keeps nothing at all: the token would live only in
the 30-minute install session. It was not picked, because it gives up three
things:

- **Configure.** Without a stored token, no page can change projects after the
  install session ends.
- **Deploy Button installs.** Vercel may call the Redirect URL again with an
  existing `configurationId` and says to keep the token so it can be found.
- **Cleanup on uninstall.** With a stored token, the webhook can try to remove
  our checks before it deletes the record. Without one, it cannot even try.

Stateless still works as a fallback: delete the `put` call in `install` and the
record never exists. The listing copy ("only an encrypted install token,
deleted when you uninstall") stays true either way.

## Routes

| Path | Vercel console field | Does |
|---|---|---|
| `/install` | Redirect URL | Checks `state`, exchanges the code, seals and stores the token, sets a 30-minute session cookie, redirects to `/setup` |
| `/setup` | none | Project list, then the workflow page with the GitHub link, then "Turn on the check", then back to Vercel's `next` URL |
| `/configure` | Configuration URL | With the install session: back to `/setup`. Without it: the workflow file and how to remove the check, with nothing about the account |
| `/webhook` | Webhook URL | Verifies `x-vercel-signature`; handles `integration-configuration.removed` and `.transferred` only |
| `/start` | none | Starts an install from our own link: sets a CSRF state cookie and sends you to `vercel.com/integrations/<slug>/new?state=...` |
| `/health` | none | `{"ok":true}` |
| `/api/sweep` | none (cron) | Weekly. Needs `Authorization: Bearer $CRON_SECRET`, which Vercel's cron sends |

The workflow page comes before the check is turned on, so a production deploy
does not wait for a workflow that is not committed yet.

### Security

- **Webhook:** HMAC-SHA1 of the raw body with the client secret, hex, compared
  with `crypto.timingSafeEqual` after a format and length check. A missing or
  wrong signature gets a 403 and changes nothing. The body is parsed only after
  the check.
- **Install binding:** the code exchange must return the same
  `installation_id` as the redirect's `configurationId`, and the same team when
  the redirect names one. Otherwise nothing is stored. An existing record is
  never given to a different owner (409).
- **CSRF:** installs started from `/start` must return the `state` we set in an
  HttpOnly `__Host-` cookie, and a browser that holds that cookie must send the
  matching state. Installs started on vercel.com carry no state (Vercel's
  docs), so they must say `source=marketplace` or `source=deploy-button`, and
  the session is set only after the exchange proves the configuration and its
  owner. Form posts need the session cookie (SameSite=Lax), a form token bound
  to it, and a same-origin `Origin` header when the browser sends one.
- **Session binding:** the 30-minute setup cookie carries the configuration id,
  the owner and the record's `sessionNonce` when it was issued, signed. Every
  request checks them against the stored record, the nonce in constant time.
  Every install and every verified transfer makes a fresh random nonce, also a
  transfer that names no new owner or one that moves A to B and back to A, so
  each ends every older session. A counter would restart after an uninstall and
  reinstall of the same id; a random nonce does not come back.
  The new owner gets a session only by installing. Uninstall deletes the
  record, which ends sessions too.
- **Risk left (login CSRF):** an attacker can send someone a link with the
  attacker's own fresh install code and `source=marketplace`. The victim's
  browser then opens the attacker's setup page, for the attacker's own
  account. The victim's data and records are not touched, and the attacker
  gains nothing they did not already have. The fix would need Vercel to send
  `state` on every flow.
- **Open redirect:** the `next` URL is followed only if it is `https://` on
  exactly `vercel.com`, the one host the CSP's `form-action` allows.
- **Rate limits:** each `/install` makes one outbound call to Vercel, so a
  visitor gets 10 a minute per function instance. Instances count on their
  own, so the real limit is a Firewall rule (below).
- **Replay:** a signed `removed` or `transferred` event older than the record's
  `createdAt` changes nothing. Configuration ids are never reused (Vercel's
  docs), so a replay can only hit a record that a reinstall brought back.
- **Headers on every answer:** a CSP with `default-src 'none'`, no scripts, the
  one inline style allowed by hash, `form-action 'self' https://vercel.com`,
  `frame-ancestors 'none'`; HSTS, `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, a closed `Permissions-Policy`,
  `Cache-Control: no-store`, and `Cross-Origin-Opener-Policy: unsafe-none`,
  which Vercel requires for the install popup.
- **Logs:** errors only, through one logger (`lib/log.mjs`) that keeps an
  allow-list of fields and masks token shapes and the secret env values. ESLint
  bans `console` everywhere else in this folder. A test runs install, setup,
  failures and a broken config with random fake credentials and checks none
  appears in the output.
- **Configure:** Vercel's Configure button carries only a `configurationId`,
  which proves nothing about who clicked. So without the install session the
  page shows nothing account-specific.
- **No telemetry:** no analytics, no Speed Insights, no third-party scripts, no
  install counter. The server subscribes to no deployment events, so deployment
  URLs never reach it.
- **Rule 4:** the server runs no model and has no dependencies. The verdict is
  the Action's exit code, from fixed rules with `fail-on: high`.
- **Rule 5:** the workflow is a constant of each server release
  (`workflow/penthera-vercel.yml`, a copy of
  `docs/examples/vercel-deployment-check.yml`; a test keeps them equal). The
  server never serves rules or templates to the runner.

Vercel's own request logs record paths with query strings, so a spent install
code and the `configurationId` appear there. The privacy draft says so.

## Environment variables

Set these yourself in the integration's Vercel project, as **Sensitive**, on
Production only. Names starting with `VERCEL_` are reserved by Vercel, so the
client id and secret use the `INTEGRATION_` prefix. Never paste their values into a chat, an issue or a log.

| Name | What |
|---|---|
| `INTEGRATION_CLIENT_ID` | The integration's client id, from the Integrations Console |
| `INTEGRATION_CLIENT_SECRET` | The integration's client secret. Also signs the webhooks |
| `PENTHERA_TOKEN_KEYS` | `v1:<base64 of 32 random bytes>`. To rotate, prepend a new one: `v2:<new>,v1:<old>`. The first encrypts; all decrypt |
| `PUBLIC_BASE_URL` | This server's origin, such as `https://vercel.penthera.org`. The Redirect URL is `<PUBLIC_BASE_URL>/install` |
| `INTEGRATION_SLUG` | The integration's URL slug. Default `penthera` |
| `CRON_SECRET` | A long random string. Vercel's cron sends it to `/api/sweep` |
| `KV_REST_API_URL`, `KV_REST_API_TOKEN` | Set by Vercel when you connect the Upstash store |

Make a key on your own machine:

```bash
node -e "console.log('v1:' + require('crypto').randomBytes(32).toString('base64'))"
```

## Vercel console settings

| Field | Value |
|---|---|
| Redirect URL | `<PUBLIC_BASE_URL>/install` |
| Webhook URL | `<PUBLIC_BASE_URL>/webhook` |
| Webhook events | `integration-configuration.removed` and `integration-configuration.transferred`. No deployment events |
| Configuration URL | `<PUBLIC_BASE_URL>/configure` |
| API scopes | Deployment Checks: Read/Write. Projects: Read. Nothing else |
| Checks API toggle | Off, unless the scope test below says it is needed |

### Firewall rate limit (dashboard only)

`vercel.json` cannot hold Firewall rules. In the integration project: Firewall,
Configure, New Rule:

- **Name:** `install-webhook-rate-limit`
- **If:** Request Path matches `^/(install|start|webhook)$`
- **Then:** Rate Limit, Fixed Window, 60 seconds, 30 requests, key IP, action
  Default (429)

Then Review Changes and Publish. Rate limiting is billed by usage on Pro;
this traffic is tiny, but it counts toward the €5 cap.

## Deploy

1. Create a Vercel project from this repo with **Root Directory**
   `integrations/vercel`, framework "Other". `vercel.json` here builds `main`
   only.
2. Connect an Upstash Redis store from the Vercel Marketplace to that project,
   free tier, EU region.
3. Set the environment variables above.
4. Add the domain, for example `vercel.penthera.org`, and set
   `PUBLIC_BASE_URL` to it.
5. In the Integrations Console, set the URLs, events and scopes above.
6. Set the team's Spend Management cap to €5 a month, with the project paused
   at the cap.
7. Install it on a test project of your own and go through the end-to-end check
   below.

## Unverified, test before submitting

Read in Vercel's docs on 5 Nov 2026: the code exchange (`POST
/v2/oauth/access_token`, form-encoded, 30 minutes, once), the Redirect URL
parameters (`state` only on the external flow), the checks-v2 endpoints and
body, `GET /v10/projects`, the webhook signature and its 30-second timeout, the
removed and transferred payloads, the COOP note, and the `export default {
fetch }` function format.

Not verified, because it needs a live integration:

- **Which scope allows `POST /v2/projects/{id}/checks`.** The docs map the
  `deployment-check` scope to the v1 per-deployment endpoints only. If checks-v2
  needs Projects Read/Write, change the scope and say so on the install page.
- **Whether Vercel removes our checks on uninstall.** The webhook tries, but the
  token is probably revoked by then. If the checks stay, a production deploy
  waits for a status that never comes once the workflow is deleted. The
  Configure page tells users to remove the check.
- **The status name.** The check waits for
  `Penthera on Vercel | scan (<project> - production)`, the status action's
  default as read from its source. Confirm it on a real deploy.
- **The GitHub prefill.** `github.com/<owner>/<repo>/new/<branch>?filename=&value=`
  works today but is not a documented GitHub API.
- **That the code exchange always returns `installation_id`.** Vercel's example
  shows it. The server now refuses an exchange without it.
- **The transfer payload for a personal account.** The docs list
  `newTeamId` and `newAccountId`; the server uses whichever names the new
  owner.

End-to-end check: install on your own project, commit the workflow from the
link, turn on the check, push to production and see it held then released,
then uninstall and confirm the record is gone (`/api/sweep` count, or the
Upstash console).

## Tests

`npm test` at the repo root runs `test/integration.test.js` with the repo's
vitest (the `unit` project includes `integrations/*/test`). The tests are
offline: an in-memory store and a mocked `fetch`, no calls to Vercel, GitHub
or Upstash.

## Legal

- [Terms of use](https://docs.penthera.org/vercel/terms)
- [Privacy notice](https://docs.penthera.org/vercel/privacy)
