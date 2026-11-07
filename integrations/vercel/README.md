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
4. registers a Vercel check on each picked project, owned by this integration,
5. relays the workflow's pass or fail for each production deployment to that
   check (`POST /report`, below), and
6. deletes everything when the user uninstalls.

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

And one link per project the check is turned on for, so `POST /report` knows
which installation's token to use:

| Field | What it is |
|---|---|
| `projectId` | the Vercel project id (`prj_...`), also the key |
| `configurationId` | the installation that turned the check on |

And one set of anonymous counters per UTC day, for upkeep and bugs, under
`pv:stats:<YYYY-MM-DD>`, each day's key expiring 90 days after its last write:

| Counter | What it counts that day |
|---|---|
| `received` | calls to `POST /report` (rate-limited ones are not counted) |
| `succeeded`, `failed` | results relayed to Vercel |
| `rejected_<reason>` | refusals, by `/report`'s error code (`bad_token`, `repository_mismatch`, `not_enabled`, and the rest in `REJECT_REASONS`) |

A counter holds a number and nothing else: no project, deployment, team or
configuration id, no IP, nothing from the request. The key is the date.

Only a relay that reached Vercel is written at once. Every refusal, also one
with a valid GitHub token (anyone can mint one from their own repo), is added up
in the function instance's memory and written at most once a minute, and each
day key gets its `EXPIRE` once per instance. So junk traffic costs a few store
commands a minute per instance, not two writes per request. Counts still in
memory when an instance stops are lost; these are rough totals.

The store refuses a record, a link or a counter with any other field or name
(`lib/store.mjs`).
Project names, repos, emails, deployment ids, deployment URLs and scan results
are never stored. Project names and repos are read live from Vercel to draw the
pages and to check a report, then dropped.

So the stored data is: an installation id, a team or account id, an encrypted
token, a date, a random value, and the ids of the projects you turned the check
on for. No other data about you or your projects. Beside it, anonymous daily
totals that name nobody.

**Who owns a link.** The installation whose own token still sees its own
Penthera check on the project. When another installation turns the check on for
a project that is already linked, the server first asks Vercel, with the
current owner's token, whether that owner's check is still there. If it is, the
link stays and no second check is added (the page says so, 409). If the
owner's record is gone, or Vercel answers 401, 403 or 404, or the check is
gone, the link moves. On any other error the link stays: it is never taken over
on a guess.

A link is deleted when you remove the check from the setup page, when the
installation is removed (every link that names it, whatever key it sits under),
and by the weekly sweep when its installation is gone or it does not match its
key.

Outside the store, Vercel's own request logs for this project record each
request's path and query string. That includes `/install?code=...` (the code is
spent within seconds and works once), the `configurationId`, the `teamId` and
Vercel's `next` URL. Those logs are Vercel's, kept for the plan's default
retention, and we do not export them.

The record and its links are deleted:

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
| `/report` | none | The workflow's pass or fail for one production deployment, with a GitHub OIDC token. Sets our check run's conclusion. Stores nothing |
| `/start` | none | Starts an install from our own link: sets a CSRF state cookie and sends you to `vercel.com/integrations/<slug>/new?state=...` |
| `/health` | none | `{"ok":true}` |
| `/api/sweep` | none (cron) | Weekly. Needs `Authorization: Bearer $CRON_SECRET`, which Vercel's cron sends |

The workflow page comes before the check is turned on, so a production deploy
does not wait for a workflow that is not committed yet.

## The check and the relay

Read in Vercel's docs on 7 Nov 2026:
[Checks API support for Marketplace integrations](https://vercel.com/changelog/checks-api-support-added-for-marketplace-integration-providers),
[Checks API reference](https://vercel.com/docs/checks/checks-api),
[Anatomy of the Checks API](https://vercel.com/docs/checks/creating-checks),
[checks-v2 endpoints](https://vercel.com/docs/rest-api/checks-v2),
[Create a check](https://vercel.com/docs/rest-api/checks-v2/create-a-check),
[Create a check run](https://vercel.com/docs/rest-api/checks-v2/create-a-check-run),
[Update a check run](https://vercel.com/docs/rest-api/checks-v2/update-a-check-run),
[List check runs for a deployment](https://vercel.com/docs/rest-api/checks-v2/list-check-runs-for-a-deployment),
[Deployment Checks](https://vercel.com/docs/deployment-checks),
[Webhooks API](https://vercel.com/docs/webhooks/webhooks-api) and the
[repository dispatch payload](https://github.com/vercel/repository-dispatch/blob/main/packages/repository-dispatch/src/data/deployment.ts).

**Why not a GitHub check.** The first design registered
`source: { kind: "git-provider", provider: "github", externalCheckName }`. On
7 Nov Vercel answered our integration's token with `400 not_implemented`:
users can import GitHub checks in the dashboard, integrations cannot.

**The check.** `POST /v2/projects/{id}/checks` with
`source: { kind: "integration", integrationId, integrationConfigurationId }`,
`requires: "deployment-url"`, `blocks: "deployment-alias"`,
`targets: ["production"]`, `isRerequestable: false` and `timeout: 1200`
(`lib/workflow.mjs`, `checkBody`). `blocks: "deployment-alias"` holds each
production deployment off the production domains until the check passes,
which is what Vercel's Deployment Checks page describes; Force Promote
bypasses it. The spec's enum also lists `deployment-promotion`, but live Vercel
answered it on 7 Nov with `400 not_implemented` ("Only deployment-alias and
none are currently supported for blocks"), so the contract mock refuses it too
(`LIVE_LIMITS` in `test/vercel-contract.mjs`). Vercel holds a deployment only
when automatic aliasing for production is on (its default). The source shape is the first `oneOf` branch
of the create schema; `kind` defaults to `integration` there and none of its
fields is marked required. `integrationId` is `INTEGRATION_ID` when set, or
else read on each "Turn on the check" from
`GET /v1/integrations/configuration/{configurationId}` with the installation's
token (its `integrationId`, "the app the configuration was created for", and
only when the answer's `id` is this configuration). If that lookup fails, the
source names the configuration alone and the log says why; the client id is
never sent. Vercel then makes a check run for each production deployment of the
project.

If Vercel answers the create with a 400 whose message names `timeout`, the
server tries once more without it (Vercel's default, 300 s). The docs give
`timeout` a default and no maximum.

**An old check on a re-install.** Vercel's docs do not say whether an
integration's checks go when its installation is removed. If one stays, it
holds production forever, because no installation finishes its runs. So before
creating its check, "Turn on" looks at the project's checks:

- A check whose `source.integrationId` is ours, from a configuration this server
  holds no live record for, is a leftover of an earlier install. It is deleted
  with the current token.
- If that configuration is still live (its own token still sees its check), or
  the server can't tell, the project counts as taken (409) and nothing is
  deleted. "Can't tell" covers a record whose token doesn't decrypt (a key
  rotation, a config error), and a 403, which the sweep also treats as possibly
  coming back. Only a missing record, or a 401 or 404 for that token, counts as
  gone.
- Nothing that is not ours by source is ever deleted: not a hand-added GitHub
  check, not another integration's check, and nothing at all when the
  integration id is unknown. A check named like ours that this installation
  cannot vouch for gets a note on the Done page with a link to Deployment
  Checks.

**When Turn on fails,** the Done page says per project what Vercel answered, in
plain words, what to do, a link to the right place in Vercel, and the code in
small print, for example `Vercel 403 forbidden: …`. It offers "Try again" only
when trying again can help.

| Vercel's answer | Page (`data-reason`) | What it says to do |
|---|---|---|
| 401 | `revoked` | install again (`/start`) |
| 403 `integration_configuration_disabled` | `disabled` | a team owner transfers it, or install again |
| 403 | `forbidden` | accept the pending permission update; check the project is shared |
| 404 | `not_found` | give Penthera access to the project |
| 409, or a 400 saying the check already exists | `conflict` | remove the old Penthera check in Deployment Checks |
| other 400 | `rejected` | on our side: send us the code |
| deleting a leftover refused | `leftover` | remove the old Penthera check in Deployment Checks |
| 429 | `rate_limited` | wait a minute, then Try again |
| 5xx, no answer | `vercel_down`, `network` | Try again |
| our store failed | `store` | Try again |

**The result.** `PATCH /v2/deployments/{deploymentId}/check-runs/{checkRunId}`
with `status: "completed"`, `conclusion` (`succeeded` or `failed`; the schema
also allows `canceled`, `skipped`, `timeout`, `neutral`), `conclusionText`,
and `externalUrl` (the GitHub run). The run is found with
`GET /v2/deployments/{id}/check-runs` (`runs[]`, each with `checkId`,
`projectId`, `deploymentId`, `status`). If Vercel has made none yet, the server
starts it with `POST /v2/deployments/{id}/check-runs` and `{ checkId }`.

**No webhooks needed.** The Checks API's older flow (`deployment.created`, then
`deployment.ready`, `/v1/deployments/{id}/checks`) registers a check per
deployment from webhooks. The v2 flow defines the check once per project, and
the run is found from the deployment id the workflow already has. So the
integration still subscribes only to `integration-configuration.removed` and
`.transferred`. `deployment.check-rerequested` is not needed because the check
is not rerequestable: a re-run means a redeploy.

### POST /report

The workflow's last step runs on every outcome (`if: always()`), for production
deployments only, and sends exactly
`{ deploymentId, projectId, conclusion: "succeeded" | "failed" }`. It reports
`failed` when the scan failed, was incomplete, or did not run. The ids come from
Vercel's dispatch payload (`client_payload.id`, `client_payload.project.id`).

It sends a GitHub Actions OIDC token as `Authorization: Bearer`, requested with
`audience=https://vercel.penthera.org/report/<deploymentId>` (the job has
`id-token: write`), so a token is good for one deployment only. The server
(`lib/oidc.mjs`, `lib/app.mjs` `relay`):

1. **Token.** RS256 only, refused before any key lookup otherwise (`alg: none`,
   HS256 with the public key, and the rest). The key comes by `kid` from
   GitHub's JWKS at `https://token.actions.githubusercontent.com/.well-known/jwks`,
   cached 10 minutes per instance. Any other fetch (an unknown `kid`, or a retry
   after GitHub failed) happens at most once a minute; in between a stale cache
   answers 503 at once. Concurrent callers share one fetch, which has a
   3-second timeout, follows no redirect and reads at most 64 KiB. A clock that
   moves backwards counts as stale. `iss` must be
   `https://token.actions.githubusercontent.com` and `aud` exactly
   `<PUBLIC_BASE_URL origin>/report/<deploymentId>` for the body's deployment. `exp`, `nbf` and `iat` must all be numbers, with
   30 seconds of leeway, and a token may live at most one hour.
2. **Workflow.** `event_name` must be `repository_dispatch` (Vercel's) and
   `workflow_ref` must be `<repository>/.github/workflows/penthera-vercel.yml@...`.
   Another workflow in the repo, or a pull request run, cannot report.
3. **Installation.** The project's link names the installation. Its record and
   token are opened under that id, as everywhere else (a moved ciphertext does
   not decrypt).
4. **Repository.** With that token, the project is read live from Vercel. Its
   connected repo must equal the token's `repository` (case-insensitive), and
   its GitHub repository id (`link.repoId`) the token's `repository_id`. A
   project with no repository id is refused, so a renamed, deleted or recreated
   repo of the same name cannot report. The owner id (`link.repoOwnerId`) is
   compared with `repository_owner_id` when Vercel gives it; the token must
   carry one.
5. **Deployment, before any write.** `GET /v13/deployments/{id}` must name this
   project and target `production`. Only then is a run looked up, started or
   changed.
6. **Check and run.** The project must carry this installation's own check
   (`source.integrationConfigurationId`). The run must be a run of exactly that
   check, and Vercel's run must name this project and this deployment.
7. **Once.** A run that is already `completed` is never changed (409), so a
   replayed token cannot flip a result.

Any failure leaves the run as it was, so the deploy stays held until Vercel's
timeout. Nothing from the request is stored or logged beyond an error code and
one tick on today's anonymous counters (above). A store error while counting
changes no answer.
`/report` answers 404 when the check is not on for the project; the workflow
then passes with a notice, for people who use the commit status alone.

The commit status stays in the workflow, so a GitHub check added by hand still
works.

**Risk left (repo write access).** Anyone who can write to the repo can send
the workflow a `repository_dispatch` of their own, with any deployment id and a
URL that scans clean, and so pass the check for that deployment. That is the
same trust a hand-added GitHub check already gives them: write access can post
a commit status directly. The relay adds no new way in; it keeps the gate at
"who can change this repo's default branch or send its dispatches".

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
  HttpOnly `__Host-` cookie, which lasts 30 minutes, as long as Vercel's install
  code. Installs started on vercel.com carry no state, so they must name a
  Vercel source (`marketplace`, `deploy-button` or `external`), and the session
  is set only after the exchange proves the configuration and its owner. The
  listing link `vercel.com/integrations/penthera/new`, opened directly rather
  than through `/start`, comes back as `source=external` with no state (live,
  7 Nov: Daan's first install from the listing was refused as
  `external_without_state`). Vercel's docs describe `state` only as a string
  "passed back upon completion" when the starter set one, and give no reason
  to treat a state-less `external` install differently from a Marketplace one:
  both are the same login-CSRF case below, and both bind nothing until the
  exchange. So an `external` install without state takes the Marketplace path.
  A state that comes back is still checked: missing cookie or a mismatch is
  refused, whatever the source. A leftover
  state cookie from an earlier `/start` does not block such an install: the
  browser takes the same path as one without the cookie, and the cookie is
  cleared. Until 7 Nov a browser holding the cookie had to send the matching
  state on every install. That blocked Daan's own Marketplace install after an
  earlier `/start`, and it protected only a browser in the middle of a `/start`
  install from the login CSRF below, which every other browser is open to
  anyway. Form posts need the session cookie (SameSite=Lax), a form token bound
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
- **A refused install** (`/install`, 403) names one of two reasons on the
  page (`data-reason`): `state_cookie_missing` (the state came back, but this
  browser no longer has the cookie: more than 30 minutes passed, or the install
  started in another browser or on another device) or `state_mismatch` (the
  state does not match this browser's cookie). Until 7 Nov a third,
  `external_without_state`, refused the listing link's normal install (see
  CSRF above). Each is refused before the code is exchanged, so
  nothing is stored and no check is added; each clears the cookie and offers
  "Install again" (`/start`).

  What it leaves behind: Vercel makes the installation before it sends the
  browser to our Redirect URL, because the `configurationId` is already in that
  URL. So after a refusal Vercel probably still lists Penthera under Settings,
  Integrations, with no token on our side and nothing on any project. Its code
  expires after 30 minutes unused. Vercel's docs do not say what
  `/integrations/<slug>/new` does for a team that already has an unfinished
  installation: open it again, add a second one, or refuse. They do say a
  configuration id is never reused. The page therefore says: install again, and
  if Vercel shows Penthera as already installed, remove it there first. Only a
  live test can show which of the three Vercel does.
- **Risk left (login CSRF):** an attacker can send someone a link with the
  attacker's own fresh install code and `source=marketplace` (or
  `source=external` with no state). The victim's
  browser then opens the attacker's setup page, for the attacker's own
  account. The victim's data and records are not touched, and the attacker
  gains nothing they did not already have. The fix would need Vercel to send
  `state` on every flow.
- **Open redirect:** the `next` URL is followed only if it is `https://` on
  exactly `vercel.com`, the one host the CSP's `form-action` allows.
- **Body caps:** every body (`/report` 1 KiB, `/webhook` 64 KiB, `/setup`
  16 KiB) is read as a stream with a running byte count and abandoned the moment
  it passes the cap, also when there is no `Content-Length` (chunked).
- **Rate limits:** each `/install` makes one outbound call to Vercel, so a
  visitor gets 10 a minute per function instance. Instances count on their
  own, so the real limit is a Firewall rule (below).
- **Replay:** a signed `removed` or `transferred` event older than the record's
  `createdAt` changes nothing. Configuration ids are never reused (Vercel's
  docs), so a replay can only hit a record that a reinstall brought back.
- **Headers on every answer:** a CSP with `default-src 'none'`, no scripts, the
  one inline style allowed by hash, fonts and images from this origin only
  (`public/`: Departure Mono and the favicon), `form-action 'self'
  https://vercel.com`, `frame-ancestors 'none'`; HSTS, `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin` (with `no-referrer`, browsers send `Origin: null` on our own form posts), a closed `Permissions-Policy`,
  `Cache-Control: no-store`, and `Cross-Origin-Opener-Policy: unsafe-none`,
  which Vercel requires for the install popup.
- **Logs:** errors only, through one logger (`lib/log.mjs`) that keeps an
  allow-list of fields and masks token shapes and the secret env values. For a
  failed check create or integration lookup, that includes Vercel's error code
  and message (at most 200 characters), so a failure explains itself. ESLint
  bans `console` everywhere else in this folder. A test runs install, setup,
  failures and a broken config with random fake credentials and checks none
  appears in the output.
- **Configure:** Vercel's Configure button carries only a `configurationId`,
  which proves nothing about who clicked. So without the install session the
  page shows nothing account-specific.
- **No telemetry:** no analytics, no Speed Insights, no third-party scripts, no
  install counter. The only counters are the anonymous daily relay totals in
  "What it keeps". The server subscribes to no deployment events, so deployment
  URLs never reach it. Per production deploy it receives the project id, the
  deployment id, pass or fail, and GitHub's signed token (which names the
  repository, workflow, run, commit and the GitHub account that started the
  run). It checks them, sets the result in Vercel, and keeps none of it,
  only one tick on the day's anonymous totals.
- **Rule 4:** the server runs no model and has no dependencies. The verdict is
  the Action's exit code, from fixed rules with `fail-on: high`. The relay only
  carries it; it decides nothing.
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
| `INTEGRATION_ID` | Optional. Overrides the integration id (`oac_...`) the server reads from Vercel for the check's `source` |
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
| API scopes | Deployment Checks: Read/Write. Projects: Read. Deployments: Read (the relay reads which project a deployment belongs to before it writes). Nothing else |
| Checks API toggle | On: the integration now owns its check. The v2 docs do not say the toggle is required; if "Turn on the check" still answers 400 or 403, this and the scope are the first two things to check |

### Firewall rate limit (dashboard only)

`vercel.json` cannot hold Firewall rules. In the integration project: Firewall,
Configure, New Rule:

- **Name:** `install-webhook-rate-limit`
- **If:** Request Path matches `^/(install|start|webhook|report)$`
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

- **That Vercel makes the run itself.** The docs list `POST
  /v2/deployments/{id}/check-runs` but do not say whether a project check gets
  its runs on its own. The server finds the run, or starts it, so both work.
  Watch the first production deploy: the run should show up as queued.
- **The configuration lookup's scope.** `GET /v1/integrations/configuration/{id}`
  says only that the owner of the configuration may read it. If the log shows
  `integration_lookup_failed` with a 403, the scope list needs the
  integration-configuration read scope, or set `INTEGRATION_ID`.
- **`timeout: 1200`.** The default is 300 seconds; the job may take 15
  minutes. The docs give no maximum. A 400 that names `timeout` falls back to
  the default by itself.
- **`link.repoId` and `link.repoOwnerId` on `GET /v9/projects/{id}`.** The relay
  refuses a project without `repoId`; if Vercel never sends it, every report is
  refused and deploys wait for the timeout. `repoOwnerId` is compared when
  present.
- **`GET /v13/deployments/{id}` with Deployments: Read.** Fields used: `id`,
  `projectId`, `target`.
- **Which scope allows the checks-v2 calls.** The docs map the
  `deployment-check` scope to the v1 per-deployment endpoints only. If checks-v2
  or the check-run calls need more, change the scope and say so on the install
  page.
- **Whether Vercel removes our checks on uninstall.** The webhook tries, but the
  token is probably revoked by then. If the checks stay, a production deploy
  waits for a status that never comes once the workflow is deleted. The
  Configure page tells users to remove the check.
- **The status name** (hand-added GitHub check only). The status is
  `Penthera on Vercel | scan (<project> - production)`, confirmed on a real
  deploy on 7 Nov.
- **The GitHub prefill.** `github.com/<owner>/<repo>/new/<branch>?filename=&value=`
  works today but is not a documented GitHub API.
- **That the code exchange always returns `installation_id`.** Vercel's example
  shows it. The server now refuses an exchange without it.
- **The transfer payload for a personal account.** The docs list
  `newTeamId` and `newAccountId`; the server uses whichever names the new
  owner.

End-to-end check: install on your own project, commit the workflow from the
link, turn on the check, push to production and see it held then released
(the workflow's last step says "Reported succeeded"), push a change with a
high finding and see it held, then uninstall and confirm the record and the
links are gone (`/api/sweep` count, or the Upstash console).

## Tests

`npm test` at the repo root runs `test/integration.test.js`,
`test/relay.test.js` (the OIDC check against a local test key set) and
`test/e2e-journey.test.js` with the repo's vitest (the `unit` project includes
`integrations/*/test`). The tests are offline: an in-memory store and a mocked
`fetch`, no calls to Vercel, GitHub or Upstash.

### The install journey against Vercel's API spec

`test/e2e-journey.test.js` walks the whole install through the real app:
`/start`, `/install` (from our link with `state`, and from the Marketplace),
Pick, Workflow and Turn on (a browser's `Origin: null` and our own origin), a
production deploy's `POST /report` with an OIDC token from a local key set, the
check run's conclusion, a preview deploy refused before any write, `/configure`,
the signed `removed` webhook, and an empty store. Each page is checked for the
words a user should see, and against the error pages' words.

Every call the server makes to Vercel goes to a fake (`test/vercel-contract.mjs`)
that holds it to Vercel's published contract:

- the method and path name a real operation;
- path parameters are filled, and every query parameter is declared, with a
  value that fits its type or enum;
- `Authorization: Bearer` is present;
- the JSON body validates against the request schema (ajv), so required
  fields, enums, types, patterns and `additionalProperties` are all checked.

A check's `source` is checked against the one `oneOf` branch its `kind` names,
because the spec's branches overlap: the webhook branch accepts any object with
a `kind`. The fake's own answers are checked against the response schemas too,
so it cannot answer in a shape Vercel does not promise. It also refuses a
git-provider check from an integration (`not_implemented`), as live Vercel did
on 7 Nov. A mismatch fails the test and names the field, for example
`/blocks: must be equal to one of the allowed values`.

The OAuth code exchange (`POST /v2/oauth/access_token`) is not in the OpenAPI
spec. It is checked by hand: form-encoded, with `client_id`, `client_secret`,
`code` and `redirect_uri`.

The contract is `test/fixtures/vercel-openapi.json`, a trimmed copy of
[Vercel's OpenAPI spec](https://vercel.com/openapi.json), fetched on 7 Nov 2026.
It keeps whole request schemas for the 10 operations in `lib/vercel.mjs`, and
response schemas cut down to the fields the server reads. Refresh it by hand
(never at run time, rule 5), then review the diff:

```bash
node integrations/vercel/scripts/refresh-openapi.mjs
```

The refresh fails if the spec drops an operation, or no longer has a response
field the server reads.

The journey test also runs `actionlint` on `workflow/penthera-vercel.yml`.
actionlint runs shellcheck on the run scripts when shellcheck is installed. CI
installs a pinned actionlint, checked against its SHA-256. Locally the test
skips when actionlint is not installed; in CI it never skips.

What the contract caught on 7 Nov: `GET /v13/deployments/{idOrUrl}` answers one
of three views. Only the owner's view has `projectId`; the reduced public view
has `project.id` instead. The relay read only `projectId`, so it would have
refused every report and held production. It now reads either.

### What only a live test proves

These stay unproven until Daan's live run:

- That Vercel makes the check run itself. The journey covers both cases.
- That a real GitHub OIDC token carries the claims the relay reads
  (`repository_id`, `repository_owner_id`, `workflow_ref`, `event_name`,
  `run_id`) in the shapes GitHub documents.
- That the install token is accepted on each call: the scopes, and whether
  Vercel answers the owner's deployment view.
- Behaviour the spec does not describe: limits such as `timeout`'s maximum,
  error messages, rate limits, and anything Vercel refuses beyond its schema,
  the way it refused the git-provider check.
- The workflow itself on a real runner: the dispatch payload, the OIDC token
  request, `jq` and `curl`.

## Legal

- [Terms of use](https://docs.penthera.org/vercel/terms)
- [Privacy notice](https://docs.penthera.org/vercel/privacy)
