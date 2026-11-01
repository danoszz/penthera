---
nav: CSP for scripts
title: A CSP that controls scripts: how to tell, and how to fix yours
description: Your CSP may do nothing. Learn which policies stop injected scripts, how to remove unsafe-inline without breaking your site, and how to check.
---
# A CSP that controls scripts

> For "my site has a Content-Security-Policy. Does it stop injected scripts?"

Your CSP may do nothing. A Content-Security-Policy header can be present and still let an injected script run, because the part that matters is the rule for scripts. The browser reads `script-src`, and falls back to `default-src` when there isn't one. With neither, the policy leaves scripts alone.

## Does yours control scripts?

These don't control scripts:

- `frame-ancestors 'none'` only says who can frame the page.
- `upgrade-insecure-requests` only rewrites `http` links.
- `default-src *` lets any host serve a script.
- `script-src https:` lets any HTTPS host serve a script.
- `script-src 'self' 'unsafe-inline'` lets an injected inline script run.

This one does in part:

- `script-src 'self' 'unsafe-eval'` loads scripts only from your site, but they can run strings as code.

These do:

- `script-src 'self'` runs only your own files.
- `script-src 'nonce-abc123' 'strict-dynamic'` runs only scripts carrying this response's nonce, and the scripts they load.

A policy sent as `Content-Security-Policy-Report-Only` controls nothing either. It only reports. Be careful with a shared host in `script-src`, such as a public CDN: if anyone can publish files there, an attacker can load one.

## Fix it in four steps

### 1. See what the browser would block

Send your target policy as a report, so nothing breaks:

```
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'
```

Open your main pages and watch the browser console. Each line it prints is something the policy would have blocked.

### 2. Deal with inline scripts

These are why most sites keep `'unsafe-inline'`. You have three ways out:

- **Move the script to a file.** That is enough for code you wrote yourself. This includes `onclick=` attributes, which a policy without `'unsafe-inline'` blocks.
- **Use a nonce on server-rendered pages.** Generate a new random value for each response, and put it in both the header and each `<script nonce="...">`. Never reuse one. In Next.js, this means generating it in middleware, and those pages can no longer be served as static files.
- **Use a hash on static pages.** Put the SHA-256 of the script's text in `script-src`. It works with no server, and it changes each time the script changes.

### 3. Add what you really need

Add each third-party script by its exact host, such as your analytics provider. With a nonce, add `'strict-dynamic'`, and scripts you trust can load what they need.

### 4. Enforce it

When the console stays quiet, rename the header to `Content-Security-Policy`:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'
```

## What it cannot see

Today's checks catch the worst cases, so read the header yourself with the rules above.

- `npx penthera <url>` flags a policy that names no script sources, or lets any host run them with `*`, `http:` or `https:`. It doesn't judge the rest of the policy.
- The check on this site does the same, and also flags `'unsafe-inline'` and `'unsafe-eval'` for scripts.
- Both read one response from one page. Other pages can send other headers.
- `penthera fix` adds a starter CSP that keeps `'unsafe-inline'`, so frameworks don't break. It's a start. Finish it with the steps above.

A strict CSP is not a guarantee. It limits what an injected script can do, and the bug that let it in still needs fixing. A policy can also break a page, so test it first.

## Check it

```
curl -sI https://your-domain.com | grep -i content-security-policy
npx penthera https://your-domain.com
```

`curl` prints the header the world sees. It controls scripts if it's named `content-security-policy`, has `script-src` or `default-src`, and has no `'unsafe-inline'`, `*` or bare `https:` there. `npx penthera` reports a missing header, and runs the rest of a standard scan.

Or use the check on this site, which also reads your TLS, cookies and DNS, and looks for keys in your JavaScript with {{N_SECRETS}} secret patterns. Check only a site you own, as the [terms](/terms) say.

{{CTA}}
