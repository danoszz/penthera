---
nav: Website security check
title: Free website security check: headers, TLS, cookies and leaked keys
description: Check your own site's security headers, TLS, cookies, keys in its JavaScript, vulnerable libraries, SPF, DMARC and security.txt. Free, passive, nothing stored.
---
# Free website security check

> For "is my website's security set up right?"

penthera.org checks a public site you own and scores it out of 100. It loads what one browser visit loads, in about 8 seconds. It sends no attacks and stores nothing. Then fix what it finds with Prompt to fix, or run Penthera on your code.

{{CTA}}

## What it checks

- **Connection.** HTTPS, the TLS version, whether the certificate expires within 14 days, and Strict-Transport-Security with a max-age of at least 180 days.
- **Security headers.** Content-Security-Policy and whether it allows inline scripts, framing protection (`frame-ancestors` or `X-Frame-Options`), `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`. CORS too, when the site sends it. These are the same header rules as the command-line scan.
- **Cookies.** Whether every cookie the page sets has `Secure`, `HttpOnly` and `SameSite`.
- **Secrets in JavaScript.** The page and up to 8 of its own scripts, checked with Penthera's {{N_SECRETS}} secret patterns: AI provider keys, Stripe secret keys, AWS and GitHub tokens, private keys. A match is shown redacted, as a short prefix and its length.
- **Vulnerable libraries.** Script names and version banners, compared with the Retire.js data that ships with Penthera. Only a library and version that data covers is called vulnerable.
- **What the page loads.** `http://` content on an `https://` page, third-party files without Subresource Integrity, and scripts that point to a source map.
- **What the server gives away.** A server or framework that names its version, and published advisories for the PHP, nginx, Apache, Node.js, Python or OpenSSL version it names.
- **Email and DNS.** SPF, DMARC and CAA records. Without SPF and DMARC, anyone can send mail that claims to come from your domain.
- **Security contact.** `/.well-known/security.txt`, and whether its `Expires` date has passed.

Each check has a weight, and the score is the share of the weight that passed. A failed check rated critical caps the score at 40; one rated high caps it at 69.

## What you get

Every failed check shows its evidence, a fix and a `curl` command to verify the fix yourself. **Prompt to fix** copies the failed checks as one prompt for your coding agent, with the order to fix them in. The report stays in your browser tab.

## What it sends to your site

1. `GET /robots.txt`. A site can opt out there.
2. `GET` the address you entered, following redirects.
3. `GET` up to 14 scripts and stylesheets the page references: 8 from your site, 6 from elsewhere.
4. `GET /.well-known/security.txt`.
5. Public DNS lookups for SPF, DMARC and CAA.

That is at most 20 requests, as `Penthera-QuickCheck/1`. It does not guess paths, log in, submit forms or send payloads. penthera.org stores nothing about a check: not the address, not the result, not who ran it.

## What it cannot see

- Pages other than the one you enter, and anything behind a login.
- Your API's authorization, your database rules and your business logic.
- Your source code and the dependencies that are not in the page.

A good score is not a guarantee, and this is not a penetration test. It finds known classes of problems from the outside. A finding can be wrong; the evidence is there so you can check it.

## Go deeper on your own machine

The command-line tool is free and open source (MIT). It runs on your machine, under your responsibility, against targets you own:

```
npx penthera https://your-site.com
npx penthera --repo .
npx penthera deps
```

The first runs a standard scan of the running app, which adds exposed files, debug pages and API specs. The second reads your code for secrets, risky code and runtime versions. The third shows what each dependency can do. None of them sends anything to penthera.org.

## Only your own site

Check a site you own, or one you have written permission to test. The [terms](/terms) say what that means and how a site owner can opt out.

{{CTA}}
