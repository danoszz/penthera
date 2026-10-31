---
nav: Lovable, Bolt, Base44
title: Is my Lovable, Bolt or Base44 app safe? A free security check
description: Check your Lovable, Bolt or Base44 app for API keys in its JavaScript, missing security headers, weak cookies and vulnerable libraries. Free and passive.
---
# Is my Lovable, Bolt or Base44 app safe?

> For "I built an app with an AI app builder. Is it safe to share?"

Paste your published app's address into penthera.org's free check: your own domain, or the address your builder gave you. In about 8 seconds you get a score out of 100, the evidence for each problem, and a prompt you can paste back into your builder's chat to fix it.

{{CTA}}

## What the check finds in a builder app

An app made with Lovable, Bolt or Base44 runs in the browser. Everything the browser downloads, anyone can read. The check looks at that from the outside:

- **Secret keys in the JavaScript.** The page and up to 8 of its own scripts, checked with Penthera's {{N_SECRETS}} secret patterns, such as OpenAI and Anthropic keys, Stripe secret keys, and AWS and GitHub tokens. A key in the bundle is a key anyone can use, and an AI key can run up your bill. The fix is to revoke the key, then call that service from a server function.
- **Google and Firebase keys.** These are meant to be in a web page, so they are a note, not a failure. The check reminds you to restrict them to your domains.
- **Security headers.** Content-Security-Policy, framing protection and the other headers that tell browsers to block common attacks. Your host decides some of them; the report shows which ones are missing.
- **Cookies** without `Secure`, `HttpOnly` or `SameSite`.
- **JavaScript libraries** with known vulnerabilities, from the Retire.js data that ships with Penthera.
- **Email records.** SPF and DMARC on your own domain, so nobody can send mail as you.

The [website security check](/website-security-check) page lists every check and every request it makes.

## What it cannot see

Most serious problems in builder apps are in the database and the backend, and those are not in the page:

- **Database access rules.** Many builder apps use Supabase. Its public (anon) key is meant to be in the page; it needs row level security on for every table, with the right policies. The check has no Supabase rule and cannot read your policies. Open your Supabase dashboard and check each table.
- **Who can see what.** Whether one user can read another user's data depends on your backend and your rules, not on the page.
- **Server functions and other pages.** It checks one page and the files it loads. It does not log in.

A good score means the outside is in order. It is not a guarantee, and it is not a penetration test.

## Check the code too

If your builder syncs or exports the code to GitHub, clone it and run Penthera on your own machine. It is free and open source (MIT), and your code stays on your machine:

```
npx penthera --repo .
npx penthera deps
```

The first finds keys committed to the code, risky code and the API routes. The second shows what each dependency can do and flags known-malicious packages and lookalike names.

## Fix it with your builder

When the check finds a problem, **Prompt to fix** copies the failed checks as one prompt, with the evidence, the fix and a command to verify each one. Paste it into your builder's chat, publish, and run the check again.

## Only your own app

Check an app you own, or one you have written permission to test. The check is passive and stores nothing. The [terms](/terms) have the details.

{{CTA}}
