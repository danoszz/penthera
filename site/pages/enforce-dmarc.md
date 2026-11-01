---
nav: Enforce DMARC
title: How to enforce DMARC: from p=none to p=reject without losing mail
description: Move DMARC from p=none to p=quarantine and p=reject in four steps, without blocking your own mail. Check the result with one command.
---
# How to enforce DMARC

> For "how do I move DMARC from p=none to p=reject without losing real mail?"

A DMARC record with `p=none` only watches. It tells receivers to send you reports, and it blocks nothing. Anyone can still send mail in your domain's name. Enforcing means `p=quarantine`, which sends failing mail to spam, or `p=reject`, which refuses it.

You change one DNS record, three times, over a few weeks. The care goes into finding every service that sends mail as you before you enforce.

## 1. List what sends mail as you

Write down everything that sends from your domain: your mail host, password resets and receipts from your app, newsletters, invoices and the support desk.

Each one must pass DMARC. That takes SPF or DKIM, and the domain that passes has to match the domain in the From address. This match is called alignment. Set up DKIM on each sender if you can: forwarding often breaks SPF, while a DKIM signature usually survives it.

## 2. Publish p=none and read the reports

Add a TXT record at `_dmarc.your-domain.com`. A domain has one DMARC record, so edit the one you have instead of adding a second.

```
v=DMARC1; p=none; rua=mailto:dmarc@your-domain.com
```

Receivers now send a daily XML report to that address, listing who sent mail as you and whether it passed. A mailbox on another domain has to agree to receive these reports, so use one on your own domain to keep it simple.

Read the reports for at least two weeks, longer if something only sends once a month, such as invoices. Fix each real sender that fails. Ignore the rest: they are the mail you want to stop.

## 3. Move to p=quarantine

When your real senders pass, change the record:

```
v=DMARC1; p=quarantine; rua=mailto:dmarc@your-domain.com
```

Failing mail now lands in spam, so a sender you missed can still be found and fixed. Keep reading the reports for a week or two, and ask the people who receive your invoices and resets whether anything went missing.

## 4. Move to p=reject

```
v=DMARC1; p=reject; rua=mailto:dmarc@your-domain.com
```

Receivers can now refuse mail that fails. Subdomains follow `p` unless you set `sp`. Keep the `rua` address and read the reports now and then, because each new tool that sends mail starts out failing.

## If the domain sends no mail

Skip the wait. Publish two TXT records that say so, one at the domain and one at `_dmarc`:

```
v=spf1 -all
v=DMARC1; p=reject
```

## What it cannot see

Penthera reads your public DNS records. It does not see your mail.

- It can't tell whether your real mail passes. Only the reports show that.
- It reads `p`. It doesn't read `sp`, or check that a `rua` address works.
- It can't list your DKIM keys, because each provider names them differently. If your SPF or DMARC needs work and the domain has MX records, it reminds you to check DKIM.

A clean result is not a guarantee that nobody can spoof your domain, and receivers decide for themselves what to do with failing mail.

## Check it

```
dig +short TXT _dmarc.your-domain.com
npx penthera https://your-domain.com
```

`dig` prints the record the world sees. DNS changes can take a while to spread. `npx penthera` reports a missing record as medium and `p=none` as low. At `p=quarantine` or `p=reject` the DMARC finding goes away. It checks SPF in the same run.

Or use the check on this site, which also reads your headers, TLS and cookies, and looks for keys in your JavaScript with {{N_SECRETS}} secret patterns. Check only a domain you own, as the [terms](/terms) say.

{{CTA}}
