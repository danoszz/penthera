# DRAFT: Terms of use for the Penthera Vercel integration

> **DRAFT, not approved, not published.** For the maintainer's review, and a
> legal reader of his choice, before anything goes live. Placeholders are in
> [brackets].

Last updated: [date]

## 1. Who provides it

The Penthera Vercel integration ("the integration") is provided by
Daan van der Zwaag, [business address], [contact email] ("we"). Penthera's code
is open source under the MIT license. These terms cover only the hosted
integration service, not the code.

Vercel Inc. is not a party to these terms.

## 2. What it does

The integration connects your Vercel projects to Penthera's GitHub Action. It:

- registers a Deployment Check on the projects you pick,
- gives you a workflow file to commit to your own repository, and
- keeps an encrypted Vercel access token for your installation.

Scans run in your own GitHub Actions. We do not run scans, and scan results
never reach us.

## 3. Price

It is free. We do not charge for it.

## 4. Your use

Use it only on projects you own or are allowed to test. Penthera's scan is
passive: it reads what a browser would load from your own deployment.

## 5. No guarantee

The integration and the scan are provided "as is", without warranty. A passing
check is not a penetration test and does not prove your app is secure.

To the extent the law allows, we are not liable for indirect or consequential
loss, and our total liability is limited to [amount]. Nothing in these terms
limits liability that Dutch or EU law does not allow to be limited, including
for intent or gross negligence, or your rights as a consumer.

A check that fails or times out can hold a production promotion. You can use
Vercel's Force Promote, remove the check, or uninstall at any time.

## 6. Ending it

You can stop at any time by uninstalling the integration in Vercel. We then
delete the stored token. Remove the Penthera check from your projects too, as
described on the Configure page.

We may stop the service with at least [30] days' notice on [where notice is
given]. We may suspend it at once to stop abuse or a security problem.

## 7. Support

Support is by email at [support address]. We aim to answer within [N] business
days. [Check this target against Vercel's support terms before submitting.]

## 8. Changes

We date every version of these terms. We give [30] days' notice of a material
change on [where].

## 9. Law

Dutch law applies. The courts of [city], the Netherlands, have jurisdiction,
unless consumer law gives you the right to go to the courts where you live.
