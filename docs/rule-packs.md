---
title: "Rule packs"
sidebarTitle: "Rule packs"
description: "A rule pack is a directory of detection data that Penthera verifies before it uses a single rule."
---

> **Pro.** For "how do I tune the rules?"

A rule pack is a directory of detection data that Penthera verifies before it
uses a single rule. This is how new knowledge about attacks (a new key format,
a worm's package list, a fresh prompt-injection trick) reaches Penthera without
Penthera ever fetching anything at run time.

```bash
penthera rules list                         # packs in effect
penthera rules verify ./my-pack             # signature, hashes, schema, ReDoS guard
penthera deps --rules ./my-pack             # add a pack to a scan (repeatable)
penthera --repo . --rules ./my-pack
```

## Trust model

Packs reach Penthera in two ways only:

1. **Bundled in a release.** `lib/rules/<name>/` ships inside the npm package.
   Releases are staged on npm by CI and go live only when the maintainer
   approves them with 2FA (see `.github/workflows/publish.yml`). The publish
   workflow runs `npm run rules:check`, which refuses to stage a release with a
   bundled pack that is not signed by a key in `lib/rules/allowed_signers`. So a
   rule change has to pass through the maintainer's signing key, which never
   enters CI, as well as through the 2FA approval.
2. **By path, from you.** `--rules <dir>` loads a pack from a directory you
   name. It must be signed by a key in `lib/rules/allowed_signers` or in a file
   you pass with `--rules-signers <file>`.

There is no third way. Penthera has no rule server, no update command, no
background refresh and no URL it pulls rules from. The rule-pack code
(`lib/rules/`) has no network code at all, and a test asserts that.

### Why no runtime fetching

A rule feed is a path from somebody else's server into a tool that runs with
your network access, and often with your credentials and your source code. Rule
updates are exactly the kind of channel attackers go after: compromise the feed
and every scanner that trusts it runs your rules, or reports your malware as
clean. Securing such a channel takes signed metadata, key rotation,
freshness guarantees and trust delegation (TUF, in-toto) [samuel2010survivable,
torresarias2019intoto]. Penthera already has a channel with those properties
for its code: the release. Shipping rules through that same channel adds no new
way in, and the rules you ran are the rules in the version you installed.

The cost is latency: a new IOC (indicator of compromise) reaches you when you
upgrade, not within the hour. For the campaigns these packs target, an IOC is most useful in the days
and weeks after disclosure, while compromised versions sit in lockfiles and
npm caches. If you need something faster, write a pack yourself, sign it with
your own key, and pass it with `--rules` and `--rules-signers`. Penthera never
decides on your behalf to trust a new source.

### What verification checks

In order, and a failure refuses the whole pack (there is no partial load):

1. **Signature.** `pack.json.sig` is an OpenSSH signature (`ssh-keygen -Y
   sign`, namespace `penthera-rules`) over the exact bytes of `pack.json`. The
   signing key must be in an allowed_signers file, with `namespaces`
   (if set) including `penthera-rules` and `valid-after`/`valid-before`
   respected. Penthera verifies it in Node (ed25519 or RSA ≥ 2048), so it needs
   no `ssh-keygen` at run time.
2. **File hashes.** Every rule file's SHA-256 must match `pack.json`. Rule files
   must be plain names in the pack directory: no paths, no `..`, no symlinks,
   size-capped.
3. **Schema.** Every rule is validated against its kind (below). Strings that
   reach your terminal or report may not contain control characters, ANSI
   escapes or bidi overrides. Template paths must stay on the scan target.
   `min_penthera` must not be newer than your Penthera.
4. **ReDoS guard.** Every regex must pass `lib/rules/regex-guard.js` (below).

An unsigned pack, or one whose signature does not verify against a trusted
key, is refused unless you pass `--allow-unsigned-rules`. That flag prints a
warning on every run. It skips only the signature check. Hash, schema and ReDoS
failures are refused with or without it.

Bundled packs are hash-checked and schema-checked on every start. A failure
there means the installation is damaged, and Penthera stops rather than run
with half its rules.

## Format

```
my-pack/
  pack.json        index: name, version, created_at, min_penthera, rules[]
  pack.json.sig    ssh-keygen -Y sign -n penthera-rules
  secrets.json     rule files, one kind each
  packages.json
```

`pack.json` (written by `scripts/rules/build-pack.mjs`, never by hand):

```json
{
  "schema": 1,
  "name": "ioc-2025-2026",
  "version": "1.0.0",
  "created_at": "2026-10-19T14:45:12Z",
  "min_penthera": "1.2.0",
  "description": "…",
  "rules": [
    { "file": "packages.json", "kind": "ioc-package", "sha256": "…" }
  ]
}
```

A rule file is `{ "kind": "<kind>", "rules": [ … ] }`. Rules are data only:
regexes, string lists, IOC lists. A pack cannot contain code, and nothing in a
pack is ever evaluated.

Every rule carries:

| Field | Meaning |
|---|---|
| `id` | Unique within the pack, `[a-z0-9._-]` |
| `source` | `https` URL of the advisory, paper or write-up the rule comes from |
| `date` | `YYYY-MM-DD`, when that source published it |
| `confidence` | `confirmed`, `likely` or `potential`, as in findings |
| `references` | Optional keys into [references.bib](https://github.com/danoszz/penthera/blob/main/docs/references.bib) |
| `description` | Optional, shown in finding descriptions |

### Kinds

| Kind | Engine | Fields |
|---|---|---|
| `secret` | `lib/whitebox/secrets.js` (`--repo`, agents, fix) | `name`, `pattern`, `flags`, `severity`, `skip_placeholders` |
| `agent-instruction` | `lib/agents/hidden-content.js`: instructions hidden in comments and decoded blobs | `pattern`, `flags` |
| `agent-exec` | `lib/agents/`: remote-code-execution shapes in skills, hooks and MCP commands | `label`, `pattern`, `flags` |
| `ioc-package` | `penthera deps`: known-malicious versions, matched against the lockfile | `campaign`, `packages: [{ name, versions }]`, `severity` |
| `ioc-pypi-package` | `penthera deps` (Python): known-malicious PyPI versions, matched against the lockfile | `campaign`, `packages: [{ name, versions }]` (PEP 503 normalized names, exact PEP 440 versions or `*`), `severity` |
| `ioc-host` | `penthera deps`: exfiltration endpoints in package code | `campaign`, `hosts` (attacker domains), `urls` (exact endpoints on shared services) |
| `ioc-file` | `penthera deps`: files a campaign drops into packages | `campaign`, `files: [{ path, sha256? }]` |
| `typosquat-target` | `lib/deps/typosquat.js`: names to protect from look-alikes | `names` |
| `nuclei-template` | `lib/templates.js`: the Nuclei subset Penthera runs (status, word, regex matchers) | `template` |
| `runtime-advisory` | `lib/advisories/`: affected versions of a runtime or server (`--repo` pins, URL banners) | `product`, `title`, `severity`, `cves`, `ghsa`, `cvss`, `kev` (date added to CISA KEV), `condition`, `fixed: [{ branch, version, introduced? }]` |
| `runtime-eol` | `lib/advisories/`: release lines past their vendor's end of support | `product`, `branches: [{ branch, eol }]` |

`runtime-advisory` and `runtime-eol` name a `product` from a fixed list (`php`,
`apache-httpd`, `nginx`, `nodejs`, `python`, `openssl`, `mongodb`; detection for each is
code in `lib/advisories/products.js`). A `branch` is a release line as that
vendor numbers them: `8.3` for PHP, `22` for Node.js, `1.1.1` or `3.0` for
OpenSSL. Every `fixed` version must be an exact upstream release on its line.
An advisory with a `condition` (an OS, a SAPI, a module a banner cannot show)
never produces more than `potential`. A `runtime-eol` line counts as ended
only when its `eol` date is on or before the rule's own `date`, so the result
depends on the pack, never on the clock of the machine that runs the scan. See
the methodology's [runtime advisories](METHODOLOGY.md#runtime-advisories)
section for how evidence and verdicts work.

Rules from packs run after the built-in rules, so a pack can add detections but
cannot shadow or reorder the built-in ones. IOC matching is literal (string
equality and `indexOf`), so IOC lists cannot be made slow. `ioc-package` matches
the lockfile, so it reports a bad version even when it is not installed.

## The ReDoS guard

Packs scan hostile input: dependency source, agent configs, HTTP responses. A
pack with a regex that backtracks exponentially could hang every scan that
loads it. V8's regex engine backtracks, and its linear-time mode refuses
ordinary bounded repeats like `{64}`, so `lib/rules/regex-guard.js` checks the
pattern's structure when the pack loads and refuses:

1. patterns longer than 512 characters, or with flags other than `imsu`;
2. backreferences and lookaround;
3. nested quantifiers: `(a+)+`, `(\w*\s?)*`;
4. alternation under an unbounded quantifier: `(a|aa)+`;
5. bounded repeats above 256;
6. an unbounded quantifier that every start position can reach and rescan
   (`\s*x`, `[a-z]+@`, `x[^\n]*\|` on `xxxx…`);
7. chains of quantifiers over overlapping characters (`.*b.*`, `\s+\S*\s*`),
   unless all of them are bounded and their product stays under 1,024.

The guard is conservative on purpose and refuses some safe patterns. Rewrite those
with a mandatory literal first, or with bounded windows such as
`[^\n]{0,80}`. Rule 6 took its current form after seeded fuzzing found
quadratic patterns that the narrower "no leading quantifier" version let
through. The fuzz test
(`tests/rule-packs.test.js`) generates random patterns and requires everything
the guard accepts to finish in under 250 ms on 10 KB of input built to make it
backtrack. In practice they finish in milliseconds. Quadratic patterns take
seconds. Regexes from packs added with `--rules` also see at most 1 MB of input
per match.

The older, narrower check for `--templates` YAML (v1.1.1) moved into the same
module as `hasNestedQuantifier()`. It used to be a regex, which CodeQL flagged as
polynomial on the pattern string it inspects. It is now a linear scan that
refuses everything the old regex refused, plus nesting it missed (`((a+))+`), so
existing user templates keep working.

## Bundled packs

| Pack | Contents |
|---|---|
| `core` | Detections that were hardcoded before rule packs, moved here so the built-in rules go through the same loader: 12 AI-provider key formats, the credential-path hidden-instruction pattern, two process-substitution exec patterns, and the `.env` exposure template. Engines splice them back in at their old positions, and a test compares the result with a snapshot of the old built-ins. |
| `advisories` | Runtime and server advisories and end-of-life release lines. The PHP security release of 21 October 2026 (CVE-2026-109618 and CVE-2026-109619, fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12), and the Node.js security release of the same day (CVE-2026-111497, a Brotli decoder RCE, and three TLS certificate hostname bypasses, fixed in 22.23.4, 24.22.1 and 26.12.1). Worked examples: CVE-2024-4577 and its bypass CVE-2024-8926 (PHP-CGI on Windows, from the php-src advisories), and CVE-2021-41773 with CVE-2021-42013 (Apache HTTP Server 2.4.49 and 2.4.50). End-of-life lines for PHP, Node.js, Python, MongoDB, nginx, Apache HTTP Server and OpenSSL, from each vendor's support page. Every rule cites the vendor page it was copied from. |
| `ioc-2025-2026` | Named npm campaigns: **s1ngularity** (nx and @nx/* versions, from GHSA-cxm3-wv7p-598c), **Shai-Hulud** (484 package versions from StepSecurity's table, the webhook.site exfil URL, and `bundle.js` by SHA-256), **Shai-Hulud 2.0** (1,089 package versions from Wiz Research's CSV, plus `setup_bun.js` and `bun_environment.js`), and **postmark-mcp** 1.0.16 to 1.0.18 with its exfil domain. Every rule cites the list it came from. We dropped entries we could not check against a primary source. |
| `ioc-pypi-2026` | Known-malicious PyPI versions, dropped files and endpoints, for `penthera deps` on Python projects. They match whether or not the package is installed. |

## Writing and signing a pack

```bash
mkdir my-pack && $EDITOR my-pack/secrets.json   # { "kind": "secret", "rules": [ … ] }
npm run rules:build -- my-pack --name my-pack --version 1.0.0
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n penthera-rules my-pack/pack.json
echo "me@example.com namespaces=\"penthera-rules\" $(cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub)" > my-signers
penthera rules verify my-pack --rules-signers my-signers
penthera deps --rules my-pack --rules-signers my-signers
```

In a checkout of Penthera, `npm run rules:build` runs the script; from an
installed copy it is `node "$(npm root -g)/penthera/scripts/rules/build-pack.mjs"`.
`build-pack.mjs` hashes the rule files, writes `pack.json`, validates the
result with the loader's own code, and deletes a `pack.json.sig` that no longer
matches. `created_at` only changes when a rule file changed.

## Signing a release (maintainer)

Bundled packs must be signed before a release can be staged:

1. Review the change: `git diff lib/rules/`. The signature vouches for every
   rule in the pack.
2. Sign each changed pack locally, never in CI:
   `scripts/rules/sign-pack.sh lib/rules/<name> [~/.ssh/key]`. The script rebuilds
   `pack.json`, signs it with `ssh-keygen -Y sign -n penthera-rules`, and runs
   `penthera rules verify`.
3. `npm run rules:check` must pass. The publish workflow runs it before staging.
4. Commit `pack.json.sig` with the release.

The signing key's public half lives in `lib/rules/allowed_signers`. Changing
that file changes Penthera's trust root, and gets the same review as a change
to the verifier. To rotate keys, add the new key, re-sign the bundled packs, and
remove the old key in a later release. Packs other people signed with the old
key keep working until it is removed. A hardware-backed key (`sk-ssh-ed25519`)
is not supported by the verifier yet. Use ed25519 or RSA.
