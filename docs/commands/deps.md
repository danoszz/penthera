---
title: "Dependency risk: penthera deps"
sidebarTitle: "Dependencies"
description: "A lockfile change is code you did not write, about to run with your app's access to files, network, environment and CI secrets."
---

> **Starter.** For "is this package safe to add?"

## Dependency risk: what can your packages do?

A lockfile change is code you did not write, about to run with your app's access
to files, network, environment and CI secrets. `penthera deps` reads
`package-lock.json`, statically scans every installed package, and tells you
what each one *can do*, and which packages are new or gained capabilities in an
upgrade. It does not check known vulnerabilities (CVEs), and every run says so.
`penthera --repo . --giants` runs osv-scanner for those, if you have it installed.
An install script over 4 KB reads as risky, and a code file that is almost all
blank lines is skipped and named, so that package reads as unscanned.

```bash
penthera deps                          # every package in node_modules
penthera deps --base origin/main       # capability diff vs the lockfile on main
penthera deps --diff ../base-checkout  # diff vs another installed tree (or an old package-lock.json)
penthera deps --pr-comment deps.md     # short Markdown diff for a PR comment
```

```
  ▲ net-helper 1.0.0 → 1.1.0  + network, whole environment
      node_modules/net-helper/index.js:3  const https = require('https');
      node_modules/net-helper/index.js:5  const body = JSON.stringify(process.env);
```

| Capability | Detected from |
|---|---|
| Install scripts | `preinstall` / `install` / `postinstall`, and `binding.gyp` (npm runs `node-gyp` implicitly). Flagged as risky when the hook pipes a download to a shell, runs a file with network or decoding code, runs a file whose command strings download or send data out (`curl`, a DNS lookup of a computed name, `/dev/tcp`), or runs a file that starts such a file (`spawn("node", [file])`, `fork(file)`; one hop). Starting a shell on its own does not count: build hooks do that |
| Code it downloads | A network call whose response reaches `eval`, `Function` or `vm` a few lines later (high, no install hook needed). A module loader that tags the fetched script with `sourceURL` is not counted |
| Entry file that sends data | A file the package loads (`main`, `module`, `exports`) that runs a recon command (`whoami`, `ls`, `$(...)`) and sends the output (medium) |
| Dependencies from a URL | A `dependencies` or `optionalDependencies` entry that is an `http(s)://` tarball on a host other than the npm registry, GitHub, GitLab or Bitbucket (medium) |
| Shell, network, dynamic code | `child_process`; `http`/`https`/`net`/`dgram`/`tls`/`http2`, `fetch`, `WebSocket`; `eval`, `new Function`, `vm` |
| Environment | `process.env` (or `process["env"]`) reads, and bulk access (`JSON.stringify(process.env)`, enumeration, `{ ...process.env }` passed to a call). Serializing the environment next to network code is reported as likely exfiltration |
| Files, modules, native | Writes near home-directory or system paths; computed `require()`/`import()`; `.node` addons and `binding.gyp` |
| Obfuscation | Obfuscator identifiers (`_0x…`), `\x`-escape density, encoded blobs that are decoded and run (embedded WebAssembly and ANSI color codes are recognized and ignored) |
| Attack indicators | Writes to `~/.claude`, `~/.cursor`, `.mcp.json` or the Claude Desktop config; running the `claude`, `gemini` or `q` CLIs (the s1ngularity pattern); GitHub token harvesting |
| Typosquats | Edit distance, separator and suffix tricks against ~7,800 popular npm names, vendored in the package and refreshed at release time |
| Known-bad versions | Package versions, exfil endpoints and dropped files from named campaigns (s1ngularity, Shai-Hulud, Shai-Hulud 2.0, postmark-mcp), from the signed [rule packs](../rule-packs.md) that ship with each release. Matched against the lockfile, so a bad version is reported even when it is not installed |

Every capability carries `file:line` evidence. It is a regex-and-tokenizer pass,
not a full parser: deterministic, never executes package code, and fast enough
for every PR (under 1 s for Penthera's own 145 packages, 5 to 16 s for real app
trees of 500 to 1,700 packages). A capability is what code
*can* do, not proof that it is malicious; the findings carry confidence
labels (`potential` for obfuscation and typosquats).

**Only installed code is read.** A package that is in the lockfile but not in
`node_modules` (or `.venv`) or npm's cache is listed as not read, never as
clean. On a fresh clone that is every package:

```
  Scanned    0 · 61 not installed or cached
  Not read   0 of 61 packages installed or cached, so no package code was read.
             To check them, run `npm ci --ignore-scripts` (it installs without running package code), then run this again.
```

The lockfile checks still run: known-bad versions on every entry, typosquat names on your direct dependencies.

**Offline by default.** Old versions for the diff come from the base tree's
`node_modules` or from npm's local cache (`~/.npm/_cacache`), looked up by the
lockfile's integrity hash and verified byte for byte. `--online` is the only
network use: it asks the npm registry for publish dates, publisher changes and
deprecations, and fetches old tarballs the cache does not have (verified the
same way). To comment the capability diff on every PR that changes the
lockfile, use the GitHub Action below.

#A package Penthera can't read in full never reads as clean. A file full of blank
lines is skipped and the package gets a high finding, "could not be scanned", which
exits 1. A line over about 190 KB says it wasn't read in full.

## npm and Python

The same command reads Python projects: `uv.lock`, `poetry.lock`, `pdm.lock`,
`Pipfile.lock` or `requirements*.txt` (pinned and `--hash` lines), and the
installed `.venv` / `venv` (or `--venv <path>`) through
`site-packages/*.dist-info` `RECORD` files, without running pip or Python. A
repo with both a `package-lock.json` and Python inputs gets one combined report.

A lockfile or requirements file that is not a regular file inside the project
(a FIFO, a device, a link out of the project, or over the 64 MiB size cap) is
not read. The report lists it as an info finding, `File not read: <file>`, and
the rest of the scan goes on. An `-r` include like that skips only the include:
the other pins in the file that has it are still checked. Either way the scan
is incomplete, so it exits 2, even when nothing else was found. A file Penthera
could not read never passes CI as an empty tree. In a virtualenv, a package
whose `METADATA`, `PKG-INFO` or `RECORD` is not read (over 16 MiB, a FIFO, a
device, no permission) stays in the report, named from its `.dist-info` or
`.egg-info` folder and marked as not scanned, and the run exits 2. So does a
startup `.pth` file in `site-packages` that is not read. A package with a code
file Penthera could not read is not scanned, never clean.

```bash
penthera deps                          # uv.lock + .venv
penthera deps --venv ~/.venvs/app      # a virtualenv somewhere else (no lockfile needed)
penthera deps --base origin/main       # capability diff vs the Python lockfile on main
```

Capabilities and evidence are the same as for npm (`subprocess`/`os.system`,
`socket`/`requests`/`httpx`/`aiohttp`, `os.environ` bulk access,
`eval`/`exec`/`compile`, computed `__import__`, native `.so`/`.pyd`, AI-agent
indicators), plus what is specific to Python: `setup.py` custom commands
(install-time code; risky when it downloads and runs: a shell next to network
code, a download or send command, a recon command like `whoami`, `pip install`
of more packages, or decoded code, in `setup.py` or in the helper modules it
imports, three levels deep, including packages under `src/`. Running git, a
compiler or a build tool, or `exec` of a local version file, is not risky),
code that runs on import (module-level code, or a local function it calls,
that makes a network call or runs a download or send command: medium; tests,
scripts, examples and files outside a package do not count), a chat bot token
or a webhook URL with its key in a file with network code (high), a file that
downloads a program and starts it or makes it executable within 15 lines, or
runs a response with `exec` (high, "runs code it downloads"), statements
hidden after 150 or more spaces, and `exec` of an encoded literal through a
renamed decoder, `.pth` files with `import` lines and a shipped
`sitecustomize.py` or `usercustomize.py` (they run on every interpreter start,
so installing the package is enough to run them: medium, high when the code
they load is risky), including ones a wheel places at the site-packages root
from `<name>-<version>.data/purelib/` or `platlib/`, as the malicious litellm
1.107.0 did, unpickling, `exec` of a
base64/zlib-decoded payload, installed files that no longer match their
`RECORD` hash, and `.pth` files no distribution owns. Old versions for the diff
come from pip's HTTP cache (matched by the lockfile's sha256) or uv's cache
(by recorded hash), otherwise they are marked "not compared". Typosquats are
checked against the top 8,000 PyPI projects, PEP 503 normalized. Known-malicious
PyPI versions, dropped files and endpoints come from the `ioc-pypi-2026` rule
pack and match whether or not the package is installed.
`--online` registry checks are npm-only for now.

### License policy

```bash
penthera deps --license-policy permissive        # or weak-copyleft-ok, no-agpl
penthera deps --license-policy legal/policy.json # a file with a "licenses" section
```

Without the flag, `penthera deps` applies the `licenses` section of
`penthera.policy.json` when there is one. A policy file that is not a regular
file inside the project, or is over 1 MiB, is not read. A policy can tighten
the gate, so this never passes quietly: `deps` and `--giants` check with the
default policy and exit 2 as incomplete, `install` stops, and AI mode does not
run.

An installed package is read in full. A link inside the package folder is
followed and read. A link out of the package, a link to nothing, or a FIFO or
device in the folder makes the package "could not be scanned", never clean.

```json
{
  "licenses": {
    "preset": "permissive",
    "allow": ["Python-2.0"],
    "deny": ["WTFPL"],
    "allowPackages": ["@acme/*", "sharp@0.33.5"],
    "unknown": "warn"
  }
}
```

| Preset | Allows |
|---|---|
| `permissive` | MIT, ISC, BSD, Apache-2.0, 0BSD, Unlicense, CC0, Zlib, BlueOak and similar. Everything else breaches |
| `weak-copyleft-ok` | `permissive` plus LGPL, MPL, EPL, CDDL and Artistic-2.0 |
| `no-agpl` | Anything except AGPL and SSPL (network copyleft) |

Licenses come from the lockfile (npm records them in v2 and v3), else from
the installed `package.json`. Expressions are parsed as SPDX:
`MIT OR GPL-3.0-only` passes `permissive` because one branch is enough, while
`MIT AND GPL-3.0-only` does not. Deprecated ids (`GPL-3.0`, `GPL-2.0+`) are
matched to their current form, so a deny of `AGPL-3.0-only` also catches a
package that says `AGPL-3.0`. A breach and `UNLICENSED` (no rights granted)
are high. A missing, custom (`SEE LICENSE IN ...`) or non-SPDX license is
medium, or high with `"unknown": "block"`. `allowPackages` exempts packages your
legal review has cleared. Findings use category `license` and appear in every
output format, and `--sbom` records each component's license.

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
