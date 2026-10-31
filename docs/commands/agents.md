---
title: "Auditing your AI tooling: penthera agents"
sidebarTitle: "Agent config audit"
description: "Your AI tools run code too."
---

> **Starter.** For "is this MCP server or skill safe?"

## Audit your agent setup

Your AI tools run code too. `penthera agents` audits the skills, MCP servers,
hooks, permissions, plugins and rule files that Claude Code, Cursor, Claude
Desktop, VS Code and Copilot load, and grades the setup A to F. If it finds no
agent config, it gives no grade and reports `Nothing to assess`, because an A
would grade something it never read.

```bash
penthera agents                 # this repo: .mcp.json, .claude/, .cursor/, AGENTS.md, CLAUDE.md, skills/
penthera agents --home          # + ~/.claude (hooks, permissions, plugins, skills), ~/.cursor/mcp.json, Claude Desktop, Cline and Roo Code
penthera agents ./some-skill    # vet a downloaded skill before you install it
penthera agents --pin           # write penthera.lock; later runs flag anything that changed
```

A folder you name with `SKILL.md` at its root, in any casing, is read as one
skill. Its scripts and other files get the same rules as a skill under
`skills/<name>/`. A file or folder Penthera could not read, or a file over the
size limit, gets a high finding, so such a skill never grades A. `node_modules`
and virtual environment packages are not read: they are listed under Not read
and do not lower the grade, so check them with `penthera deps`. In `--json`,
`agents.skillTarget` is true when the run read the folder as one named skill.
You can also pass the `SKILL.md` itself, and Penthera reads its folder. Any
other file is an error.

Your working folder is a project scan, whether you write `penthera agents`,
`penthera agents .` or its full path. So a `SKILL.md` at the root of your repo
does not change a CI run. To vet the skill you are standing in, pass `SKILL.md`,
or name the folder from its parent. A folder that only holds skills further
down, such as `./skills`, reports `Nothing to assess`: name one skill, or the
project above it. With `--pin`, `penthera.lock` goes inside the folder you named
and is left out of the skill's hash. Penthera does not read or write a
`penthera.lock` that is a symbolic link.

It is **offline and deterministic**: no LLM judge, no registry lookups, nothing
leaves your machine, and it never modifies the config it reads. Every verdict
is a rule you can read in [`lib/agents/`](https://github.com/danoszz/penthera/tree/main/lib/agents), so a skill can't talk
its way past it.

| Check | What it catches |
|---|---|
| Hidden content | Unicode tag characters (decoded), zero-width and bidi controls, variation-selector smuggling, text pushed past a wall of blank lines or off-screen, instructions in HTML comments, text addressed to the scanner, base64 blobs (decoded and classified), `.pyc`/archives/executables in a skill folder (by magic bytes, so a renamed `.png` doesn't hide one), symlinks that leave the folder. Every file in a skill folder is read, `__pycache__`, `build` and `dist` included. A `.pyc` is low only when it is Python's ordinary cache: named `__pycache__/<name>.<tag>.pyc` next to `<name>.py`, with a timestamp-based header that records that file's size. Such files are reported once per `__pycache__` folder. Any other `.pyc` or `.pyo` is high: no source next to it, a hash-based header (an unchecked one runs without looking at the source), a size that does not match, a legacy `x.pyc`, or an odd name. `node_modules` and `.git` are skipped, and the result lists them under Not checked. A Python virtual environment is handled by `skill-venv` below |
| Files outside the project | Instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md` and the rest), rule and command folders (`skills/`, `.cursor/rules`, `.claude/commands`, `.github/instructions`, `plugins/`), config files and hook scripts that resolve outside the project through a symlink are not read. A plugin's files that resolve outside the plugin folder are not read either. Each is listed under Not checked. With `--home`, the files under your home folder are read where they are |
| Code execution | `curl \| sh`, `wget \| bash`, `bash <(curl …)`, `eval "$(curl …)"`, `base64 -d \| sh`, `exec(base64…)`, PowerShell `iwr \| iex`, in skills, scripts, hooks and MCP launch commands |
| MCP servers | `npx -y` / `uvx` / `bunx` / `pnpm dlx` without an exact version, git sources (`git+https://…`, `git+ssh://…`, `github:owner/repo`) without a full 40-character commit SHA (`#<sha>` for npm, `@<sha>` for uv and pip: a tag or a branch can be moved), inline secrets in `env`, headers or args (same rules as the repo secret scan), remote servers over plain `http://`. Read from `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json` and `.roo/mcp.json` |
| Hooks & permissions | Hooks that auto-approve tool calls or pipe into a shell (including the scripts they run), hooks that run a local script file, `Bash(*)` and other wildcard allows, `bypassPermissions`, allow rules for `~/.ssh` and other credential files, wildcards in a skill's `allowed-tools` |
| Auto-run and auto-approve | VS Code tasks that run when the folder opens, MCP auto-approve keys (`autoApprove`, `alwaysAllow`, `trust: true`), Claude Code `enableAllProjectMcpServers`, VS Code `chat.tools.global.autoApprove` |
| Environment and registries | `NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONSTARTUP` and similar in an MCP server's `env`, a hook, a task or the settings `env`; a skill, hook, plugin or MCP config that points npm, Yarn or pip at another registry |
| Plugins | Marketplaces and marketplace plugins not pinned to a commit |
| Rug pulls | `--pin` writes SHA-256 hashes of every skill folder, MCP server definition, hook and installed plugin to `penthera.lock`. A later run reports what changed, appeared or disappeared. Lock version 2 hashes every file in a skill except `node_modules` and `.git`: `__pycache__` and virtual environments are pinned, since both hold code that runs. Python writing a new cache after the pin shows as a change, so delete `__pycache__` before you pin. A version 1 file (2.0.0) is compared the version 1 way, with an info finding that asks you to re-pin. An unknown or newer version is not compared at all, and an info finding says so |

### Rules for auto-run, registries and environment

Each rule below is deterministic. The finding says why it matters and how to
fix it.

| Rule | Severity | Why | How to fix |
|---|---|---|---|
| `task-folder-open` | medium; critical when the task downloads and runs code | VS Code runs a task with `runOptions.runOn: "folderOpen"` when a trusted workspace opens ([VS Code tasks](https://code.visualstudio.com/docs/editor/tasks)). In current VS Code, `task.allowAutomaticTasks` defaults to `off`, but a workspace with such a task still gets a one-time notification: Allow runs the task and sets the option to `on` for every trusted workspace. With `on` the task runs with no prompt. Only an `off` the user set themselves stops both (`runAutomaticTasks.ts` in the VS Code source). The setting has application scope, so VS Code ignores it in a repo's `.vscode/settings.json`, and Penthera does too. Medium, because one click on that notification runs a command from the repository, and after it every trusted folder's tasks run unasked. | Remove `runOn`, or run the task by hand. |
| `skill-venv` | medium | A skill folder holds a real Python virtual environment: `pyvenv.cfg` with a `home =` key, a `python` in `bin/` or `Scripts/`, and `lib/pythonX.Y/site-packages` or `Lib/site-packages`. All three must hold, because anyone can add an empty `pyvenv.cfg` or name a folder `venv` to hide it, and such a decoy is scanned like any other folder. In a real one, the packages in `lib`/`Lib` and `include`, and the binaries and links in `bin`/`Scripts`, are not scanned (listed under Not checked; `penthera deps --venv` reads the packages). The text scripts in `bin`/`Scripts` and every other file in the venv are scanned, so a download-and-run script there is still found. The whole venv is pinned in `penthera.lock`. | Ship a requirements file and let the user create the environment. |
| `hook-local-script` | low when the script is in the project and was read; medium when it is outside the project or missing | The hook runs a script file on every matching event with no prompt. `"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh` and the other documented forms resolve to the project. Low when Penthera read the script: its content went through the hook rules, and a change shows up in code review. Medium when nobody can read it here. A script outside the project, or a symlink that leads out of it, is not read. `node_modules/.bin/*` is a package binary, not a script (`penthera deps` checks those). A changed script does not change the settings file or `penthera.lock`. | Keep hook scripts in the repository and review them like code. |
| `registry-redirect` | high in skills, rule files and hooks; medium in MCP configs, settings `env` and plugin `.npmrc` files. Lower for the common legitimate forms: low for a registry on `localhost` or `127.0.0.1` (a local Verdaccio), a scoped `@scope:registry` (only that scope moves, as with GitHub Packages) and vendor indexes (`download.pytorch.org`, `pypi.nvidia.com`); at most medium for `--extra-index-url` and for an official registry over plain `http://` | Another registry decides what every later `npm install` or `pip install` gets. Medium where a team may point at its own mirror on purpose. `--extra-index-url` stays medium, because pip and uv take a package from either index (dependency confusion). `https://registry.npmjs.org`, `registry.yarnpkg.com` and `pypi.org` are never flagged, and a `$VARIABLE` value cannot be resolved offline, so it is not flagged either. One finding per file, at the severity of its worst line, so a harmless loopback or scoped line cannot lower a real redirect after it. Scoped and extra-index are decided by the flag or key that sets the value, never by text inside the URL. | Remove it. Set a company mirror in your own user config. |
| `env-code-injection` | high | `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT -r`, `JAVA_TOOL_OPTIONS -javaagent` and `NODE_OPTIONS` with `--require` or `--import` load code into every process started with them. `NODE_OPTIONS=--max-old-space-size=4096` is not flagged. | Remove it from the config. Set it in your own shell if a tool needs it. |
| `mcp-auto-approve` | high for `trust: true`, `"*"` and the VS Code switch; medium for a list of named tools and for `enableAllProjectMcpServers` | These keys skip the prompt before a tool call or a server start, in any MCP config Penthera reads (with `--home`, that includes Cline's `cline_mcp_settings.json` and Roo Code's `mcp_settings.json` in the global storage of VS Code, VS Code Insiders, VSCodium, Cursor and Windsurf): Cline `autoApprove` ([Cline docs](https://docs.cline.bot/mcp/configuring-mcp-servers)), Roo Code `alwaysAllow` ([Roo Code docs](https://roocodeinc.github.io/Roo-Code/features/mcp/using-mcp-in-roo)), Gemini CLI `trust: true` ([Gemini CLI docs](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md)), Claude Code `enableAllProjectMcpServers` ([settings](https://code.claude.com/docs/en/settings)) and VS Code `chat.tools.global.autoApprove` ([Copilot settings](https://code.visualstudio.com/docs/copilot/reference/copilot-settings)). Cursor and Windsurf document no per-server auto-approve key in their MCP config. | Approve tools one by one. List reviewed servers in `enabledMcpjsonServers`. |

Each finding names the OWASP [MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
and [Agentic Top 10](https://genai.owasp.org/) (ASI) ids it maps to, and the
usual `--json`, `-o`, `--markdown` and `--sarif` outputs all work. The scanner
is built for the ways LLM-judged skill scanners have been bypassed: it reads
whole files (no context window to overflow), every file in a skill folder (not
just `SKILL.md`), and treats text aimed at a reviewer as a finding rather than
an argument.

## Why these files matter

A coding agent runs with your developer's permissions. What it can do is decided
by files that rarely get reviewed: `.mcp.json`, `.claude/settings.json`, hooks,
skills, plugins, `CLAUDE.md`, `AGENTS.md` and `.cursor/` rules. Some arrive from
a teammate's pull request, some from a marketplace, some from a blog post. In
2025 and 2026 attackers used these paths: skills with instructions hidden from
human reviewers, MCP servers launched with `npx -y` on whatever version was
latest, and npm worms that wrote to `~/.claude` and ran the `claude` CLI on the
victim's machine.

`penthera deps` also flags packages that write to `~/.claude`, `~/.cursor` or
`.mcp.json`, or run the `claude`, `gemini` or `q` CLIs, which is how the
s1ngularity attack used local AI tools ([`penthera deps`](deps.md)).

## For a team

Add the [pre-commit hook](hook.md) so agent-config changes are checked before
they are committed, and the GitHub Action in `agents` mode on pull requests
([in CI](action.md)):

```bash
npx penthera hook install
```

```yaml
- uses: danoszz/penthera@<release-commit-sha>
  with:
    mode: agents
```

Or copy one file that runs `npx --yes penthera@2.1.2 agents` on every pull request and uploads SARIF: [`github-actions-agents.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-agents.yml) ([details](action.md#the-agent-config-check-in-one-file)).

The rules in [Rules for auto-run, registries and environment](#rules-for-auto-run-registries-and-environment), the Not checked line and the skill-folder changes shipped in 2.1.0. Penthera 2.0.0 does not have them. They run once you pin 2.1.0 or later.

## What you get

From Penthera's own test fixture of a deliberately bad setup (abridged). This
is the terminal report. Piped output is the shorter [agent brief](brief.md),
which has no grade line; `--json` and `-o` hold the grade.

```
  Grade       F  (0/100)
  Found      1 skills · 4 MCP servers · 3 hooks · 0 plugins · 1 rule files
  Lock       none (run with --pin)

  CRIT  MCP server "installer" launches by downloading and running code
         .mcp.json
  CRIT  SessionStart hook downloads and runs code
         .claude/settings.json
  HIGH  Instructions hidden in an HTML comment
         skills/helper/SKILL.md
  HIGH  Text addressed to a security scanner
         skills/helper/SKILL.md
  HIGH  PreToolUse (*) hook auto-approves tool calls
         .claude/settings.json
  HIGH  Permission allow-list grants `Bash(*)`
         .claude/settings.json
  MED   MCP server "filesystem" runs an unpinned package via npx
         .mcp.json
```

## What it does not do

- It reads configuration and files on disk. It does not watch what an agent does
  at run time, and it does not sandbox anything. For running agents, see
  [running AI agents safely](../agents-safely.md).
- It does not know whether a remote MCP server is trustworthy. It checks how the
  server is launched and configured, not what the service behind it does.
- It does not check MCP tool descriptions. It never starts a server, so
  instructions hidden in a tool's description (tool poisoning, OWASP MCP03)
  are not checked, and no finding carries the MCP03 label. Every agents
  result says so under Not checked.
- It does not read every agent's config yet. Codex `config.toml`, Cursor
  `hooks.json`, Windsurf, Continue, Kiro, Amazon Q, OpenCode, Zed and dev
  container files are listed under Not checked when they exist, instead of
  being read.
- It does not check the registries for newly published malicious skills or
  packages. A registry-watching service such as
  [Socket](../compare/socket.md) covers that.
- Its rules cover the patterns in the [methodology](../METHODOLOGY.md). A new
  trick needs a new rule and a release.

[Docs index](../index.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
