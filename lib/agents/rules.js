/**
 * Risky-configuration rules for MCP servers, hooks, permissions, skills'
 * allowed-tools, and plugin marketplaces. Pure functions over the inventory
 * from discover.js; each returns `{ rule, severity, title, detail, url }` hits.
 */
import { realpathSync } from "node:fs";
import { basename, isAbsolute, resolve, sep } from "node:path";
import { findSecretsInText } from "../whitebox/secrets.js";
import { findExecPatterns, preview } from "./hidden-content.js";
import { readText, isFile } from "./discover.js";

// ── Helpers ───────────────────────────────────────────────────────────────

function mask(s) {
  const v = String(s);
  return v.length <= 8 ? "***" : v.slice(0, 4) + "…" + v.slice(-4);
}

/** Split a command line on whitespace, honouring simple quotes. */
export function splitCommand(s) {
  return (String(s).match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) => t.replace(/^(["'])(.*)\1$/, "$2"));
}

function commandTokens(def) {
  const cmd = def.command ? splitCommand(def.command) : [];
  const args = Array.isArray(def.args) ? def.args.map(String) : [];
  return [...cmd, ...args];
}

const LOCAL_HOST = /^(?:localhost|127(?:\.\d+){3}|\[?::1\]?|0\.0\.0\.0|[\w-]+\.localhost|host\.docker\.internal)$/i;

function isPlainRemoteHttp(u) {
  if (typeof u !== "string" || !/^(?:http|ws):\/\//i.test(u)) return false;
  try {
    return !LOCAL_HOST.test(new URL(u.replace(/^ws:/i, "http:")).hostname);
  } catch {
    return false;
  }
}

// ── MCP: unpinned package runners ─────────────────────────────────────────

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

// A full commit SHA. A tag or a branch can be moved to other code; a commit cannot.
const COMMIT = /^[0-9a-f]{40}$/i;
const GIT_SCHEME = /git\+[a-z][\w+.-]*:|git:\/\/|(?:github|gitlab|bitbucket|gist):/i;
// npm reads a bare `owner/repo` as a GitHub repo.
const NPM_GITHUB_SHORTHAND = /^(?!\.)[\w.-]+\/[\w.-]+(?:#\S*)?$/;
const GIT_HOST_REPO = /^https?:\/\/(?:[^/\s@]*@)?(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[^/\s]+\/[^/\s#@]+\/?(?:[#@]\S*)?$/i;

/**
 * The git source in a package spec, or null: `git+https://…`, `git+ssh://…`,
 * `git://…`, `github:owner/repo`, an https URL of a repo (`….git`, or a
 * GitHub, GitLab or Bitbucket repo root), also after `name@` or `name @ `.
 */
export function gitSource(spec) {
  const s = String(spec).trim();
  const m = GIT_SCHEME.exec(s);
  if (m && (m.index === 0 || /[\s@=]/.test(s[m.index - 1]))) return s.slice(m.index).split(/\s/)[0];
  if (/^https?:\/\//i.test(s) && !/\s/.test(s) && (/\.git(?:[#@]|\/?$)/i.test(s) || GIT_HOST_REPO.test(s))) return s;
  return null;
}

/**
 * True if a git source names a full 40-hex commit: `#<sha>` (npm) or
 * `@<sha>` after the repo path (pip, uv). A tag, a branch or no ref is not pinned.
 */
export function gitRefPinned(src) {
  const hash = src.indexOf("#");
  if (hash >= 0 && COMMIT.test(src.slice(hash + 1))) return true;
  const body = hash < 0 ? src : src.slice(0, hash);
  const scheme = body.indexOf("://");
  // The path starts after the host, so `git@host` in an ssh URL is not a ref.
  const pathStart = scheme < 0 ? body.indexOf(":") + 1 : body.indexOf("/", scheme + 3);
  if (pathStart <= 0) return false;
  const path = body.slice(pathStart);
  const at = path.lastIndexOf("@");
  return at >= 0 && COMMIT.test(path.slice(at + 1));
}

/**
 * True if an npm spec (`pkg@1.2.3`, `@scope/pkg@1.2.3`) pins an exact version,
 * or a git source (`git+https://…`, `github:owner/repo`, `owner/repo`) pins a full commit.
 */
export function npmSpecPinned(spec) {
  const git = gitSource(spec) ?? (NPM_GITHUB_SHORTHAND.test(spec) ? spec : null); // `owner/repo` is GitHub to npm
  if (git) return gitRefPinned(git);
  if (/^(?:\.{0,2}\/|file:|https?:|[A-Za-z]:\\)/.test(spec)) return true; // local path or tarball URL: not a registry lookup
  const at = spec.startsWith("@") ? spec.indexOf("@", 1) : spec.indexOf("@");
  if (at < 0) return false;
  return EXACT_SEMVER.test(spec.slice(at + 1));
}

/**
 * True if a Python spec (`pkg==1.2.3`, `pkg@1.2.3`) pins an exact version,
 * or a git source (`git+https://…@<sha>`, `pkg @ git+…`) pins a full commit.
 */
export function pySpecPinned(spec) {
  const git = gitSource(spec);
  if (git) return gitRefPinned(git);
  if (/^(?:\.{0,2}\/|file:|https?:)/.test(spec)) return true;
  const version = pinnedVersion(spec);
  // Same language as /^\d+(?:\.\d+)*(?:[-.+]?[A-Za-z0-9.]+)?$/, without its quadratic overlap.
  return version != null && /^(?:\d[A-Za-z0-9.]*|\d+(?:\.\d+)*[-+][A-Za-z0-9.]+)$/.test(version) && !/[<>~^*]/.test(spec);
}

/**
 * The text after the first `==` or `@` in the spec's last run of
 * non-separator characters: what `/(?:==|@)([^,;\s]+)$/` captures, found in
 * linear time (that regex rescans the tail from every `@`).
 */
function pinnedVersion(spec) {
  let start = spec.length;
  while (start > 0 && !/[,;\s]/.test(spec[start - 1])) start--;
  const tail = spec.slice(start);
  const at = tail.search(/==|@/);
  if (at < 0) return null;
  const version = tail.slice(at + (tail[at] === "@" ? 1 : 2));
  return version || null;
}

const RUNNERS = [
  { name: "npx", match: (t) => /^npx(?:\.cmd)?$/.test(basename(t[0])), from: 1, eco: "npm", valueOpts: ["-p", "--package", "-c", "--call", "--cache", "--registry"], pkgOpts: ["-p", "--package"], autoYes: (a) => a.includes("-y") || a.includes("--yes") },
  { name: "bunx", match: (t) => /^bunx$/.test(basename(t[0])), from: 1, eco: "npm", valueOpts: ["-p", "--package"], pkgOpts: ["-p", "--package"], autoYes: () => true },
  { name: "pnpm dlx", match: (t) => /^pnpm$/.test(basename(t[0])) && t[1] === "dlx", from: 2, eco: "npm", valueOpts: ["--package"], pkgOpts: ["--package"], autoYes: () => true },
  { name: "yarn dlx", match: (t) => /^yarn$/.test(basename(t[0])) && t[1] === "dlx", from: 2, eco: "npm", valueOpts: ["-p", "--package"], pkgOpts: ["-p", "--package"], autoYes: () => true },
  { name: "uvx", match: (t) => /^uvx$/.test(basename(t[0])), from: 1, eco: "py", valueOpts: ["--from", "--with", "--python", "-p", "--index-url", "--index"], pkgOpts: ["--from"], autoYes: () => true },
  { name: "uv tool run", match: (t) => /^uv$/.test(basename(t[0])) && t[1] === "tool" && t[2] === "run", from: 3, eco: "py", valueOpts: ["--from", "--with", "--python", "-p"], pkgOpts: ["--from"], autoYes: () => true },
  { name: "pipx run", match: (t) => /^pipx$/.test(basename(t[0])) && t[1] === "run", from: 2, eco: "py", valueOpts: ["--spec", "--python", "--index-url"], pkgOpts: ["--spec"], autoYes: () => true },
];

/** Identify the package an MCP launch command installs on the fly, if any. */
export function runnerPackage(tokens) {
  const runner = RUNNERS.find((r) => tokens.length && r.match(tokens));
  if (!runner) return null;
  const args = tokens.slice(runner.from);
  let pkg = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const [flag, inline] = a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, null];
    if (runner.pkgOpts.includes(flag)) { pkg = inline ?? args[i + 1]; break; }
    if (a.startsWith("-")) {
      if (runner.valueOpts.includes(flag) && inline == null) i++;
      continue;
    }
    pkg = a;
    break;
  }
  if (!pkg) return null;
  const pinned = runner.eco === "npm" ? npmSpecPinned(pkg) : pySpecPinned(pkg);
  const git = gitSource(pkg) != null || (runner.eco === "npm" && NPM_GITHUB_SHORTHAND.test(pkg));
  return { runner: runner.name, pkg, pinned, git, autoYes: runner.autoYes(args) };
}

// ── MCP rules ─────────────────────────────────────────────────────────────

const SECRET_NAME = /(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|bearer|cookie)/i;
const NOT_A_SECRET = /^(?:\$\{?[\w:-]+\}?|\$\w+|%\w+%|<[^>]+>|\{\{[^}]+\}\}|env:.*|op:\/\/.*|your[-_ ].*|xxx+.*|changeme|placeholder|\*+|true|false|none|null|\d{1,6})$/i;

const CONNECTION_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^:/@\s]*:([^@/\s]+)@/i;

function inlineSecretHits(kind, k, v) {
  const value = String(v ?? "");
  if (!value || NOT_A_SECRET.test(value.trim())) return [];
  const hits = findSecretsInText(`${k}="${value}"`).map((h) => ({ name: h.name, severity: h.severity, match: h.match }));
  if (hits.length) return hits;
  // Bearer tokens in headers, and long literals under a secret-looking name.
  const bearer = value.match(/^(?:Bearer|Basic|Token)\s+(\S{12,})$/i);
  if (bearer && !NOT_A_SECRET.test(bearer[1])) return [{ name: `${kind} credential`, severity: "high", match: bearer[1] }];
  if (SECRET_NAME.test(k) && value.length >= 12 && !/\s/.test(value)) {
    return [{ name: "Credential-like value", severity: "high", match: value }];
  }
  // A connection string carries its password whatever the variable is called.
  const password = value.match(CONNECTION_PASSWORD)?.[1];
  if (password && !NOT_A_SECRET.test(password)) return [{ name: "Connection string password", severity: "high", match: password }];
  return [];
}

export function checkMcpServer(server) {
  const { name, def, file } = server;
  const hits = [];
  const tokens = commandTokens(def);

  const run = runnerPackage(tokens);
  if (run && !run.pinned) {
    hits.push({
      rule: "mcp-unpinned",
      severity: run.autoYes ? "medium" : "low",
      title: `MCP server "${name}" runs an unpinned ${run.git ? "git source" : "package"} via ${run.runner}`,
      detail: run.git
        ? `\`${preview([...tokens].join(" "), 120)}\` fetches \`${preview(run.pkg, 120)}\` from git at launch${run.autoYes ? " without a prompt" : ""}, without a full commit. A tag or a branch can be moved to other code, so a pushed or hijacked change runs on your machine with the agent's access. Pin a full 40-character commit SHA (\`${run.runner.includes("uv") || run.runner.includes("pipx") ? "@<sha>" : "#<sha>"}\`).`
        : `\`${preview([...tokens].join(" "), 120)}\` installs \`${run.pkg}\` from the registry at launch${run.autoYes ? " without a prompt" : ""}, at whatever version is current. A compromised or hijacked release runs on your machine with the agent's access. Pin an exact version (\`${run.pkg.replace(/@[^@/]*$/, "")}@x.y.z\`${run.runner.includes("uv") || run.runner.includes("pipx") ? " or `pkg==x.y.z`" : ""}).`,
      url: file,
    });
  }

  const exec = findExecPatterns(tokens.join(" "));
  if (exec.length) {
    hits.push({
      rule: "mcp-exec",
      severity: "critical",
      title: `MCP server "${name}" launches by downloading and running code`,
      detail: `Launch command contains a ${exec[0].label}: \`${preview(exec[0].match, 120)}\`.`,
      url: file,
    });
  }

  const secretSources = [];
  if (def.env && typeof def.env === "object") for (const [k, v] of Object.entries(def.env)) secretSources.push(["env", k, v]);
  if (def.headers && typeof def.headers === "object") for (const [k, v] of Object.entries(def.headers)) secretSources.push(["header", k, v]);
  tokens.forEach((t, i) => {
    const flag = tokens[i - 1] || "";
    if (/^--?[\w-]*(?:key|token|secret|password)/i.test(flag)) secretSources.push(["arg", flag.replace(/^-+/, ""), t]);
    else if (t.includes("=")) secretSources.push(["arg", t.slice(0, t.indexOf("=")).replace(/^-+/, ""), t.slice(t.indexOf("=") + 1)]);
    else secretSources.push(["arg", "arg", t]);
  });
  const url = def.url || def.serverUrl || def.endpoint;
  if (typeof url === "string") {
    try {
      const u = new URL(url);
      for (const [k, v] of u.searchParams) secretSources.push(["url", k, v]);
    } catch { /* not a URL */ }
  }
  const reported = new Set();
  for (const [kind, k, v] of secretSources) {
    for (const h of inlineSecretHits(kind, k, v)) {
      if (reported.has(k)) continue;
      reported.add(k);
      hits.push({
        rule: "mcp-inline-secret",
        severity: h.severity === "critical" ? "critical" : "high",
        title: `MCP server "${name}" has an inline secret in ${kind} \`${k}\``,
        detail: `${h.name} stored in plain text in the config (\`${mask(h.match)}\`). Config files get synced, shared and committed. Reference an environment variable instead (\`"${k}": "\${${k.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}}"\`) and rotate this one.`,
        url: file,
      });
    }
  }

  const remote = [url, ...tokens].find(isPlainRemoteHttp);
  if (remote) {
    hits.push({
      rule: "mcp-plain-http",
      severity: "high",
      title: `MCP server "${name}" connects over plain HTTP`,
      detail: `\`${preview(remote, 100)}\` is not TLS. Anyone on the network path can read the tool traffic and inject tool results or descriptions. Use https://.`,
      url: file,
    });
  }
  return hits;
}

// ── Permissions ───────────────────────────────────────────────────────────

const SHELL_TOOL = "(?:Bash|Shell|PowerShell|run_terminal_cmd|terminal)";
const UNRESTRICTED = new RegExp(`^(?:\\*|${SHELL_TOOL}(?:\\(\\s*(?:\\*|:\\*|\\*\\*|\\*:\\*)?\\s*\\))?)$`, "i");
const DANGEROUS_CMD = new RegExp(`^${SHELL_TOOL}\\(\\s*(sudo|curl|wget|sh|bash|zsh|eval|ssh|scp|nc|ncat|rm|chmod|dd)\\b([^)]*)\\)$`, "i");
const INTERPRETER_CMD = new RegExp(`^${SHELL_TOOL}\\(\\s*(python[0-9.]*|node|npx|bunx|deno|bun|ruby|perl|php|uvx)\\b([^)]*)\\)$`, "i");
// A path in a folder every local user and process can write (`/tmp/x.sh`).
const WORLD_WRITABLE = new RegExp(`^${SHELL_TOOL}\\([^)]*?(?<=[\\s=:'"(])((?:/private)?/(?:var/)?tmp/|/dev/shm/)[^)]*\\)$`, "i");
// The arguments after the command: none, or a `*` anywhere, allow any call.
const anyArguments = (args) => !args.trim() || args.includes("*");
const CREDENTIAL_PATH = /\((?:[^)]*?)(?:~\/\.ssh|\.ssh\/|\.aws\/|\.gnupg|\.npmrc|\.netrc|\.env\b|\.docker\/config|id_rsa|id_ed25519|\.config\/gh)/i;

/** Classify one permission rule (`Bash(*)`, `Read(~/.ssh/**)`). Null if fine. */
export function classifyPermission(rule) {
  const r = String(rule).trim();
  if (UNRESTRICTED.test(r)) {
    return { rule: "permission-wildcard", severity: "high", why: "unrestricted shell: the agent can run any command without asking" };
  }
  let m = r.match(WORLD_WRITABLE);
  if (m) return { rule: "permission-tmp-script", severity: "medium", why: `runs a file from a world-writable folder (\`${m[1]}\`); any local process can replace it, and it then runs without asking`, fix: "Move the script into the repository, where changes show up in review, or remove the rule." };
  // An exact command (`Bash(bash ./scripts/check.sh)`) is the narrow form the
  // fix below asks for, so only open-ended grants are reported.
  m = r.match(DANGEROUS_CMD);
  if (m && anyArguments(m[2])) return { rule: "permission-wildcard", severity: "medium", why: `pre-approves \`${m[1]}\` with any arguments, enough to download, exfiltrate or delete` };
  if (m && /^sudo$/i.test(m[1])) return { rule: "permission-wildcard", severity: "low", why: "pre-approves a command that runs as root" };
  m = r.match(INTERPRETER_CMD);
  if (m && anyArguments(m[2])) return { rule: "permission-wildcard", severity: "low", why: `pre-approves \`${m[1]}\`, which can run arbitrary code` };
  if (/^(?:Read|Edit|Write|MultiEdit)\(/i.test(r) && CREDENTIAL_PATH.test(r)) {
    return { rule: "permission-credential-read", severity: "medium", why: "pre-approves access to credential files" };
  }
  if (/^mcp__\*$|^mcp__[^_]+__\*$/.test(r) || /^mcp__[\w-]+$/.test(r)) {
    return null; // whole-server allows are a normal pattern
  }
  return null;
}

export function checkPermissions(inv) {
  const hits = [];
  for (const p of inv.permissions) {
    if (p.list !== "allow") continue;
    const c = classifyPermission(p.rule);
    if (c) {
      hits.push({
        rule: c.rule,
        severity: c.severity,
        title: `Permission allow-list grants \`${p.rule}\``,
        detail: `\`${p.rule}\` ${c.why}. ${c.fix || "Narrow it to the exact commands the workflow needs (`Bash(npm test)`, `Bash(git status)`)."}`,
        url: p.file,
      });
    }
  }
  for (const s of inv.settings) {
    if (s.defaultMode === "bypassPermissions") {
      hits.push({
        rule: "permission-bypass-mode",
        severity: "high",
        title: "Permissions default to bypassPermissions",
        detail: "`permissions.defaultMode: \"bypassPermissions\"` runs every tool call without asking, including ones a prompt-injected agent makes. Use the default mode and an allow-list.",
        url: s.file,
      });
    }
  }
  return hits;
}

/** Tokenize an `allowed-tools` frontmatter value (string or list). */
export function parseAllowedTools(value) {
  if (Array.isArray(value)) return value.flatMap(parseAllowedTools);
  if (typeof value !== "string") return [];
  return value.match(/[A-Za-z_*][\w*-]*(?:\([^)]*\))?/g) || [];
}

export function checkAllowedTools(display, frontmatter, label) {
  const hits = [];
  const tools = parseAllowedTools(frontmatter?.["allowed-tools"] ?? frontmatter?.allowedTools);
  for (const t of tools) {
    const c = classifyPermission(t);
    if (!c) continue;
    hits.push({
      rule: c.rule,
      severity: c.severity,
      title: `${label} pre-approves \`${t}\` in allowed-tools`,
      detail: `While this ${label.toLowerCase().startsWith("skill") ? "skill" : "command"} is active, \`${t}\` ${c.why}. Instructions inside it (or injected into it) run with that grant.`,
      url: display,
    });
  }
  return hits;
}

// ── Hooks ─────────────────────────────────────────────────────────────────

// Whitespace, an optional (escaped) quote, whitespace. Written so the two
// whitespace runs cannot split one run of spaces between them, which made the
// former `\s*\\?["']?\s*` quadratic on long whitespace.
const QSEP = String.raw`\s*(?:\\?["']\s*|\\\s*)?`;
const AUTO_APPROVE = new RegExp(String.raw`["']?(?:permissionDecision|behavior)["']?${QSEP}:${QSEP}allow\b|["']?decision["']?${QSEP}:${QSEP}approve\b`, "i");
const PIPE_TO_SHELL = /\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b(?:\s|$|;|&|\))/;

/** The line holding the first pipe into a shell, for a finding's detail. */
function pipeToShellLine(text) {
  const m = /\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/.exec(text);
  if (!m) return null;
  const start = text.lastIndexOf("\n", m.index) + 1;
  const end = text.indexOf("\n", m.index + m[0].length);
  return text.slice(start, end < 0 ? text.length : end);
}

/**
 * The script a hook runs, read only when it resolves (symlinks followed)
 * inside the hook's base folder: the project, or the plugin folder. Uses the
 * same target as `hook-local-script`, so the rules read the file that rule
 * names. Returns { path, text } or null.
 */
function hookScript(hook, command) {
  const target = hookScriptTarget(command, hook.baseDir);
  if (!target?.path || !hook.baseDir || !insideReal(target.path, hook.baseDir) || !isFile(target.path)) return null;
  const text = readText(target.path);
  return typeof text === "string" ? { path: target.path, text } : null;
}

/** Does `p`, with every symlink resolved, sit inside `base` (also resolved)? */
export function insideReal(p, base) {
  let rp;
  let rb;
  try { rp = realpathSync(p); } catch { return false; }
  try { rb = realpathSync(base); } catch { rb = resolve(base); }
  return rp === rb || rp.startsWith(rb.endsWith(sep) ? rb : rb + sep);
}

export function checkHook(h) {
  const hits = [];
  const command = typeof h.hook.command === "string" ? h.hook.command : "";
  if (!command) return hits;
  const where = `${h.event}${h.matcher ? ` (${h.matcher})` : ""}`;
  const script = hookScript(h, command);
  const sources = [{ label: "command", text: command }];
  if (script) sources.push({ label: `script ${basename(script.path)}`, text: script.text });

  for (const s of sources) {
    const exec = findExecPatterns(s.text);
    if (exec.length) {
      hits.push({
        rule: "hook-exec",
        severity: "critical",
        title: `${where} hook downloads and runs code`,
        detail: `Hook ${s.label} contains a ${exec[0].label}: \`${preview(exec[0].match, 120)}\`. Hooks run automatically on every matching event, with no prompt.`,
        url: h.file,
      });
      break;
    }
    if (PIPE_TO_SHELL.test(s.text)) {
      hits.push({
        rule: "hook-pipe-shell",
        severity: "high",
        title: `${where} hook pipes into a shell`,
        detail: `Hook ${s.label} pipes data into \`sh\`/\`bash\`: \`${preview(pipeToShellLine(s.text) || s.text, 120)}\`. Whatever produces that input controls the commands.`,
        url: h.file,
      });
      break;
    }
  }

  const approve = sources.find((s) => AUTO_APPROVE.test(s.text));
  if (approve) {
    const m = String(h.matcher || "");
    const broad = !m || m === "*" || m === ".*" || /\bBash\b|\bShell\b|\bmcp__/i.test(m);
    hits.push({
      rule: "hook-auto-approve",
      severity: broad ? "high" : "medium",
      title: `${where} hook auto-approves tool calls`,
      detail: `Hook ${approve.label} returns an allow/approve decision${broad ? ` for ${m ? `\`${m}\`` : "every tool"}` : ""}, so matching tool calls skip the permission prompt. A prompt-injected agent gets the same pass.`,
      url: h.file,
    });
  }
  return hits;
}

// ── Plugins and marketplaces ──────────────────────────────────────────────

/** Describe a marketplace/plugin source and whether it is pinned to a commit. */
export function sourcePin(source) {
  if (typeof source === "string") {
    if (/^\.{0,2}\//.test(source)) return { local: true };
    if (/^https?:\/\//i.test(source)) return { pinned: false, label: source, http: isPlainRemoteHttp(source) };
    return { pinned: false, label: source };
  }
  if (!source || typeof source !== "object") return { local: true };
  const kind = source.source;
  if (kind === "directory" || kind === "file" || kind === "local") return { local: true };
  const label = source.repo || source.url || source.path || JSON.stringify(source);
  const pinned = COMMIT.test(source.sha || "") || COMMIT.test(source.ref || "") || COMMIT.test(source.commit || "");
  return { pinned, label, http: isPlainRemoteHttp(source.url), firstParty: /^anthropics\//i.test(source.repo || "") };
}

export function checkMarketplaces(inv) {
  const hits = [];
  for (const m of inv.marketplaces) {
    const s = sourcePin(m.source);
    if (s.local || s.pinned) continue;
    hits.push({
      rule: "marketplace-unpinned",
      severity: s.http ? "high" : s.firstParty ? "low" : "medium",
      title: `Plugin marketplace "${m.name}" is not pinned to a commit`,
      detail: `Source \`${preview(s.label, 100)}\` tracks a moving branch${s.http ? " over plain HTTP" : ""}. Whoever controls it can change the skills, hooks and MCP servers you install on the next update. Pin \`sha\` (or \`ref\`) to a reviewed commit.`,
      url: m.file,
    });
  }
  for (const p of inv.pluginSources) {
    const s = sourcePin(p.source);
    if (s.local || s.pinned) continue;
    hits.push({
      rule: "plugin-source-unpinned",
      severity: s.http ? "high" : "medium",
      title: `Marketplace plugin "${p.name}" is not pinned to a commit`,
      detail: `Source \`${preview(s.label, 100)}\` has no \`sha\`. Everyone installing from this marketplace gets whatever is on the branch at install time.`,
      url: p.file,
    });
  }
  return hits;
}


// ── Package-registry redirects ────────────────────────────────────────────

// The public registries. Anything else in a skill, hook or MCP config moves
// every later install to a server someone else controls.
const OFFICIAL_REGISTRY_HOSTS = new Set([
  "registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com",
  "pypi.org", "pypi.python.org", "files.pythonhosted.org",
]);

/** Environment variables that choose the npm, yarn, pip or uv registry. */
export const REGISTRY_ENV = /^(?:npm_config_(?:@[\w.-]+:)?registry|yarn_registry|yarn_npm_registry_server|pip_index_url|pip_extra_index_url|uv_index_url|uv_extra_index_url|uv_default_index|uv_index)$/i;

/** Host of a registry value, or null when it is not a literal URL (`$VAR`, `${X}`). */
function registryHost(value) {
  const v = String(value ?? "").trim().replace(/^["']|["']$/g, "");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return null;
  try { return new URL(v).hostname.toLowerCase(); } catch { return null; }
}

// Vendor package indexes that install guides name on purpose (PyTorch, NVIDIA
// wheels). Still another registry, so still reported, at low.
const VENDOR_INDEX_HOSTS = new Set(["download.pytorch.org", "pypi.nvidia.com"]);

/**
 * How a registry value moves installs, or null when it does not: "http" (an
 * official registry over plain HTTP), "loopback" (a local registry such as
 * Verdaccio), "vendor" (a well-known vendor index) or "redirect".
 */
export function registryKind(value) {
  const v = String(value ?? "").trim().replace(/^["']|["']$/g, "");
  const host = registryHost(v);
  if (host == null) return null;
  if (OFFICIAL_REGISTRY_HOSTS.has(host)) return /^https:/i.test(v) ? null : "http";
  if (LOCAL_HOST.test(host)) return "loopback";
  if (VENDOR_INDEX_HOSTS.has(host) && /^https:/i.test(v)) return "vendor";
  return "redirect";
}

/** True when a registry value is a literal URL off the official registries, or one over plain HTTP. */
export function isRegistryRedirect(value) {
  return registryKind(value) != null;
}

const VAL = String.raw`["']?([^\s"';|&)]+)`;
const REGISTRY_PATTERNS = [
  // npm config set registry URL, pnpm/yarn alike, scoped (@acme:registry) too
  new RegExp(String.raw`\b(?:npm|pnpm|yarn)\s+config\s+set\s+(?:--global\s+|-g\s+)?(?:@[\w.-]+:)?(?:registry|npmRegistryServer)[\s=]+${VAL}`, "gi"),
  // --registry URL on any npm-family command
  new RegExp(String.raw`--registry[=\s]+${VAL}`, "gi"),
  // NPM_CONFIG_REGISTRY=URL, export PIP_INDEX_URL=URL, YARN_REGISTRY: URL
  new RegExp(String.raw`\b(npm_config_(?:@[\w.-]+:)?registry|YARN_REGISTRY|YARN_NPM_REGISTRY_SERVER|PIP_(?:EXTRA_)?INDEX_URL|UV_(?:EXTRA_)?INDEX_URL|UV_DEFAULT_INDEX)\s*[=:]\s*${VAL}`, "gi"),
  // pip/uv --index-url, --extra-index-url, --default-index, --index
  new RegExp(String.raw`--(?:extra-)?index-url[=\s]+${VAL}|--default-index[=\s]+${VAL}`, "gi"),
  // pip config set global.index-url URL
  new RegExp(String.raw`\bpip3?\s+config\s+set\s+[\w.-]*index-url\s+${VAL}`, "gi"),
  // .yarnrc.yml npmRegistryServer, pip.conf index-url =
  // ([ \t] only, so a match never crosses a line, and the runs either side of
  // the separator cannot share a space, which would backtrack quadratically.)
  new RegExp(String.raw`^[ \t]*(?:npmRegistryServer[ \t]*:|(?:extra-)?index-url[ \t]*=)[ \t]*${VAL}`, "gim"),
];
// pip install -i URL: the short flag is only a registry after `pip install`,
// which is checked in a bounded look-back (a lazy scan from every `pip
// install` to the flag was quadratic on a line of repeated `pip install`).
const PIP_SHORT_I = new RegExp(String.raw`(?:^|\s)-i\s+${VAL}`, "gm");
const PIP_INSTALL_BEFORE = /\bpip3?\s+install\b[^\n|;&]*$/;
// .npmrc `registry=` and `@scope:registry=`, .yarnrc `registry "URL"`: only in
// those files. The separator is `=` with optional blanks, or blanks alone; the
// two branches cannot share a space, so a line of `registry` and a megabyte of
// spaces fails in linear time (the former `\s*[= ]\s*` was quadratic).
const NPMRC_PATTERN = new RegExp(String.raw`^[ \t]*(?:@[\w.-]+:)?registry(?:[ \t]*=[ \t]*|[ \t]+)${VAL}`, "gim");
const NPMRC_FILE = /(?:^|[/\\])\.(?:npmrc|yarnrc)$/i;

/**
 * Registry redirects in a text (a script, a hook command, a SKILL.md, an
 * .npmrc). Returns [{ match, url }] for every literal URL that is not an
 * official registry; `$VAR` values cannot be resolved offline and are skipped.
 */
export function findRegistryRedirects(text, fileName = "") {
  const s = String(text ?? "");
  const out = [];
  // One match per URL and kind: the same server as a scope first and as the
  // whole registry later must not hide the second behind the first.
  const seen = new Set();
  const add = (r) => {
    const key = `${r.kind}\0${r.url}`;
    if (!seen.has(key)) { seen.add(key); out.push(r); }
  };
  const patterns = NPMRC_FILE.test(fileName) ? [...REGISTRY_PATTERNS, NPMRC_PATTERN] : REGISTRY_PATTERNS;
  for (const re of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(s))) {
      const url = m.slice(1).filter(Boolean).find((g) => /:\/\//.test(g)) ?? m.slice(1).filter(Boolean).pop();
      if (url && isRegistryRedirect(url)) add(registryMatch(m[0].trim(), url));
      if (m[0].length === 0) re.lastIndex++;
    }
  }
  PIP_SHORT_I.lastIndex = 0;
  let m;
  while ((m = PIP_SHORT_I.exec(s))) {
    const before = s.slice(Math.max(0, m.index - 300), m.index + 1);
    const url = m[1];
    if (PIP_INSTALL_BEFORE.test(before) && isRegistryRedirect(url)) add(registryMatch(`pip install ... ${m[0].trim()}`, url));
  }
  return out;
}

// The key or flag before the value: `@scope:registry` (npm config set, an
// .npmrc line, npm_config_@scope:registry) or an extra-index flag or key.
// Tested on the text before the URL only, so `--registry
// https://host/@acme:registry` or `-i https://host/extra-index-url/` cannot
// pass the URL off as a scope or an extra index.
const SCOPED_KEY = /(?:^|[\s_])@[\w.-]+:(?:registry|npmRegistryServer)[\s=:"']*$/i;
const EXTRA_KEY = /(?:^|[\s-])(?:--extra-index-url|(?:PIP|UV)_EXTRA_INDEX_URL|extra-index-url)[\s=:"']*$/i;

/**
 * A registry match with its kind: the value's kind, or "scoped" (only one
 * npm scope moves) or "extra" (pip/uv add an index next to PyPI) from the
 * key or flag that sets it.
 */
function registryMatch(match, url) {
  let kind = registryKind(url);
  if (kind === "redirect") {
    const at = match.lastIndexOf(url);
    const key = at >= 0 ? match.slice(0, at) : match;
    if (SCOPED_KEY.test(key)) kind = "scoped";
    else if (EXTRA_KEY.test(key)) kind = "extra";
  }
  return { match, url, kind };
}

const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
const atMost = (sev, cap) => (SEVERITY_ORDER.indexOf(sev) > SEVERITY_ORDER.indexOf(cap) ? cap : sev);

/**
 * Severity of a registry match where the place it sits in gives `base`:
 * low for a loopback registry, a single npm scope or a known vendor index;
 * medium at most for an extra pip index and for an official registry over
 * plain HTTP; `base` otherwise.
 */
export function registrySeverity(r, base) {
  if (r.kind === "loopback" || r.kind === "scoped" || r.kind === "vendor") return "low";
  if (r.kind === "extra" || r.kind === "http") return atMost(base, "medium");
  return base;
}

/**
 * The match with the highest severity, so a harmless line (a loopback
 * registry, one scope) before a real redirect never decides the finding.
 * Ties keep the first match.
 */
export function worstRegistryMatch(matches, base) {
  let worst = null;
  for (const r of matches) {
    if (!worst || SEVERITY_ORDER.indexOf(registrySeverity(r, base)) > SEVERITY_ORDER.indexOf(registrySeverity(worst, base))) worst = r;
  }
  return worst;
}

/** The sentence that explains a registry match of a given kind. */
export function registryDetail(r) {
  const host = preview(registryHost(r.url) || r.url, 80);
  const head = `\`${preview(r.match, 120)}\``;
  switch (r.kind) {
    case "http": return `${head} reaches the official registry over plain HTTP, so anyone on the network path can swap the packages it installs. Use the \`https://\` URL.`;
    case "loopback": return `${head} sends package installs to a registry on this machine (\`${host}\`), such as a local Verdaccio for publish tests. Low, because only someone with access to the machine runs it; make sure it is not left in config others use.`;
    case "scoped": return `${head} moves one npm scope to \`${host}\`; every other package still comes from the public registry. Low, since this is how GitHub Packages and private scopes work; check that the scope is yours.`;
    case "vendor": return `${head} installs from \`${host}\`, a vendor index that install guides name on purpose. Low; check the URL is the vendor's.`;
    case "extra": return `${head} adds \`${host}\` next to the public index. pip and uv then take a package from either one, so a name on that server can win over the public one (dependency confusion). Medium; prefer \`--index-url\` with one index you trust, or pin hashes.`;
    default: return `${head} sends package installs to \`${host}\` instead of the public registry. Whoever runs that server decides what every later \`npm install\` or \`pip install\` gets, including packages with the right names and the wrong code.`;
  }
}

function registryHit(r, where, url, base) {
  return {
    rule: "registry-redirect",
    severity: registrySeverity(r, base),
    title: `${where} points the package manager at another registry`,
    detail: `${registryDetail(r)} Remove it, or, for a company mirror, set the registry in your own user config rather than in agent config others ship.`,
    url,
  };
}

// ── Code-loading environment variables ───────────────────────────────────

// Variables that make a process load extra code before its own. A launcher
// that sets one runs that code inside every process it starts.
const LOADER_ENV = {
  LD_PRELOAD: () => true,
  LD_AUDIT: () => true,
  DYLD_INSERT_LIBRARIES: () => true,
  BASH_ENV: () => true,
  PYTHONSTARTUP: () => true,
  PERL5OPT: () => true,
  // Only the flags that load code; --max-old-space-size and friends are fine.
  NODE_OPTIONS: (v) => /(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader)(?:[=\s]|$)/.test(v),
  RUBYOPT: (v) => /(?:^|\s)-r/.test(v),
  JAVA_TOOL_OPTIONS: (v) => /-javaagent:/.test(v),
};

/** Is `NAME=value` a code-loading variable with a value that loads code? */
export function loaderEnv(name, value) {
  const check = LOADER_ENV[String(name).toUpperCase()];
  const v = String(value ?? "").trim();
  return !!check && v !== "" && check(v);
}

const LOADER_ASSIGN = new RegExp(String.raw`\b(${Object.keys(LOADER_ENV).join("|")})=("[^"\n]*"|'[^'\n]*'|[^\s;|&]*)`, "g");

/** `NAME=value` assignments of code-loading variables in a shell text. */
export function findLoaderEnv(text) {
  const out = [];
  LOADER_ASSIGN.lastIndex = 0;
  let m;
  while ((m = LOADER_ASSIGN.exec(String(text ?? "")))) {
    const value = m[2].replace(/^(["'])(.*)\1$/, "$2");
    if (loaderEnv(m[1], value)) out.push({ name: m[1], value, match: m[0] });
  }
  return out;
}

function loaderHit(where, name, value, url) {
  return {
    rule: "env-code-injection",
    severity: "high",
    title: `${where} sets ${name}`,
    detail: `\`${name}=${preview(value, 80)}\` makes every process started with it load that code first (${name === "NODE_OPTIONS" ? "Node.js `--require`/`--import`" : name === "BASH_ENV" ? "bash sources the file before any non-interactive script" : name === "PYTHONSTARTUP" ? "Python runs the file at interactive start" : "the dynamic loader injects the library"}). A config change can then run code without touching the command anyone reviews. Remove it; if a tool needs it, set it in your own shell.`,
    url,
  };
}

/** env-code-injection and registry-redirect hits for an env block. */
export function checkEnvBlock(env, where, url, registryBase = "medium") {
  const hits = [];
  if (!env || typeof env !== "object" || Array.isArray(env)) return hits;
  for (const [k, v] of Object.entries(env)) {
    if (loaderEnv(k, v)) hits.push(loaderHit(where, k, String(v), url));
    if (REGISTRY_ENV.test(k) && isRegistryRedirect(v)) hits.push(registryHit(registryMatch(`${k}=${v}`, String(v)), where, url, registryBase));
  }
  return hits;
}

// ── MCP auto-approve ──────────────────────────────────────────────────────

/**
 * Per-server keys that skip the tool-call prompt:
 * - Cline `autoApprove: [tools]` (docs.cline.bot/mcp/configuring-mcp-servers)
 * - Roo Code `alwaysAllow: [tools]` (roocodeinc.github.io/Roo-Code/features/mcp/using-mcp-in-roo)
 * - Gemini CLI `trust: true` (github.com/google-gemini/gemini-cli docs/tools/mcp-server.md)
 * Cursor, Windsurf and VS Code document no such per-server key.
 */
export function checkMcpAutoApprove(server) {
  const { name, def, file } = server;
  const hits = [];
  if (def.trust === true) {
    hits.push({
      rule: "mcp-auto-approve",
      severity: "high",
      title: `MCP server "${name}" is trusted: every tool call skips confirmation`,
      detail: "`\"trust\": true` (Gemini CLI) bypasses the confirmation for every tool this server offers, including tools it adds later. A prompt-injected agent gets the same pass. Remove it and approve tools one by one.",
      url: file,
    });
  }
  for (const key of ["autoApprove", "alwaysAllow"]) {
    const v = def[key];
    const all = v === true || v === "*" || (Array.isArray(v) && v.some((t) => t === "*"));
    const list = Array.isArray(v) ? v.filter((t) => typeof t === "string" && t !== "*") : [];
    if (!all && !list.length) continue;
    hits.push({
      rule: "mcp-auto-approve",
      severity: all ? "high" : "medium",
      title: `MCP server "${name}" auto-approves ${all ? "every tool" : `${list.length} tool${list.length === 1 ? "" : "s"}`}`,
      detail: `\`${key}\` ${all ? "approves every tool" : `approves \`${preview(list.join(", "), 100)}\``} without a prompt${key === "autoApprove" ? " (Cline)" : " (Roo Code)"}. Whatever the agent is told to do with ${all ? "them" : "those tools"}, injected instructions included, runs unasked. Keep auto-approval to read-only tools, or remove it.`,
      url: file,
    });
  }
  return hits;
}

/** Settings-level switches: Claude Code enableAllProjectMcpServers, VS Code chat auto-approve. */
export function checkApproveSettings(inv) {
  const hits = [];
  for (const s of inv.settings) {
    if (s.raw?.enableAllProjectMcpServers === true) {
      hits.push({
        rule: "mcp-auto-approve",
        severity: "medium",
        title: "Every MCP server in the project's .mcp.json starts without approval",
        detail: "`enableAllProjectMcpServers: true` (Claude Code) approves every server in `.mcp.json`, including one a pull request adds later, so its launch command runs without the per-server prompt. List the servers you reviewed in `enabledMcpjsonServers` instead.",
        url: s.file,
      });
    }
    hits.push(...checkEnvBlock(s.raw?.env, "Claude Code settings `env`", s.file));
  }
  for (const e of inv.editorSettings) {
    for (const key of ["chat.tools.global.autoApprove", "chat.tools.autoApprove"]) {
      if (e.raw?.[key] !== true) continue;
      hits.push({
        rule: "mcp-auto-approve",
        severity: "high",
        title: `VS Code approves every agent tool call (\`${key}\`)`,
        detail: `\`"${key}": true\` in workspace settings runs every chat tool, MCP tools and terminal commands included, without asking. VS Code's own docs warn it disables critical security protections. Remove it from the workspace settings.`,
        url: e.file,
      });
    }
  }
  return hits;
}

// ── VS Code tasks ─────────────────────────────────────────────────────────

function taskCommand(task) {
  const parts = [];
  for (const t of [task, task.windows, task.osx, task.linux]) {
    if (!t || typeof t !== "object") continue;
    const cmd = typeof t.command === "string" ? t.command : t.command?.value;
    if (typeof cmd === "string") parts.push(cmd);
    if (Array.isArray(t.args)) parts.push(...t.args.map((a) => (typeof a === "string" ? a : a?.value ?? "")));
  }
  return parts.join(" ").trim();
}

/** VS Code tasks that run when the folder opens (`runOptions.runOn: "folderOpen"`). */
export function checkTasks(inv) {
  const hits = [];
  for (const t of inv.tasks) {
    const command = taskCommand(t.task);
    if (t.runOn === "folderOpen") {
      const exec = findExecPatterns(command);
      // No "workspace allows automatic tasks" escalation: VS Code registers
      // task.allowAutomaticTasks with application scope, so a value in the
      // repo's .vscode/settings.json is ignored (task.contribution.ts).
      const severity = exec.length ? "critical" : "medium";
      hits.push({
        rule: "task-folder-open",
        severity,
        title: `VS Code task "${preview(t.label, 60)}" runs when the folder opens`,
        detail: `\`runOptions.runOn: "folderOpen"\` runs \`${preview(command || "(no command)", 120)}\` when a trusted workspace opens. Current VS Code (\`task.allowAutomaticTasks\` defaults to \`off\`) shows a one-time notification per workspace, and Allow runs it and turns automatic tasks on for every trusted workspace; with the setting \`on\` it runs with no prompt, and only an \`off\` the user set themselves stops both. The repo cannot change that setting. ${exec.length ? `The command contains a ${exec[0].label}. ` : ""}Coding agents and teammates open folders all the time. Remove \`runOn\`, or run the task by hand.`,
        url: t.file,
      });
    }
    const env = t.task.options?.env;
    hits.push(...checkEnvBlock(env, `VS Code task "${preview(t.label, 60)}"`, t.file));
  }
  return hits;
}

// ── Hooks: local scripts, loader variables, registries ───────────────────

const SCRIPT_EXT = /\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|mts|rb|pl|ps1)$/i;
const SEGMENT_START = new Set(["&&", "||", ";", "|", "then", "do"]);
const INTERPRETER = /^(?:node|nodejs|bash|sh|zsh|dash|ksh|python[0-9.]*|ruby|perl|pwsh|powershell|deno|bun|tsx|ts-node|uv|source|\.)$/i;
const BASE_MARK = /\u0000(CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)\u0000/g;
const PACKAGE_BIN = /(?:^|[/\\])node_modules[/\\]\.bin[/\\][^/\\]+$/;
const HOOK_VARS = String.raw`\$\{?(CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT)\b\}?`;
// "$CLAUDE_PROJECT_DIR"/rest and "$CLAUDE_PROJECT_DIR/rest" (one quoted
// word, maybe followed by an unquoted tail), or a bare $CLAUDE_PROJECT_DIR/rest.
const HOOK_VAR_WORD = new RegExp(String.raw`"${HOOK_VARS}([^"\n]*)"([^\s"';|&]*)|${HOOK_VARS}([^\s"';|&]*)`, "g");

/**
 * Expand Claude Code's hook variables to the base folder, keeping the result
 * one quoted word: the documented \`"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh\`
 * becomes \`"/repo/.claude/hooks/x.sh"\`, not \`"/repo"\` and a stray path.
 */
export function expandHookVars(command, baseDir) {
  const base = typeof baseDir === "function" ? baseDir : () => baseDir || ".";
  return String(command).replace(HOOK_VAR_WORD, (_, v1, inner, tail, v2, bare) => `"${base(v1 ?? v2)}${bare ?? `${inner}${tail}`}"`);
}

// A path with a space in it (`"$CLAUDE_PROJECT_DIR/.claude/hooks/my hook.js"`,
// one quoted word) is a file only when it has a folder and a script
// extension; other words with spaces are text, not paths.
const looksLikeFile = (t) => !!t && !/:\/\//.test(t) && !/[$`*?\t\r\n]/.test(t)
  && (!/ /.test(t) || (SCRIPT_EXT.test(t) && /[/\\]/.test(t)))
  && (SCRIPT_EXT.test(t) || /[/\\]/.test(t));
// Package runners that start an interpreter by name: `npx tsx x.ts`.
const PACKAGE_RUNNER = /^(?:npx|bunx|pnpx)$/i;

/**
 * The local script file a hook command runs, if any: { token, path }. A
 * script is the first word of a command (`./x.sh`, `.claude/hooks/x.py`) or
 * the first non-flag argument of an interpreter (`node ./x.js`, `bash a.sh`,
 * `python .claude/hooks/x.py`). Arguments of other commands (`prettier
 * src/a.ts`) are not scripts the hook runs.
 */
export function hookScriptTarget(command, baseDir) {
  // The variables expand to a marker first, so a base folder with a space in
  // it still splits as one word and passes the file test; the marker becomes
  // the folder in `path` and the variable name in `token`.
  const tokens = splitCommand(expandHookVars(command, (v) => `\u0000${v}\u0000`)).map((t) => t.replace(/;$/, ""));
  const toTarget = (raw) => {
    const tok = raw.replace(BASE_MARK, "$$$1");
    const p = raw.replace(BASE_MARK, () => baseDir || ".");
    return { token: tok, path: p.startsWith("~/") ? null : isAbsolute(p) ? p : resolve(baseDir || ".", p) };
  };
  for (let i = 0; i < tokens.length; i++) {
    if (!(i === 0 || SEGMENT_START.has(tokens[i - 1]))) continue;
    let j = i;
    while (j < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[j])) j++; // FOO=bar cmd
    if (tokens[j] && PACKAGE_RUNNER.test(basename(tokens[j]))) {
      // npx [-y] [--package x] tsx script.ts: the interpreter is the word
      // after the runner's own flags. Anything else (`npx prettier src/a.ts`)
      // is a package, not a script the project keeps.
      j++;
      while (j < tokens.length && tokens[j].startsWith("-")) j += /^(?:-p|--package)$/.test(tokens[j]) ? 2 : 1;
      if (!tokens[j] || !INTERPRETER.test(basename(tokens[j]))) continue;
    }
    const first = tokens[j];
    if (!first) continue;
    if (!INTERPRETER.test(basename(first))) {
      // node_modules/.bin/prettier is a package binary (`penthera deps`
      // reads those), not a script the project keeps.
      if (looksLikeFile(first) && /[/\\]/.test(first) && !PACKAGE_BIN.test(first)) return toTarget(first);
      continue;
    }
    for (let k = j + 1; k < tokens.length && !SEGMENT_START.has(tokens[k]); k++) {
      const a = tokens[k];
      if (a === "-c" || a === "-m" || a === "-e" || a === "--eval" || a === "-p") break; // inline code or a module, not a file
      if (a.startsWith("-") || a === "run") continue;
      if (looksLikeFile(a)) return toTarget(a);
      break;
    }
  }
  return null;
}

function hookLocalScriptHit(h, where) {
  const command = typeof h.hook.command === "string" ? h.hook.command : "";
  const target = hookScriptTarget(command, h.baseDir);
  if (!target) return null;
  const found = !!target.path && isFile(target.path);
  // The same check hookScript reads by: symlinks resolved, inside the base folder.
  const readable = found && !!h.baseDir && insideReal(target.path, h.baseDir);
  return {
    rule: "hook-local-script",
    severity: readable ? "low" : "medium",
    title: `${where} hook runs a local script: ${preview(target.token, 80)}`,
    detail: readable
      ? `The hook runs \`${preview(target.token, 100)}\` on every matching event, with no prompt. The script is not in the settings file, so a change to it changes what runs without a settings diff; Penthera read it with the hook rules above. Review the script and keep it under code review.`
      : `The hook runs \`${preview(target.token, 100)}\` on every matching event, with no prompt, and the script ${found ? "resolves outside the scanned project, so Penthera did not read it" : "is not among the scanned files (not on disk, or not part of this scan), so Penthera could not read it"}. Neither you nor Penthera can review what it runs from here. Keep hook scripts in the repository, where changes show up in review.`,
    url: h.file,
  };
}

/** Extra hook rules: local scripts, code-loading variables and registry redirects. */
export function checkHookExtras(h) {
  const hits = [];
  const command = typeof h.hook.command === "string" ? h.hook.command : "";
  if (!command) return hits;
  const where = `${h.event}${h.matcher ? ` (${h.matcher})` : ""}`;
  const local = hookLocalScriptHit(h, where);
  if (local) hits.push(local);
  const script = hookScript(h, command);
  const texts = [command, script?.text].filter((t) => typeof t === "string");
  const loader = texts.flatMap(findLoaderEnv)[0];
  if (loader) hits.push(loaderHit(`${where} hook`, loader.name, loader.value, h.file));
  const reg = worstRegistryMatch(texts.flatMap((t) => findRegistryRedirects(t)), "high");
  if (reg) hits.push(registryHit(reg, `${where} hook`, h.file, "high"));
  hits.push(...checkEnvBlock(h.hook.env, `${where} hook`, h.file));
  return hits;
}

/** Extra MCP rules: auto-approve keys, code-loading variables and registry redirects. */
export function checkMcpExtras(server) {
  const { name, def, file } = server;
  const hits = [...checkMcpAutoApprove(server)];
  hits.push(...checkEnvBlock(def.env, `MCP server "${name}"`, file));
  const reg = worstRegistryMatch(findRegistryRedirects(commandTokens(def).join(" ")), "medium");
  if (reg) hits.push(registryHit(reg, `MCP server "${name}"`, file, "medium"));
  return hits;
}
