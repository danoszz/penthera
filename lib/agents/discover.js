/**
 * Discover AI developer-tooling configuration in a repo and (opt-in) in the
 * user's home directory: MCP servers, hooks, permissions, skills, plugins,
 * marketplaces, and instruction files (AGENTS.md, CLAUDE.md, rules).
 *
 * Read-only. Nothing here writes, executes, or touches the network.
 */
import { readFileSync, readdirSync, statSync, lstatSync, existsSync, realpathSync } from "node:fs";
import { join, relative, dirname, basename, sep, resolve } from "node:path";
import { homedir } from "node:os";
import YAML from "yaml";

const SKIP_DIRS = new Set(["node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next"]);
/** The folders 2.0.0 skipped when it hashed a skill: version 1 lock files hash this way. */
export const LOCK_V1_SKIP_DIRS = SKIP_DIRS;
/**
 * Inside a skill folder only dependency trees and git metadata are skipped
 * outright. A skill ships what the agent reads and runs, so compiled code in
 * `__pycache__`, `build` or `dist` is exactly what a reviewer needs to see.
 * `node_modules` is a dependency tree of thousands of files that `penthera
 * deps` reads with its own rules, and `.git` is version-control metadata, not
 * skill content; both are recorded as not read instead of silently dropped.
 */
export const SKILL_SKIP_DIRS = new Set(["node_modules", ".git"]);

/** The folders of a Python virtual environment that hold installed packages and the interpreter. */
export const VENV_INTERNAL_DIRS = new Set(["bin", "Scripts", "lib", "lib64", "Lib", "include", "Include"]);

function lstatOk(p) {
  try { return lstatSync(p); } catch { return null; }
}

/**
 * Is `dir` a real Python virtual environment? A name (`.venv`) or an empty
 * `pyvenv.cfg` is not enough, since anyone can create either to hide a
 * folder. All three must hold:
 *   - `pyvenv.cfg` is a small file with a `home =` key;
 *   - `bin/` (or `Scripts/`) holds a `python` executable (a file or a link);
 *   - `lib/pythonX.Y/site-packages` (or `Lib/site-packages`) is a folder.
 */
export function isRealVenv(dir) {
  const cfg = join(dir, "pyvenv.cfg");
  const st = lstatOk(cfg);
  if (!st?.isFile() || st.size > 64 * 1024) return false;
  let text = "";
  try { text = readFileSync(cfg, "utf-8"); } catch { return false; }
  if (!/^[ \t]*home[ \t]*=/m.test(text)) return false;
  const hasPython = (d) => {
    let names = [];
    try { names = readdirSync(join(dir, d)); } catch { return false; }
    return names.some((n) => {
      if (!/^python(?:[0-9.]*|w)?(?:\.exe)?$/i.test(n)) return false;
      const st = lstatOk(join(dir, d, n));
      return !!st && !st.isDirectory();
    });
  };
  if (!hasPython("bin") && !hasPython("Scripts")) return false;
  if (isDir(join(dir, "Lib", "site-packages"))) return true;
  let libs = [];
  try { libs = readdirSync(join(dir, "lib")); } catch { return false; }
  return libs.some((n) => /^python\d+(?:\.\d+)?$/.test(n) && isDir(join(dir, "lib", n, "site-packages")));
}

/**
 * Skip test for scanning a skill folder: `node_modules` and `.git`, plus the
 * package and interpreter folders (`bin`, `lib`, `include`, ...) of a real
 * virtual environment. The venv's other files (anything at its top level, or
 * in folders a venv does not make) are still scanned, and the whole venv is
 * still hashed in penthera.lock.
 */
export function skillSkipDir(name, full) {
  if (SKILL_SKIP_DIRS.has(name)) return true;
  return VENV_INTERNAL_DIRS.has(name) && isRealVenv(dirname(full));
}

export const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_WALK_FILES = 5000;

// ── Small helpers ─────────────────────────────────────────────────────────

/** JSON.parse that tolerates // and /* *\/ comments and trailing commas (JSONC). */
export function parseJsonc(text) {
  try {
    return JSON.parse(text);
  } catch {
    let out = "";
    let inStr = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inStr) {
        out += ch;
        if (ch === "\\") { out += text[++i] ?? ""; continue; }
        if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') { inStr = true; out += ch; continue; }
      if (ch === "/" && text[i + 1] === "/") { while (i < text.length && text[i] !== "\n") i++; out += "\n"; continue; }
      if (ch === "/" && text[i + 1] === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i++; continue; }
      out += ch;
    }
    return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
  }
}

function isFile(p) {
  try { return statSync(p).isFile(); } catch { return false; }
}
function isDir(p) {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

export function readText(p) {
  try {
    const st = statSync(p);
    if (!st.isFile()) return null;
    if (st.size > MAX_FILE_BYTES) return { tooLarge: true, size: st.size };
    return readFileSync(p, "utf-8");
  } catch {
    return null;
  }
}

/** Parse YAML frontmatter from a Markdown file. Returns {} when absent or invalid. */
export function parseFrontmatter(text) {
  const m = /^﻿?---\r?\n([\s\S]*?)\r?\n---\r?(?:\n|$)/.exec(text || "");
  if (!m) return {};
  try {
    const fm = YAML.parse(m[1]);
    return fm && typeof fm === "object" ? fm : {};
  } catch {
    return {};
  }
}

/**
 * Walk a directory without following symlinks. Returns files and symlinks
 * (relative to `dir`), bounded so a hostile tree can't hang the scan.
 */
export function walk(dir, { maxDepth = 12, maxFiles = MAX_WALK_FILES, skipDirs = SKIP_DIRS } = {}) {
  const skip = typeof skipDirs === "function" ? skipDirs : (name) => skipDirs.has(name);
  const files = [];
  const symlinks = [];
  const skipped = [];
  let truncated = false; // anything left unread: the file cap, depth, an unreadable folder
  let capped = false;    // the file cap alone
  const stop = () => { truncated = true; capped = true; };
  const visit = (d, depth) => {
    if (files.length >= maxFiles) { stop(); return; }
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { truncated = true; return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (files.length >= maxFiles) { stop(); return; }
      const full = join(d, e.name);
      if (e.isSymbolicLink()) { symlinks.push(full); continue; }
      if (e.isDirectory()) {
        if (skip(e.name, full)) { skipped.push(full); continue; }
        if (depth >= maxDepth) { truncated = true; continue; }
        visit(full, depth + 1);
      } else if (e.isFile()) {
        files.push(full);
      }
    }
  };
  visit(dir, 0);
  return { files, symlinks, truncated, capped, skipped };
}

// ── Inventory ─────────────────────────────────────────────────────────────

function createInventory(root, homeDir, includeHome) {
  const display = (p) => {
    const abs = resolve(p);
    if (abs === root || abs.startsWith(root + sep)) return relative(root, abs) || ".";
    if (homeDir && (abs === homeDir || abs.startsWith(homeDir + sep))) return "~/" + relative(homeDir, abs).split(sep).join("/");
    return abs;
  };
  return {
    root,
    homeDir: includeHome ? homeDir : null,
    display,
    configFiles: [],      // every config file read: { path, display }
    instructionFiles: [], // Markdown/rule files a model reads: { path, display, scope }
    skills: [],           // { name, dir, display, skillFile, frontmatter, scope }
    mcpServers: [],       // { name, def, file, scope }
    hooks: [],            // { event, matcher, hook, file, key, baseDir }
    permissions: [],      // { rule, list, file }
    settings: [],         // { file, defaultMode, raw }
    marketplaces: [],     // { name, source, file }
    plugins: [],          // { id, installPath, version, gitCommitSha, file, enabled }
    pluginSources: [],    // plugin entries listed in a marketplace.json: { name, source, file }
    tasks: [],            // VS Code tasks: { label, task, runOn, file }
    editorSettings: [],   // VS Code workspace settings: { file, raw }
    notRead: [],          // agent config present on disk that no rule reads: { file, what }
    registryFiles: [],    // package-manager config shipped in a plugin folder: { path, display }
    errors: [],           // { file, message }
  };
}

/**
 * A JSON.parse error without the file's content. V8 quotes the text around
 * the error ("Unexpected token 'S', \"SECRETVALU\"..."); a finding must not
 * carry that into a terminal, a job log or SARIF.
 */
export function jsonErrorMessage(e) {
  const msg = String(e?.message ?? e ?? "");
  if (/^Unexpected end of JSON input/.test(msg)) return "invalid JSON: unexpected end of input";
  const lc = /\(line (\d+) column (\d+)\)/.exec(msg);
  if (lc) return `invalid JSON at line ${lc[1]}, column ${lc[2]}`;
  const pos = /at position (\d+)/.exec(msg);
  return pos ? `invalid JSON at position ${pos[1]}` : "invalid JSON";
}

/** Does `p`, symlinks resolved, sit inside `base` (also resolved)? */
export function resolvesInside(p, base) {
  let rp;
  let rb;
  try { rp = realpathSync(p); } catch { return false; }
  try { rb = realpathSync(base); } catch { rb = resolve(base); }
  return rp === rb || rp.startsWith(rb.endsWith(sep) ? rb : rb + sep);
}

/**
 * Read a JSON(C) config. With `base` (the project or a plugin folder), a file
 * that resolves outside it through a symlink is not read: it is listed under
 * Not checked instead, so a repo cannot make the scan quote a file elsewhere
 * on the machine.
 */
function loadJson(inv, path, base = null) {
  if (base && !resolvesInside(path, base)) {
    if (!inv.notRead.some((n) => n.file === inv.display(path))) {
      inv.notRead.push({ file: inv.display(path), what: "resolves outside the project through a symlink" });
    }
    return null;
  }
  const text = readText(path);
  if (text == null) return null;
  if (typeof text === "object") {
    inv.errors.push({ file: inv.display(path), message: `larger than ${MAX_FILE_BYTES} bytes, not parsed` });
    return null;
  }
  try {
    const json = parseJsonc(text);
    inv.configFiles.push({ path, display: inv.display(path) });
    return json;
  } catch (e) {
    inv.errors.push({ file: inv.display(path), message: jsonErrorMessage(e) });
    return null;
  }
}

function addMcpServers(inv, servers, file, scope) {
  if (!servers || typeof servers !== "object") return;
  for (const [name, def] of Object.entries(servers)) {
    if (def && typeof def === "object") inv.mcpServers.push({ name, def, file, scope });
  }
}

function addMcpFile(inv, path, scope, base = null) {
  const json = loadJson(inv, path, base);
  if (!json) return;
  // Claude/Cursor/Desktop use `mcpServers`; VS Code uses `servers`.
  addMcpServers(inv, json.mcpServers || json.servers, inv.display(path), scope);
}

function addHooks(inv, hooksObj, file, baseDir) {
  if (!hooksObj || typeof hooksObj !== "object") return;
  for (const [event, groups] of Object.entries(hooksObj)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((group, gi) => {
      const matcher = group?.matcher ?? "";
      const list = Array.isArray(group?.hooks) ? group.hooks : [group];
      list.forEach((hook, hi) => {
        if (!hook || typeof hook !== "object") return;
        inv.hooks.push({
          event,
          matcher,
          hook,
          file,
          baseDir,
          key: `hook:${file}#${event}[${matcher || "*"}]/${gi}.${hi}`,
        });
      });
    });
  }
}

function addSettingsFile(inv, path, scope, base = null) {
  const json = loadJson(inv, path, base);
  if (!json) return;
  const file = inv.display(path);
  const projectDir = scope === "repo" ? inv.root : dirname(dirname(path));
  inv.settings.push({ file, defaultMode: json.permissions?.defaultMode ?? null, raw: json });
  addHooks(inv, json.hooks, file, projectDir);
  for (const list of ["allow", "ask", "deny"]) {
    const rules = json.permissions?.[list];
    if (Array.isArray(rules)) for (const rule of rules) inv.permissions.push({ rule: String(rule), list, file });
  }
  addMcpServers(inv, json.mcpServers, file, scope);
  const mk = json.extraKnownMarketplaces;
  if (mk && typeof mk === "object") {
    for (const [name, v] of Object.entries(mk)) inv.marketplaces.push({ name, source: v?.source ?? v, file });
  }
}

/**
 * With `base` (the project or a plugin folder): is `path` inside it once
 * symlinks resolve? When it is not, it is listed under Not checked and the
 * caller reads nothing from it, so a symlinked CLAUDE.md or skills/ folder
 * cannot make the scan quote a file elsewhere on the machine.
 */
function contained(inv, path, base) {
  if (!base || resolvesInside(path, base)) return true;
  const file = inv.display(path);
  const what = base === inv.root ? "resolves outside the project through a symlink" : "resolves outside the plugin folder through a symlink";
  if (!inv.notRead.some((n) => n.file === file)) inv.notRead.push({ file, what });
  return false;
}

function addInstructionFile(inv, path, scope, base = null) {
  if (!isFile(path) || !contained(inv, path, base)) return;
  inv.instructionFiles.push({ path, display: inv.display(path), scope });
}

function addMarkdownDir(inv, dir, scope, base = null) {
  if (!isDir(dir) || !contained(inv, dir, base)) return;
  // walk() does not follow symlinks below `dir`, so every file is inside it.
  for (const f of walk(dir, { maxDepth: 6 }).files) {
    if (/\.(?:md|mdc|markdown|txt)$/i.test(f)) addInstructionFile(inv, f, scope);
  }
}

function isSkillFileName(name) {
  return name.toLowerCase() === "skill.md";
}

function addSkill(inv, skillFile, text, scope) {
  const skillDir = dirname(skillFile);
  const fm = typeof text === "string" ? parseFrontmatter(text) : {};
  inv.skills.push({
    name: typeof fm.name === "string" ? fm.name : basename(skillDir),
    dir: skillDir,
    display: inv.display(skillDir),
    skillFile,
    frontmatter: fm,
    scope,
  });
}

function addSkillsUnder(inv, dir, scope, base = null) {
  if (!isDir(dir) || !contained(inv, dir, base)) return;
  const seen = new Set(inv.skills.map((s) => s.dir));
  for (const f of walk(dir, { maxDepth: 6 }).files) {
    if (!isSkillFileName(basename(f))) continue;
    const skillDir = dirname(f);
    if (seen.has(skillDir)) continue;
    seen.add(skillDir);
    addSkill(inv, f, readText(f), scope);
  }
}

/**
 * The folder the user named is itself a skill: a downloaded one, before it is
 * installed. Only with `skillTarget`: a project scan never counts its root.
 * A SKILL.md that is a symlink still counts, or a link could take the whole
 * folder out of the scan. Its target is read only when it stays inside the
 * folder; a link that leaves is a symlink-escape finding.
 */
function addRootSkill(inv) {
  const r = inv.root;
  let names = [];
  try {
    names = readdirSync(r, { withFileTypes: true })
      .filter((e) => isSkillFileName(e.name) && (e.isFile() || e.isSymbolicLink()))
      .map((e) => e.name);
  } catch { return; }
  if (!names.length) return;
  const f = join(r, names.sort()[0]);
  addSkill(inv, f, resolvesInside(f, r) ? readText(f) : null, "repo");
  inv.skills.at(-1).target = true;
}

function addPluginDir(inv, pluginDir, scope) {
  // A plugin that ships its own .npmrc or pip.conf changes where installs run from.
  for (const f of [".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini"]) {
    const p = join(pluginDir, f);
    if (!isFile(p) || inv.registryFiles.some((r) => r.path === p)) continue;
    if (resolvesInside(p, pluginDir)) inv.registryFiles.push({ path: p, display: inv.display(p) });
    else inv.notRead.push({ file: inv.display(p), what: "resolves outside the plugin folder through a symlink" });
  }
  addSkillsUnder(inv, join(pluginDir, "skills"), scope, pluginDir);
  addMarkdownDir(inv, join(pluginDir, "commands"), scope, pluginDir);
  addMarkdownDir(inv, join(pluginDir, "agents"), scope, pluginDir);
  const hooksFile = join(pluginDir, "hooks", "hooks.json");
  if (isFile(hooksFile)) {
    const json = loadJson(inv, hooksFile, pluginDir);
    if (json) addHooks(inv, json.hooks || json, inv.display(hooksFile), pluginDir);
  }
  const mcp = join(pluginDir, ".mcp.json");
  if (isFile(mcp)) addMcpFile(inv, mcp, scope, pluginDir);
  const manifest = join(pluginDir, ".claude-plugin", "plugin.json");
  if (isFile(manifest)) {
    const json = loadJson(inv, manifest, pluginDir);
    if (json) {
      if (json.mcpServers && typeof json.mcpServers === "object") addMcpServers(inv, json.mcpServers, inv.display(manifest), scope);
      if (json.hooks && typeof json.hooks === "object") addHooks(inv, json.hooks.hooks || json.hooks, inv.display(manifest), pluginDir);
    }
  }
}

function addMarketplaceManifest(inv, path) {
  const json = loadJson(inv, path, inv.root);
  if (!json || !Array.isArray(json.plugins)) return;
  for (const p of json.plugins) {
    if (p && typeof p === "object") inv.pluginSources.push({ name: p.name || "(unnamed)", source: p.source, file: inv.display(path) });
  }
}

/** VS Code tasks.json (JSONC): every task, with its runOn trigger. */
function addTasksFile(inv, path) {
  const json = loadJson(inv, path, inv.root);
  if (!json || !Array.isArray(json.tasks)) return;
  const file = inv.display(path);
  json.tasks.forEach((task, i) => {
    if (!task || typeof task !== "object") return;
    const label = typeof task.label === "string" ? task.label : typeof task.taskName === "string" ? task.taskName : `task ${i + 1}`;
    inv.tasks.push({ label, task, runOn: task.runOptions?.runOn ?? null, file });
  });
}

/**
 * Agent configuration Penthera knows about but has no rules for yet. Listed
 * so a clean result never reads as "everything was checked".
 */
const NOT_READ_REPO = [
  [".codex/config.toml", "Codex config (MCP servers in TOML)"],
  [".cursor/hooks.json", "Cursor hooks"],
  [".windsurf", "Windsurf rules and workflows"],
  [".continue", "Continue config"],
  [".kiro", "Kiro steering and hooks"],
  [".amazonq", "Amazon Q rules and MCP config"],
  [".gemini/commands", "Gemini CLI custom commands"],
  ["opencode.json", "OpenCode config"],
  ["opencode.jsonc", "OpenCode config"],
  [".opencode", "OpenCode agents and commands"],
  [".zed/settings.json", "Zed settings (context servers)"],
  [".devcontainer/devcontainer.json", "Dev container lifecycle commands"],
  [".devcontainer.json", "Dev container lifecycle commands"],
];

// ── Repo ──────────────────────────────────────────────────────────────────

const SKILL_ROOTS = ["skills", ".claude/skills", ".cursor/skills", ".agents/skills", ".codex/skills"];
const INSTRUCTION_FILES = [
  "AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "GEMINI.md",
  ".cursorrules", ".windsurfrules", ".clinerules",
  ".github/copilot-instructions.md",
];

function discoverRepo(inv) {
  const r = inv.root;
  // Gemini CLI keeps its MCP servers in .gemini/settings.json, Roo Code in .roo/mcp.json.
  for (const f of [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".roo/mcp.json"]) {
    if (isFile(join(r, f))) addMcpFile(inv, join(r, f), "repo", r);
  }
  if (isFile(join(r, ".vscode", "tasks.json"))) addTasksFile(inv, join(r, ".vscode", "tasks.json"));
  if (isFile(join(r, ".vscode", "settings.json"))) {
    const json = loadJson(inv, join(r, ".vscode", "settings.json"), r);
    if (json && typeof json === "object") inv.editorSettings.push({ file: inv.display(join(r, ".vscode", "settings.json")), raw: json });
  }
  for (const [f, what] of NOT_READ_REPO) {
    if (isFile(join(r, f)) || isDir(join(r, f))) inv.notRead.push({ file: f, what });
  }
  for (const f of [".claude/settings.json", ".claude/settings.local.json"]) {
    if (isFile(join(r, f))) addSettingsFile(inv, join(r, f), "repo", r);
  }
  for (const f of INSTRUCTION_FILES) addInstructionFile(inv, join(r, f), "repo", r);
  if (isDir(join(r, ".clinerules"))) addMarkdownDir(inv, join(r, ".clinerules"), "repo", r);
  addMarkdownDir(inv, join(r, ".cursor", "rules"), "repo", r);
  addMarkdownDir(inv, join(r, ".github", "instructions"), "repo", r);
  addMarkdownDir(inv, join(r, ".claude", "commands"), "repo", r);
  addMarkdownDir(inv, join(r, ".claude", "agents"), "repo", r);
  for (const s of SKILL_ROOTS) addSkillsUnder(inv, join(r, s), "repo", r);
  // Plugins developed in this repo: plugins/<name>/{skills,hooks,...}. A
  // symlinked plugins/ is not followed; a symlinked plugins/<name> is not a
  // directory entry, so it is not followed either.
  if (isDir(join(r, "plugins")) && contained(inv, join(r, "plugins"), r)) {
    for (const e of readdirSync(join(r, "plugins"), { withFileTypes: true })) {
      if (e.isDirectory()) addPluginDir(inv, join(r, "plugins", e.name), "repo");
    }
  }
  if (isFile(join(r, ".claude-plugin", "marketplace.json"))) addMarketplaceManifest(inv, join(r, ".claude-plugin", "marketplace.json"));
  if (isFile(join(r, ".claude-plugin", "plugin.json"))) addPluginDir(inv, r, "repo");
}

// ── Home ──────────────────────────────────────────────────────────────────

/**
 * `appData` is the real %APPDATA%, used only when the scan reads this user's
 * own home. With an explicit `homeDir` (a copied or mounted home folder) it is null,
 * so the scan never also reads the real user's files.
 */
export function claudeDesktopConfigPaths(homeDir, platform = process.platform, appData = process.env.APPDATA) {
  const out = [];
  if (platform === "darwin") out.push(join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"));
  if (platform === "win32") out.push(join(appData || join(homeDir, "AppData", "Roaming"), "Claude", "claude_desktop_config.json"));
  out.push(join(homeDir, ".config", "Claude", "claude_desktop_config.json"));
  return out;
}

/**
 * MCP settings that VS Code extensions keep in globalStorage: Cline
 * (`autoApprove`) and Roo Code (`alwaysAllow`). Both extensions also run in
 * VS Code forks, which keep globalStorage under their own app folder. Every
 * OS layout is checked under the home folder, so a scan of a copied home
 * folder finds them too.
 */
export const VSCODE_APPS = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"];
export const VSCODE_EXTENSION_MCP_FILES = [
  ["saoudrizwan.claude-dev", "cline_mcp_settings.json"],
  ["rooveterinaryinc.roo-cline", "mcp_settings.json"],
];

export function vscodeGlobalStoragePaths(homeDir, platform = process.platform, appData = process.env.APPDATA) {
  const userDirs = [
    join(homeDir, "Library", "Application Support"), // macOS
    join(homeDir, ".config"),                        // Linux
    join(homeDir, "AppData", "Roaming"),             // Windows
  ];
  if (platform === "win32" && appData) userDirs.push(appData);
  const out = [];
  for (const d of [...new Set(userDirs)]) {
    for (const app of VSCODE_APPS) {
      for (const [ext, file] of VSCODE_EXTENSION_MCP_FILES) out.push(join(d, app, "User", "globalStorage", ext, "settings", file));
    }
  }
  return out;
}

function discoverHome(inv, homeDir) {
  const claude = join(homeDir, ".claude");
  for (const f of ["settings.json", "settings.local.json"]) {
    if (isFile(join(claude, f))) addSettingsFile(inv, join(claude, f), "home");
  }
  addInstructionFile(inv, join(claude, "CLAUDE.md"), "home");
  addSkillsUnder(inv, join(claude, "skills"), "home");
  addSkillsUnder(inv, join(homeDir, ".agents", "skills"), "home");
  addSkillsUnder(inv, join(homeDir, ".cursor", "skills"), "home");
  addMarkdownDir(inv, join(claude, "commands"), "home");
  addMarkdownDir(inv, join(claude, "agents"), "home");

  // User-scoped MCP servers for Claude Code live in ~/.claude.json, top level
  // and per project. Only the scanned project's entry is read.
  const userJsonPath = join(homeDir, ".claude.json");
  if (isFile(userJsonPath)) {
    const json = loadJson(inv, userJsonPath);
    if (json) {
      addMcpServers(inv, json.mcpServers, inv.display(userJsonPath), "home");
      const proj = json.projects?.[inv.root];
      if (proj?.mcpServers) addMcpServers(inv, proj.mcpServers, `${inv.display(userJsonPath)} (project ${basename(inv.root)})`, "home");
    }
  }

  if (isFile(join(homeDir, ".cursor", "mcp.json"))) addMcpFile(inv, join(homeDir, ".cursor", "mcp.json"), "home");
  if (isFile(join(homeDir, ".gemini", "settings.json"))) addMcpFile(inv, join(homeDir, ".gemini", "settings.json"), "home");
  // The real %APPDATA% belongs to this user's home, not to an explicit homeDir.
  const appData = inv.explicitHome ? null : process.env.APPDATA;
  for (const p of claudeDesktopConfigPaths(homeDir, process.platform, appData)) {
    if (isFile(p)) addMcpFile(inv, p, "home");
  }
  for (const p of vscodeGlobalStoragePaths(homeDir, process.platform, appData)) {
    if (isFile(p)) addMcpFile(inv, p, "home");
  }

  // Plugins and the marketplaces they come from.
  const pluginsDir = join(claude, "plugins");
  const known = isFile(join(pluginsDir, "known_marketplaces.json")) ? loadJson(inv, join(pluginsDir, "known_marketplaces.json")) : null;
  if (known && typeof known === "object") {
    const file = inv.display(join(pluginsDir, "known_marketplaces.json"));
    for (const [name, v] of Object.entries(known)) {
      if (!inv.marketplaces.some((m) => m.name === name)) inv.marketplaces.push({ name, source: v?.source ?? v, file });
    }
  }
  const enabled = new Set();
  for (const s of inv.settings) {
    const ep = s.raw?.enabledPlugins;
    if (ep && typeof ep === "object") for (const [id, on] of Object.entries(ep)) if (on) enabled.add(id);
  }
  const installed = isFile(join(pluginsDir, "installed_plugins.json")) ? loadJson(inv, join(pluginsDir, "installed_plugins.json")) : null;
  const pluginMap = installed?.plugins && typeof installed.plugins === "object" ? installed.plugins : {};
  const file = inv.display(join(pluginsDir, "installed_plugins.json"));
  for (const [id, entries] of Object.entries(pluginMap)) {
    for (const e of Array.isArray(entries) ? entries : [entries]) {
      if (!e || typeof e !== "object") continue;
      inv.plugins.push({
        id,
        installPath: e.installPath || null,
        version: e.version || null,
        gitCommitSha: e.gitCommitSha || null,
        file,
        enabled: enabled.has(id),
      });
      if (e.installPath && isDir(e.installPath)) addPluginDir(inv, e.installPath, `plugin:${id}`);
    }
  }
}

/**
 * The folder `penthera agents <path>` audits: the path itself, or the folder
 * of a direct path to a SKILL.md. Null for any other file, which is no target.
 */
export function agentsTarget(path) {
  if (isDir(path)) return path;
  return isFile(path) && isSkillFileName(basename(path)) ? dirname(path) : null;
}

/**
 * Discover agent configuration.
 * @param {string} root - repo root
 * @param {object} [opts] { home: boolean, homeDir: string, skillTarget: boolean }
 */
export function discoverAgentConfig(root, opts = {}) {
  const absRoot = resolve(root);
  let canonical = absRoot;
  try { canonical = realpathSync(absRoot); } catch { /* keep as given */ }
  const homeDir = resolve(opts.homeDir || homedir());
  const inv = createInventory(canonical, homeDir, !!opts.home);
  inv.explicitHome = !!opts.homeDir;
  if (existsSync(canonical)) discoverRepo(inv);
  if (opts.skillTarget && existsSync(canonical)) addRootSkill(inv);
  if (opts.home) discoverHome(inv, homeDir);
  return inv;
}

export { isFile, isDir };
