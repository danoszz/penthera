/**
 * Penthera, agents mode: an offline, deterministic audit of the AI developer
 * tooling configured in a repo and (with --home) on this machine.
 *
 * No network, no LLM judge, no registry lookups. Every verdict is a rule you
 * can read, so a skill cannot argue its way past it.
 */
import { readFileSync, realpathSync, statSync, lstatSync, openSync, readSync, closeSync } from "node:fs";
import { relative, sep, extname, basename, dirname, join } from "node:path";
import { discoverAgentConfig, walk, parseFrontmatter, MAX_FILE_BYTES, skillSkipDir, jsonErrorMessage, VENV_INTERNAL_DIRS, resolvesInside } from "./discover.js";
import { scanHiddenContent, sniffBinary, BINARY_EXTENSIONS, MEDIA_EXTENSIONS } from "./hidden-content.js";
import {
  checkMcpServer, checkHook, checkPermissions, checkAllowedTools, checkMarketplaces,
  checkMcpExtras, checkHookExtras, checkTasks, checkApproveSettings, findRegistryRedirects,
  registrySeverity, registryDetail, worstRegistryMatch,
} from "./rules.js";
import { computeLockEntries, diffLock, readLock, writeLock, lockPath, LOCK_FILENAME, LOCK_VERSION } from "./lock.js";
import { owaspFor, owaspLabel } from "./owasp.js";
import { gradeFindings } from "./grade.js";

export { scanHiddenContent } from "./hidden-content.js";
export { discoverAgentConfig, agentsTarget } from "./discover.js";

const SOURCE = "agents-scan";
export const NOT_CHECKED_TOOL_DESCRIPTIONS = "MCP tool descriptions: servers are not started, so tool-description poisoning is not checked.";
export const NOTHING_TO_ASSESS = "Nothing to assess: no skills, MCP servers, hooks, permissions, plugins or rule files at the paths Penthera reads. This is not a clean result.";
const CATEGORY = "agent-config";

/** Turn a rule hit into a finding in Penthera's standard shape. */
export function toFinding(hit) {
  const ids = owaspFor(hit.rule);
  const mapping = ids.length ? ` [${owaspLabel(ids)}]` : "";
  return {
    severity: hit.severity,
    title: hit.title,
    description: `${hit.detail}${hit.line ? ` (line ${hit.line})` : ""}${mapping}`,
    url: hit.url,
    category: CATEGORY,
    source: SOURCE,
    templateId: `agents/${hit.rule}`,
    owasp: ids,
    confidence: hit.confidence || (hit.severity === "info" ? "confirmed" : "likely"),
  };
}

// ── Content scanning ──────────────────────────────────────────────────────

/** High, so a named skill Penthera read only in part can never grade A. */
function notReadHit(path, display, e) {
  return {
    rule: "config-unparsed",
    severity: "high",
    title: "Skill file could not be read",
    detail: `${e.code || e.message}. This file was not checked. Review it by hand.`,
    url: display,
  };
}

function scanTextFile(path, display, hits, { registry = false, target = false } = {}) {
  let buf;
  try {
    const st = statSync(path);
    if (st.size > MAX_FILE_BYTES) {
      hits.push({
        rule: "file-too-large",
        severity: target ? "high" : "medium",
        title: "File too large to scan",
        detail: `${(st.size / 1024 / 1024).toFixed(1)} MB, over the ${MAX_FILE_BYTES / 1024 / 1024} MB limit. Padding a file past a scanner's size limit is a known way to hide a payload; review it by hand.`,
        url: display,
      });
      return;
    }
    buf = readFileSync(path);
  } catch (e) {
    if (target) hits.push(notReadHit(path, display, e));
    return;
  }
  const binary = sniffBinary(buf);
  if (binary) {
    hits.push({
      rule: "embedded-binary",
      severity: "high",
      title: `Embedded ${binary}`,
      detail: `A ${binary} inside agent instructions cannot be reviewed as text, and agents can be told to unpack or run it.`,
      url: display,
    });
    return;
  }
  if (buf.subarray(0, 8192).includes(0)) {
    hits.push({
      rule: "unknown-binary",
      severity: "medium",
      title: "Unrecognised binary file",
      detail: "A binary file of unknown type sits next to agent instructions. Check what it is and why it is there.",
      url: display,
    });
    return;
  }
  const text = buf.toString("utf-8");
  for (const h of scanHiddenContent(text)) hits.push({ ...h, url: display });
  if (registry) {
    const r = worstRegistryMatch(findRegistryRedirects(text, path), "high");
    if (r) {
      hits.push({
        rule: "registry-redirect",
        severity: registrySeverity(r, "high"),
        title: "Agent instructions point the package manager at another registry",
        detail: `${registryDetail(r)} A skill or rule file that changes the registry decides what later installs get. Remove it; a company mirror belongs in your own user config.`,
        url: display,
      });
    }
  }
}

// The only name Python 3 gives a cache file: __pycache__/<module>.<tag>.pyc,
// with an optional .opt-1 or .opt-2. A module name has no dots.
const PYCACHE_NAME = /^([A-Za-z_][A-Za-z0-9_]*)\.[a-z]+-?\d+(?:\.opt-[12])?\.pyc$/;

/**
 * The Python source a .pyc is the ordinary cache of, or null. Only a file
 * Python itself would write and check against that source qualifies:
 *   - its name is exactly `__pycache__/<stem>.<tag>[.opt-N].pyc` and
 *     `../<stem>.py` exists;
 *   - its 16-byte header (PEP 552) says timestamp-based (flags 0): a
 *     hash-based pyc, checked or not, is not what a script run writes, and an
 *     unchecked one runs without looking at the source at all;
 *   - the source size recorded in the header equals the `.py` file's size.
 * A legacy `x.pyc` or `x.pyo` beside `x.py` never qualifies: Python 3 does
 * not write those.
 */
export function pycSource(f) {
  const dir = dirname(f);
  if (basename(dir) !== "__pycache__") return null;
  const m = PYCACHE_NAME.exec(basename(f));
  if (!m) return null;
  const src = join(dirname(dir), `${m[1]}.py`);
  let size;
  try {
    const st = statSync(src);
    if (!st.isFile()) return null;
    size = st.size;
  } catch {
    return null;
  }
  const head = Buffer.alloc(16);
  let n = 0;
  let fd;
  try {
    fd = openSync(f, "r");
    n = readSync(fd, head, 0, 16, 0);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* ignore */ }
  }
  if (n < 16 || head[2] !== 0x0d || head[3] !== 0x0a) return null;
  if (head.readUInt32LE(4) !== 0) return null;
  if (head.readUInt32LE(12) !== size % 2 ** 32) return null;
  return src;
}

const NOT_READ_SKILL_DIR = (d) => basename(d) === "node_modules"
  ? "dependency folder inside a skill (check it with `penthera deps`)"
  : basename(d) === ".git"
    ? "git metadata inside a skill"
    : /^(?:bin|Scripts)$/.test(basename(d))
      ? "interpreter and binaries of a Python virtual environment inside a skill (its text scripts were scanned; the folder is still pinned in penthera.lock)"
      : "installed packages of a Python virtual environment inside a skill (check them with `penthera deps --venv`; the folder is still pinned in penthera.lock)";

/** Text files in a venv's bin/ or Scripts/: content rules only, so a decoy cannot park a script there unread. */
function scanVenvScripts(venv, inv, hits, target) {
  for (const d of ["bin", "Scripts"]) {
    // A linked bin/ would lead the scan out of the skill folder.
    try { if (lstatSync(join(venv, d)).isSymbolicLink()) continue; } catch { continue; }
    for (const f of walk(join(venv, d), { maxDepth: 1, maxFiles: 500, skipDirs: () => true }).files) {
      let head = Buffer.alloc(0);
      try {
        if (statSync(f).size > MAX_FILE_BYTES) continue;
        head = readFileSync(f).subarray(0, 8192);
      } catch (e) {
        if (target) hits.push(notReadHit(f, inv.display(f), e));
        continue;
      }
      if (sniffBinary(head) || head.includes(0)) continue;
      scanTextFile(f, inv.display(f), hits, { registry: true, target });
    }
  }
}

/**
 * The SKILL.md of the folder the user named. It is what the agent reads, so
 * it is scanned whatever the walk did with it: a symlink into `node_modules`
 * or to a `.png`, or a name past the file cap. A link that leaves the folder
 * is not read, and is already a symlink-escape finding.
 */
function scanTargetSkillFile(skill, scanned, inv, hits) {
  const f = skill.skillFile;
  if (!resolvesInside(f, skill.dir)) return;
  try {
    if (!statSync(f).isFile()) throw new Error("not a regular file");
    closeSync(openSync(f, "r"));
  } catch (e) {
    hits.push({
      rule: "config-unparsed",
      severity: "high",
      title: "Skill file could not be read",
      detail: `${e.code || e.message}. The skill's instructions were not checked. Review it by hand.`,
      url: inv.display(f),
    });
    return;
  }
  if (!scanned) scanTextFile(f, inv.display(f), hits, { registry: true, target: true });
}

function scanSkillFolder(skill, inv, hits) {
  const { files, symlinks, truncated, capped, skipped } = walk(skill.dir, { skipDirs: skillSkipDir });
  const venvs = new Set();
  for (const d of skipped) {
    if (!skill.target || !inv.notRead.some((n) => n.file === inv.display(d))) inv.notRead.push({ file: inv.display(d), what: NOT_READ_SKILL_DIR(d) });
    if (VENV_INTERNAL_DIRS.has(basename(d))) venvs.add(dirname(d));
  }
  for (const v of venvs) {
    hits.push({
      rule: "skill-venv",
      severity: "medium",
      title: "Skill ships a Python virtual environment",
      detail: `\`${relative(skill.dir, v) || "."}\` is a virtual environment: an interpreter link and installed packages a reviewer cannot read as the skill. Its packages were not scanned here (use \`penthera deps --venv\`); its other files and the scripts in \`bin\`/\`Scripts\` were, and the whole folder is pinned in penthera.lock. Ship a requirements file instead and let the user create the environment.`,
      url: inv.display(v),
    });
    scanVenvScripts(v, inv, hits, skill.target);
  }
  let realDir = skill.dir;  try { realDir = realpathSync(skill.dir); } catch { /* keep */ }
  for (const l of symlinks) {
    let target = null;
    try { target = realpathSync(l); } catch { /* broken */ }
    if (!target || (target !== realDir && !target.startsWith(realDir + sep))) {
      hits.push({
        rule: "symlink-escape",
        severity: "high",
        title: "Symlink points outside the skill folder",
        detail: `\`${relative(skill.dir, l)}\` resolves to ${target ? `\`${inv.display(target)}\`` : "a missing target"}. Scanners that stay inside the folder never see what the agent reads through it.`,
        url: inv.display(l),
      });
    }
  }
  if (skill.target && truncated) {
    // High, so a folder Penthera read only in part can never grade A.
    hits.push({
      rule: "file-too-large",
      severity: "high",
      title: "Skill folder not read in full",
      detail: "Too many files, folders nested too deep, or a folder Penthera may not read. What it skipped was not checked. Review the folder by hand.",
      url: skill.display,
    });
  } else if (capped) {
    hits.push({
      rule: "file-too-large",
      severity: "medium",
      title: "Skill folder too large to scan fully",
      detail: "More files than the scanner's limit; the rest were not checked. Review the folder by hand.",
      url: skill.display,
    });
  }
  const caches = new Map(); // __pycache__ folder -> [source paths]
  for (const f of files) {
    const display = inv.display(f);
    const pySource = /\.pyc$/i.test(f) ? pycSource(f) : null;
    if (pySource) {
      // Python writes this cache the first time the skill's own script runs.
      const dir = dirname(f);
      if (!caches.has(dir)) caches.set(dir, []);
      caches.get(dir).push(pySource);
      continue;
    }
    if (BINARY_EXTENSIONS.test(f)) {
      let head = Buffer.alloc(0);
      try { head = readFileSync(f).subarray(0, 512); } catch { /* unreadable */ }
      const kind = sniffBinary(head) || `${extname(f)} file`;
      hits.push({
        rule: "embedded-binary",
        severity: "high",
        title: `Embedded ${kind} in skill`,
        detail: `Compiled code and archives in a skill cannot be reviewed as text. A skill can tell the agent to run or unpack them.`,
        url: display,
      });
      continue;
    }
    if (MEDIA_EXTENSIONS.test(f)) {
      // Check that "media" really is media; a renamed archive is a classic dodge.
      let head = Buffer.alloc(0);
      try { head = readFileSync(f).subarray(0, 512); } catch (e) {
        if (skill.target) hits.push(notReadHit(f, display, e));
      }
      const kind = sniffBinary(head);
      if (kind) {
        hits.push({
          rule: "embedded-binary",
          severity: "high",
          title: `${kind} disguised as ${extname(f)}`,
          detail: `The file extension says media; the bytes say ${kind}.`,
          url: display,
        });
      }
      continue;
    }
    // scanTargetSkillFile reports the named SKILL.md itself.
    scanTextFile(f, display, hits, { registry: true, target: skill.target && f !== skill.skillFile });
  }
  if (skill.target) scanTargetSkillFile(skill, files.includes(skill.skillFile), inv, hits);
  // One low finding per __pycache__ folder, not one per file.
  for (const [dir, sources] of caches) {
    const names = sources.map((p) => `\`${relative(skill.dir, p)}\``);
    hits.push({
      rule: "embedded-binary",
      severity: "low",
      title: `Python bytecode cache in skill (${sources.length} file${sources.length === 1 ? "" : "s"})`,
      detail: `Python's ordinary cache of ${names.slice(0, 3).join(", ")}${names.length > 3 ? ` and ${names.length - 3} more` : ""}: the names, the timestamp-based headers and the recorded source sizes match the \`.py\` files next to them, which were checked. The bytecode itself was not, and a cache whose header matches its source's time and size is loaded instead of the source. Delete \`__pycache__\` before you share the skill, so what ships is only what a reviewer can read.`,
      url: inv.display(dir),
    });
  }
}

function registryHitForFile(r, display) {
  return {
    rule: "registry-redirect",
    severity: registrySeverity(r, "medium"),
    title: "Plugin ships a package-manager config that changes the registry",
    detail: `${registryDetail(r)} It applies to installs run in this plugin folder. Check that the server is one you trust, or remove the file from the plugin.`,
    url: display,
  };
}

// ── Grade ─────────────────────────────────────────────────────────────────

// In its own module so callers that only grade (the dashboard, init) do not
// load discover.js and its `yaml` dependency.
export { gradeFindings };

// ── Scan ──────────────────────────────────────────────────────────────────

/**
 * Run `check` on each item; one file that throws (hostile nesting, a parser
 * edge case) is reported and skipped instead of aborting the whole audit.
 */
function eachChecked(items, hits, fileOf, check) {
  for (const item of items) {
    try {
      check(item);
    } catch (e) {
      hits.push({
        rule: "config-unparsed",
        severity: "medium",
        title: "File could not be checked",
        detail: `${e?.message || e}. Review it by hand.`,
        url: fileOf(item),
      });
    }
  }
}

/**
 * Audit agent configuration.
 * @param {string} root
 * @param {object} [opts] { home, homeDir, pin, onPhase, skillTarget }
 *   skillTarget: the user named this folder, so a SKILL.md at its root makes
 *   it a skill. A project scan leaves it off.
 */
export async function scanAgents(root, opts = {}) {
  const progress = opts.onPhase || (() => {});
  const start = Date.now();

  progress("Discovering agent configuration...");
  const inv = discoverAgentConfig(root, { home: opts.home, homeDir: opts.homeDir, skillTarget: opts.skillTarget });
  const hits = [];

  progress(`Scanning ${inv.skills.length} skill(s) for hidden content...`);
  const rootSkillHits = [];
  eachChecked(inv.skills, hits, (s) => inv.display(s.skillFile), (s) => {
    const into = s.target ? rootSkillHits : hits;
    scanSkillFolder(s, inv, into);
    into.push(...checkAllowedTools(inv.display(s.skillFile), s.frontmatter, `Skill "${s.name}"`));
  });

  progress("Scanning instruction and rule files...");
  eachChecked(inv.instructionFiles, hits, (f) => f.display, (f) => {
    scanTextFile(f.path, f.display, hits, { registry: true });
    if (/\.mdc?$/i.test(f.path)) {
      let text = "";
      try { text = readFileSync(f.path, "utf-8"); } catch { /* unreadable */ }
      hits.push(...checkAllowedTools(f.display, parseFrontmatter(text), "Command"));
    }
  });
  // A skill at the root of the target also holds what the project scan read
  // (its AGENTS.md, a skills/ folder inside it). One file, one report.
  const hitKey = (h) => `${h.rule}|${h.url}|${h.line ?? ""}`;
  const reported = new Set(hits.map(hitKey));
  hits.push(...rootSkillHits.filter((h) => !reported.has(hitKey(h))));

  progress(`Checking ${inv.mcpServers.length} MCP server(s), ${inv.hooks.length} hook(s), permissions and plugins...`);
  eachChecked(inv.mcpServers, hits, (m) => m.file, (m) => hits.push(...checkMcpServer(m), ...checkMcpExtras(m)));
  eachChecked(inv.hooks, hits, (h) => h.file, (h) => hits.push(...checkHook(h), ...checkHookExtras(h)));
  hits.push(...checkPermissions(inv));
  hits.push(...checkApproveSettings(inv));
  hits.push(...checkTasks(inv));
  eachChecked(inv.registryFiles, hits, (f) => f.display, (f) => {
    let text = "";
    try { text = readFileSync(f.path, "utf-8"); } catch { return; }
    const r = worstRegistryMatch(findRegistryRedirects(text, f.path), "medium");
    if (r) hits.push(registryHitForFile(r, f.display));
  });
  hits.push(...checkMarketplaces(inv));
  for (const e of inv.errors) {
    hits.push({ rule: "config-unparsed", severity: "info", title: "Config file could not be parsed", detail: e.message, url: e.file });
  }

  // Rug-pull pins
  progress("Comparing against penthera.lock...");
  const lpath = opts.lockPath || lockPath(inv.root);
  let lock = null;
  let corrupt = null;
  if (!opts.pin) {
    try { lock = readLock(lpath); } catch (e) { corrupt = e; }
  }
  // A lock file is compared with hashes made the way its version made them,
  // so upgrading Penthera never reads as a changed skill (a false rug pull).
  // Version 1 is 1, "1" or a missing field (2.0.0 always wrote 1). Anything
  // else that is not exactly a known version is not compared at all: a newer
  // Penthera may hash differently, and a guess gives false lock-changed
  // results, or none.
  const rawVersion = lock ? lock.lockfileVersion : undefined;
  const asNumber = typeof rawVersion === "number" ? rawVersion : typeof rawVersion === "string" && /^\d+$/.test(rawVersion.trim()) ? Number(rawVersion) : NaN;
  const knownVersion = rawVersion == null || asNumber === 1 ? 1 : asNumber === LOCK_VERSION ? LOCK_VERSION : null;
  const lockVersion = lock ? (knownVersion ?? LOCK_VERSION) : LOCK_VERSION;
  const entries = computeLockEntries(inv, { version: lockVersion, lockFile: lpath });
  const lockInfo = { path: lpath, status: "missing", changed: 0, added: 0, removed: 0, entries: Object.keys(entries).length };
  if (opts.pin) {
    writeLock(lpath, entries);
    lockInfo.status = "pinned";
  } else {
    if (corrupt) {
      hits.push({ rule: "config-unparsed", severity: "medium", title: `${LOCK_FILENAME} is corrupt`, detail: `${corrupt instanceof SyntaxError ? jsonErrorMessage(corrupt) : corrupt.message}. Rug-pull detection is off until it is re-pinned.`, url: LOCK_FILENAME });
      lockInfo.status = "corrupt";
    }
    if (lock && knownVersion == null) {
      const newer = Number.isInteger(asNumber) && asNumber > LOCK_VERSION;
      hits.push({
        rule: "lock-outdated",
        severity: "info",
        title: newer
          ? `${LOCK_FILENAME} is lockfile version ${asNumber}, newer than this Penthera reads`
          : `${LOCK_FILENAME} has an unknown lockfile version`,
        detail: `${newer ? `This Penthera reads versions 1 and ${LOCK_VERSION}; upgrade Penthera to compare it.` : `\`lockfileVersion\` must be 1 or ${LOCK_VERSION}.`} The pins were not compared, so rug-pull detection is off for this run. Review the skills, then run \`penthera agents --pin\` to write version ${LOCK_VERSION}.`,
        url: LOCK_FILENAME,
      });
      lockInfo.status = "unknown-version";
    } else if (lock) {
      if (lockVersion < LOCK_VERSION) {
        hits.push({
          rule: "lock-outdated",
          severity: "info",
          title: `${LOCK_FILENAME} is lockfile version ${lockVersion}: re-pin after upgrading`,
          detail: `It was compared the way version ${lockVersion} hashes skills, which leaves out \`dist\`, \`build\`, \`.next\`, \`__pycache__\`, \`.venv\` and \`venv\` inside a skill folder. Review the skills, then run \`penthera agents --pin\` to write version ${LOCK_VERSION}, which pins those folders too.`,
          url: LOCK_FILENAME,
        });
      }
      const scopes = opts.home ? ["repo", "home"] : ["repo"];
      const d = diffLock(lock, entries, { scopes });
      Object.assign(lockInfo, { status: "checked", changed: d.changed.length, added: d.added.length, removed: d.removed.length });
      for (const c of d.changed) {
        hits.push({
          rule: "lock-changed",
          severity: "high",
          title: `Pinned ${c.kind} changed since ${LOCK_FILENAME}: ${c.key.replace(/^\w+:/, "")}`,
          detail: `Hash was ${c.previous.slice(0, 12)}…, now ${c.sha256.slice(0, 12)}…. A ${c.kind} that changes after review is how a rug pull works. Diff it, then re-pin with \`penthera agents --pin\` if the change is expected.`,
          url: LOCK_FILENAME,
        });
      }
      for (const a of d.added) {
        hits.push({
          rule: "lock-new",
          severity: "medium",
          title: `New ${a.kind} not in ${LOCK_FILENAME}: ${a.key.replace(/^\w+:/, "")}`,
          detail: `Added since the last pin. Review it, then run \`penthera agents --pin\`.`,
          url: LOCK_FILENAME,
        });
      }
      for (const r of d.removed) {
        hits.push({
          rule: "lock-removed",
          severity: "info",
          title: `Pinned ${r.kind} no longer present: ${r.key.replace(/^\w+:/, "")}`,
          detail: "Removed since the last pin.",
          url: LOCK_FILENAME,
        });
      }
    } else if (lockInfo.status === "missing" && Object.keys(entries).length) {
      hits.push({
        rule: "lock-missing",
        severity: "info",
        title: `No ${LOCK_FILENAME}: skills, MCP servers and hooks are not pinned`,
        detail: `Run \`penthera agents --pin\` after reviewing them. Later runs then report anything that changed (rug pulls) or appeared.`,
        url: LOCK_FILENAME,
      });
    }
  }

  const findings = hits.map(toFinding);
  // No config read and nothing to report: an A here would grade an absence.
  const read = [inv.skills, inv.mcpServers, inv.hooks, inv.permissions, inv.plugins, inv.marketplaces,
    inv.instructionFiles, inv.tasks, inv.registryFiles, inv.configFiles].some((list) => list.length) || findings.length > 0;
  const { grade, score } = read ? gradeFindings(findings) : { grade: null, score: null };

  return {
    target: inv.root,
    mode: "agents",
    local: true,
    reachable: true,
    timestamp: new Date().toISOString(),
    duration: Date.now() - start,
    agents: {
      grade,
      score,
      home: !!opts.home,
      skillTarget: inv.skills.some((s) => s.target),
      inventory: {
        skills: inv.skills.length,
        mcpServers: inv.mcpServers.length,
        hooks: inv.hooks.length,
        permissions: inv.permissions.length,
        plugins: inv.plugins.length,
        marketplaces: inv.marketplaces.length,
        instructionFiles: inv.instructionFiles.length,
        tasks: inv.tasks.length,
        configFiles: inv.configFiles.map((f) => f.display),
      },
      // What this scan did not read: always the MCP tool descriptions, plus
      // any agent config on disk that no rule covers yet.
      notChecked: [
        ...(read ? [] : [NOTHING_TO_ASSESS]),
        ...inv.notRead.map((n) => `${n.file}: ${n.what}, not read by \`penthera agents\`.`),
        NOT_CHECKED_TOOL_DESCRIPTIONS,
      ],
      lock: { ...lockInfo, path: inv.display(lpath) },
    },
    executedProbes: ["agent-config-discovery", "hidden-content", "agent-config-rules", "agent-lock"],
    findings,
  };
}

