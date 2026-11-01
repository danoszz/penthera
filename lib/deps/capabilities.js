/**
 * Static capability detection for npm packages (`penthera deps`).
 *
 * For one package, answer "what can this code do?": run at install time, spawn
 * a shell, open sockets, write outside its folder, read the environment, build
 * code at runtime, load native binaries. Plus signals that a package is hiding
 * something (obfuscation) and indicators from real attacks (writing AI agent
 * config, driving AI CLIs to search the disk, harvesting GitHub tokens).
 *
 * Deliberately simple and deterministic: comments are blanked by a small
 * tokenizer, then line-level patterns run over the code. No AST, no network, no
 * model. Every capability carries file:line evidence so a human can check it.
 * A regex pass misses things a determined attacker can hide; that is why the
 * obfuscation signals exist, and why the output says "capability" rather than
 * "safe".
 *
 * Literals that name attack indicators are assembled at runtime so Penthera's
 * own source does not read like the payloads it looks for.
 */

const j = (...parts) => parts.join("");

/** Capability catalogue. `severity` is used when a package newly gains it. */
export const CAPABILITIES = {
  "install-scripts": { label: "install script", severity: "high", confidence: "confirmed",
    why: "Runs code on `npm install`, before you have used or reviewed the package." },
  shell: { label: "shell", severity: "medium", confidence: "likely",
    why: "Can run arbitrary programs through child_process." },
  network: { label: "network", severity: "medium", confidence: "likely",
    why: "Can open network connections (http, https, net, dgram, tls, fetch, WebSocket)." },
  "fs-write": { label: "writes outside its folder", severity: "medium", confidence: "potential",
    why: "Writes files and refers to the home directory or system paths." },
  env: { label: "env vars", severity: "low", confidence: "likely",
    why: "Reads process.env." },
  "env-bulk": { label: "whole environment", severity: "medium", confidence: "likely",
    why: "Serialises or enumerates all of process.env, which holds tokens and keys." },
  eval: { label: "dynamic code", severity: "medium", confidence: "likely",
    why: "Builds code at runtime with eval, new Function or vm." },
  "dynamic-require": { label: "computed require/import", severity: "low", confidence: "likely",
    why: "Loads modules whose names are computed at runtime." },
  native: { label: "native binary", severity: "low", confidence: "confirmed",
    why: "Ships or builds native code (.node, binding.gyp) that this scanner cannot read." },
  obfuscated: { label: "obfuscated", severity: "high", confidence: "potential",
    why: "Code looks deliberately hidden (obfuscator identifiers, escape-heavy strings, encoded blobs fed to eval)." },
  "ai-config-write": { label: "writes AI agent config", severity: "critical", confidence: "likely",
    why: "Writes AI assistant config (~/.claude, ~/.cursor, .mcp.json, Claude Desktop config). A dependency has no business doing this." },
  "ai-cli-invoke": { label: "drives AI CLIs", severity: "critical", confidence: "likely",
    why: "Runs an AI coding CLI (claude, gemini, q), the pattern used by the s1ngularity attack to search the disk for secrets." },
  "token-harvest": { label: "GitHub token harvesting", severity: "critical", confidence: "likely",
    why: "Reads GitHub credentials: runs the gh CLI to print its token, reads gh's hosts file or git's credential store, or matches token-shaped strings next to network code." },
  // Python only (lib/deps/python): code that runs whenever the interpreter starts, and unpickling.
  "startup-hook": { label: "runs at Python startup", severity: "high", confidence: "confirmed",
    why: "Ships a .pth file with an import line (or a sitecustomize.py), or writes one. Python runs that code on every interpreter start in that environment, so installing the package is enough to run it: a known persistence and supply-chain trick." },
  deserialize: { label: "unpickles data", severity: "low", confidence: "likely",
    why: "Loads pickle, marshal or unsafe YAML data, which runs code if the data is attacker-controlled." },
};

/** Python wording for capabilities whose npm description names npm or Node APIs. */
const PY_WHY = {
  "install-scripts": "Runs code at install time: a setup.py with custom commands, or an in-tree build backend, executes when pip builds the package from source.",
  shell: "Can run arbitrary programs (subprocess, os.system, os.popen, pty).",
  network: "Can open network connections (socket, urllib, requests, httpx, aiohttp and similar).",
  env: "Reads os.environ.",
  "env-bulk": "Serialises or enumerates all of os.environ, which holds tokens and keys.",
  eval: "Builds code at runtime with eval, exec or compile.",
  "dynamic-require": "Imports modules whose names are computed at runtime (__import__, importlib).",
  native: "Ships native extensions (.so, .pyd) or loads libraries with ctypes, which this scanner cannot read.",
  obfuscated: "Code looks deliberately hidden (encoded blobs or compressed payloads handed to exec, escape-heavy strings, PyArmor).",
  "ai-cli-invoke": "Runs an AI coding CLI (claude, gemini, q) through a subprocess, the pattern used by the s1ngularity attack to search the disk for secrets.",
};

/** Why a capability matters, worded for the package's ecosystem. */
export const capabilityWhy = (id, ecosystem) => (ecosystem === "pypi" && PY_WHY[id]) || CAPABILITIES[id]?.why || id;

/** Stable display order. */
export const CAPABILITY_ORDER = Object.keys(CAPABILITIES);

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const maxSeverity = (sevs) => sevs.reduce((m, s) => (SEV_RANK[s] > SEV_RANK[m] ? s : m), "info");

const JS_EXT = /\.(c|m)?jsx?$/i;
// Large enough for real bundles (typescript.js and editor workers are 9-13 MB),
// and the same as the tarball reader's per-file cap (source.js MAX_FILE_BYTES).
// A file over it is not read, and the package is then unscanned, never clean.
const MAX_JS_BYTES = 64 * 1024 * 1024;
const MAX_EVIDENCE = 5;
const MAX_SPACE_RUN = 32;
const EXFIL_WINDOW = 40; // lines
const NEAR_WINDOW = 30; // lines
const PAYLOAD_WINDOW = 3000; // characters

// ── Tokenizer: blank comments, keep strings and line numbers ─────────────

const REGEX_PREV = new Set("(,=:[!&|?{};+-*%<>~^".split(""));
const REGEX_KEYWORDS = /(?:^|[^\w$])(return|typeof|case|do|else|in|of|void|yield|await|delete|instanceof|new|throw)$/;

/**
 * Replace comment bodies with spaces (newlines preserved) so patterns don't
 * fire on documentation. Strings, template literals and regex literals are
 * skipped over intact. Heuristic, not a full parser.
 */
export function blankComments(src) {
  return collapseSpaces(blank(src));
}

/**
 * A run of spaces costs some patterns time in its length squared or worse, and
 * a bundle's blanked comments are such runs. So is one a package plants to stall
 * the scan. No pattern needs more than a few spaces, so long runs are cut.
 */
function isInlineSpace(c) {
  return c === 32 || (c >= 9 && c <= 13 && c !== 10) || c === 0xa0 || c === 0xfeff || c === 0x1680
    || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000;
}

function collapseSpaces(code) {
  const parts = [];
  let last = 0;
  let run = 0;
  for (let i = 0; i <= code.length; i++) {
    const c = code.charCodeAt(i); // NaN past the end ends the last run
    if (isInlineSpace(c)) { run++; continue; }
    if (run > MAX_SPACE_RUN) {
      parts.push(code.slice(last, i - run + MAX_SPACE_RUN));
      last = i;
    }
    run = 0;
  }
  return last === 0 ? code : parts.join("") + code.slice(last);
}

/**
 * Newlines stay, or line numbers would be wrong, so a run of blank lines keeps
 * its cost: some patterns take time in a run's length squared. A file that would
 * cost this much is not scanned, and the package reads as unscanned, not clean.
 */
const MAX_BLANK_COST = 2e9; // about a second of matching, and a comment of 40,000 lines
function tooBlankToScan(src) {
  const code = blankComments(src);
  let cost = 0;
  let run = 0;
  for (let i = 0; i <= code.length; i++) {
    const c = code.charCodeAt(i);
    if (c === 10 || isInlineSpace(c)) { run++; continue; }
    if (run > 1) cost += run * run;
    run = 0;
  }
  return cost > MAX_BLANK_COST;
}

function blank(src) {
  const n = src.length;
  const parts = [];
  let last = 0;
  let i = 0;
  let prev = ""; // previous significant character
  // One space per line: a blanked comment only needs to keep its newlines.
  const spaces = (s) => s.replace(/[^\n]+/g, " ");
  while (i < n) {
    const ch = src[i];
    const nx = src[i + 1];
    if (ch === "/" && nx === "/") {
      let end = src.indexOf("\n", i);
      if (end === -1) end = n;
      parts.push(src.slice(last, i), " ");
      i = last = end;
      continue;
    }
    if (ch === "/" && nx === "*") {
      let end = src.indexOf("*/", i + 2);
      end = end === -1 ? n : end + 2;
      parts.push(src.slice(last, i), spaces(src.slice(i, end)));
      i = last = end;
      continue;
    }
    if (ch === '"' || ch === "'") {
      i++;
      while (i < n && src[i] !== ch && src[i] !== "\n") i += src[i] === "\\" ? 2 : 1;
      i++;
      prev = ch;
      continue;
    }
    if (ch === "`") {
      i++;
      while (i < n && src[i] !== "`") i += src[i] === "\\" ? 2 : 1;
      i++;
      prev = ch;
      continue;
    }
    if (ch === "/") {
      const isRegex = prev === "" || REGEX_PREV.has(prev) ||
        (/[\w$]/.test(prev) && REGEX_KEYWORDS.test(src.slice(Math.max(0, i - 12), i).trimEnd()));
      if (isRegex) {
        i++;
        let inClass = false;
        while (i < n && src[i] !== "\n") {
          const c = src[i];
          if (c === "\\") { i += 2; continue; }
          if (c === "[") inClass = true;
          else if (c === "]") inClass = false;
          else if (c === "/" && !inClass) break;
          i++;
        }
        i++;
        prev = "a"; // a regex literal behaves like an operand
        continue;
      }
    }
    if (ch !== " " && ch !== "\t" && ch !== "\n" && ch !== "\r") prev = ch;
    i++;
  }
  parts.push(src.slice(last));
  return parts.join("");
}

// ── Patterns ──────────────────────────────────────────────────────────────

/** require("x") / import "x" / from "x" / import("x"), with optional node: prefix and subpath. */
const moduleRe = (mods) => new RegExp(
  String.raw`(?:(?<![\w$.])require\s*\(\s*|\bfrom\s*|(?<![\w$.])import\s*\(\s*|(?<![\w$.])import\s+)(['"\`])(?:node:)?(?:${mods})(?:\/[\w/]*)?\1`,
);

// process.env or process["env"]; ENV_COPY: post(u, { ...process.env }).
const PENV = String.raw`process(?:\.env\b|\[\s*['"\`]env['"\`]\s*\])`;
const ENV_COPY = String.raw`[(,]\s{0,32}\{\s*\.\.\.\s*${PENV}\s*\}\s*[,)]`;

const P = {
  shell: [moduleRe("child_process"), /process\.binding\(\s*['"]spawn_sync['"]/],
  network: [
    moduleRe("http|https|http2|net|dgram|tls"),
    /(?<![\w$.]|function\s{1,4}|\bfunction\s{0,4}\*?\s{0,4})fetch\s*\(\s*[^)\s]/,
    /\bnew\s+(?:WebSocket|XMLHttpRequest)\s*\(/,
    /\bnavigator\.sendBeacon\s*\(/,
  ],
  env: [new RegExp(String.raw`\b${PENV}`)],
  envSerialise: new RegExp(String.raw`\bJSON\.stringify\(\s*${PENV}\s*[,)]|\bBuffer\.from\(\s*JSON\.stringify\(\s*${PENV}|${ENV_COPY}`),
  envBulk: [
    String.raw`\bJSON\.stringify\(\s*${PENV}\s*[,)]`,
    String.raw`\bObject\.(?:keys|entries|values)\(\s*${PENV}\s*\)`,
    String.raw`\bfor\s*\(\s*(?:const|let|var)?\s*[\w$]+\s+in\s+${PENV}\s*\)`,
    ENV_COPY,
  ].map((x) => new RegExp(x)),
  eval: [
    /(?<![\w$.])eval\s*\(/,
    /\bnew\s+Function\s*\((?!\s*['"`]return this['"`]\s*\))/,
    /(?<![\w$.]|new\s{1,4})Function\s*\((?!\s*\))(?!\s*['"`]return this['"`]\s*\))/,
    /\bFunction\.constructor\s*\((?!\s*\))(?!\s*['"`]return this['"`]\s*\))/,
    moduleRe("vm"),
  ],
  dynamicRequire: [
    /(?<![\w$.]|function\s{1,4})require\s*\(\s*(?![\s'")]|`[^`$]*`)/,
    /(?<![\w$.])import\s*\(\s*(?![\s'")]|`[^`$]*`)/,
  ],
  native: [/\bprocess\.dlopen\s*\(/],
  fsReadCall: /\b(?:readFile|readFileSync|createReadStream)\s*\(/,
  fsWriteCall: /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|cpSync|rename|renameSync|symlink|symlinkSync|outputFile|outputFileSync|writeJson|writeJsonSync|chmod|chmodSync)\s*\(/,
  outsidePath: /\b(?:os\.)?homedir\s*\(\s*\)|process\.env\.(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_CONFIG_HOME)\b|['"`]~\/|['"`]\/(?:etc|usr|var|Library|System)\/|['"`][A-Z]:\\\\(?:Windows|Users)/,
  dataUri: /data:(?:image|font|audio|video)\/[\w.+-]+;base64,$/,
};

// Attack indicators, assembled at runtime.
const escRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const AI_CONFIG_TARGETS = [j(".cl", "aude"), j(".cur", "sor"), j(".m", "cp.json"), j("claude_", "desktop_", "config.json")];
const AI_CONFIG_RE = new RegExp(
  `['"\`/\\\\](?:${AI_CONFIG_TARGETS.map(escRe).join("|")})(?:['"\`/\\\\]|$)`,
);
const DESKTOP_CONFIG_RE = new RegExp(escRe(AI_CONFIG_TARGETS[3]));
const AI_CLIS = [j("cla", "ude"), j("gem", "ini"), "q"];
const AI_CLI_CALL_RE = new RegExp(
  String.raw`\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|execa|execaSync)\s*\(\s*['"\`](?:${AI_CLIS.join("|")})(?:['"\`]|\s)`,
);
const AI_CLI_FLAGS = [j("--dangerously", "-skip-", "permissions"), j("--yo", "lo"), j("--trust-", "all-", "tools")];
const AI_CLI_FLAG_RE = new RegExp(`['"\`\\s](?:${AI_CLI_FLAGS.join("|")})(?:['"\`\\s]|$)`);
const GH_TOKEN_CMD_RE = new RegExp(j("\\bgh\\s+auth\\s+", "token\\b"));
const GH_CRED_FILE_RE = new RegExp(`(?:${j("\\.git-", "credentials")}|${j("gh[/\\\\\\\\]", "hosts\\.yml")})`);
const GH_TOKEN_REGEX_RE = new RegExp(`(?:${j("gh", "p_")}|${j("gh", "o_")}|${j("github", "_pat_")}|${j("gh", "\\[pousr")}|${j("gh", "\\[ps")})`);

/** Attack-indicator patterns shared with the Python scanner (lib/deps/python). */
export const INDICATORS = {
  AI_CONFIG_RE, DESKTOP_CONFIG_RE, AI_CLIS, AI_CLI_FLAG_RE, GH_TOKEN_CMD_RE, GH_CRED_FILE_RE, GH_TOKEN_REGEX_RE,
};

const DECODE_RE = /\batob\s*\(|String\.fromCharCode\s*\(|\bdecodeURIComponent\s*\(\s*escape\s*\(/;
const DECODE_ENCODING = /['"`](?:base64|hex)['"`]/g;

/**
 * Where code decodes something, for the dropper check. `Buffer.from("…", "hex")`
 * is found by walking from each call to its first ")", once, so a file of
 * unclosed calls costs one pass and not one per call.
 */
function decodeOffsets(code) {
  const out = [...code.matchAll(new RegExp(DECODE_RE.source, "g"))].map((m) => m.index);
  const call = "Buffer.from(";
  for (let i = code.indexOf(call); i !== -1;) {
    const close = code.indexOf(")", i);
    const end = close === -1 ? code.length : close;
    const quoted = [...code.slice(i, end).matchAll(DECODE_ENCODING)].at(-1);
    if (quoted) {
      for (let at = i; at !== -1 && at < i + quoted.index; at = code.indexOf(call, at + 1)) {
        if (!/[\w$]/.test(code[at - 1] || "")) out.push(at);
      }
    }
    i = code.indexOf(call, end);
  }
  return out;
}

const SUSPICIOUS_INSTALL_CMD = /\b(?:curl|wget|powershell|Invoke-WebRequest|iwr)\b|\|\s*(?:ba)?sh\b|base64\s+(?:-d|--decode)/i;
// Plus senders: DNS or ping of a computed name, raw sockets, hex dumps.
const INSTALL_SHELL_RE = new RegExp(String.raw`${SUSPICIOUS_INSTALL_CMD.source}|\b(?:nslookup|dig|host|ping)\s+(?:-\S+\s+)*[^\s'"\`]*(?:\$[({]|\`|[\w-]+\.[a-z]{2,})|\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat|telnet)\s+(?:-\w+\s+)*[\w.$\{\}-]+\s+\d{2,5}\b|\bxxd\s+-p\b`, "i");
// Recon and send in one command.
const SEND_CMD = /\bcurl\b[^|;]*\s(?:-d|--data[\w-]*|-F|--form|-T|--upload-file|-X\s*POST)\b|\bwget\b[^|;]*--post-|\b(?:nslookup|dig|host|ping)\s|\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat)\s/i;

// These patterns are slow on long input, so they only ever see short pieces of it.
const MAX_COMMAND = 4096;
const WINDOW_OVERLAP = 1024;
const MAX_WINDOWS = 64;
const collapse = (text) => String(text).replace(/\s+/g, " ");

const COMMAND_WORD = /\b(?:curl|wget|powershell|invoke-webrequest|iwr|base64|nslookup|dig|host|ping|nc|ncat|netcat|telnet|xxd)\b|\|\s*(?:ba)?sh\b|\/dev\/(?:tcp|udp)\//gi;

/** Where to look in a long text: around its first command words, one window each. One past the limit means the walk stops early. */
function commandWindows(flat) {
  const starts = [];
  let seen = -1;
  for (const m of flat.matchAll(COMMAND_WORD)) {
    if (m.index < seen) continue;
    const from = Math.max(0, m.index - WINDOW_OVERLAP);
    seen = from + MAX_COMMAND - WINDOW_OVERLAP;
    starts.push(from);
    if (starts.length > MAX_WINDOWS) break;
  }
  return starts;
}

/**
 * Does the text match? Whitespace is collapsed first: every run of it means the
 * same to the pattern. A long text is checked around its command words, so no
 * padding can push a command out of view. If there are too many to check, it
 * counts as a match: unread text never makes a result better.
 */
function windowsMatch(re, text) {
  const flat = collapse(text);
  if (flat.length <= MAX_COMMAND) return re.test(flat);
  const starts = commandWindows(flat);
  return starts.length > MAX_WINDOWS || starts.some((from) => re.test(flat.slice(from, from + MAX_COMMAND)));
}

/** Did the walk stop before the end of this text? */
const walkStopsEarly = (text) => {
  if (text.length <= MAX_COMMAND) return false;
  return commandWindows(collapse(text)).length > MAX_WINDOWS;
};

export const INSTALL_SHELL_CMD = { test: (text) => windowsMatch(INSTALL_SHELL_RE, text) };
const SENDS_DATA = /\s(?:-d|--data[\w-]*|-F|--form|-T|--upload-file|-X\s*POST)\b/i;
const NAMED_SENDER = /\b(?:nslookup|dig|host|ping)\s|\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat)\s/i;

/** Curl or wget with data in the same pipeline step, or a DNS or socket tool. Past a window, SEND_CMD could not see both ends of a curl. */
export function commandSends(text) {
  const flat = collapse(text);
  if (flat.length <= MAX_COMMAND) return SEND_CMD.test(flat);
  if (NAMED_SENDER.test(flat)) return true;
  return flat.split(/[|;]/).some((step) => {
    const curl = step.search(/\bcurl\b/i);
    if (curl !== -1 && SENDS_DATA.test(step.slice(curl + 4))) return true;
    const wget = step.search(/\bwget\b/i);
    return wget !== -1 && /--post-/i.test(step.slice(wget + 4));
  });
}

/** Too long to judge in full. An install script like this reads as risky, not clean. */
export const commandTooLong = (text) => collapse(text).length > MAX_COMMAND;

/** Past this a string is only partly checked, and the scan says so. */
const COMMAND_READ_LIMIT = (MAX_COMMAND - WINDOW_OVERLAP) * MAX_WINDOWS;

const RECON = String.raw`(?:whoami|hostname|uname|pwd|id|ifconfig|ipconfig|printenv|env|ls|cat)`;
const RECON_CMD = new RegExp(String.raw`\$\(|(?:^|[\s;|&("'])${RECON}(?=$|[\s;|)"'])`);
const RECON_EXEC_RE = new RegExp(String.raw`\bexec(?:Sync)?\s*\(\s*['"\`]${RECON}(?:\s+[\w./-]+)?['"\`]`);
const CMD_HINT = /curl|wget|owershell|ebRequest|iwr|sh\b|base64|ookup|dig|host|ping|\/dev\/|nc|telnet|xxd/i;
const DECODED_REQUIRE_RE = /(?<![\w$.])require\s*\(\s*(?:Buffer\.from|atob|String\.fromCharCode|decodeURIComponent|unescape)\s*\(/;
const NET_CALL_RE = /(?<![\w$.])fetch\s*\(|\baxios(?:\.(?:get|post|request))?\s*\(|\bhttps?\.(?:get|request)\s*\(|(?<![\w$.])got(?:\.(?:get|post))?\s*\(/g;
const RUN_CODE_RE = /(?<![\w$.])eval\s*\(|\bFunction(?:\.constructor)?\s*\((?!\s*\))(?!\s*['"`]return this['"`])|\bvm\.(?:runIn\w*Context|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\(/g;
const RESPONSE_RE = /\.then\s*\(|\bawait\b|\.(?:json|text|arrayBuffer)\s*\(\s*\)|\.(?:data|body)\b|\.on\s*\(\s*['"`](?:data|end)['"`]/;
const CALLBACK_RUN_RE = /\(\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\{?\s*(?:return\s+)?(?:eval|(?:new\s+)?Function(?:\.constructor)?)\s*\(\s*\1\.(?:data|body|content|responseText)\b/;
const RESPONSE_VAR_RE = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+[\w$.]+\.(?:json|text)\s*\(\s*\)/g;
const SPAWN_CALL_RE = /\b(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(/g;
const SCRIPT_LITERAL_RE = /['"`]((?:\.{0,2}\/)?[\w./-]+\.(?:c|m)?js)['"`]/;
export const RISKY_FOR_INSTALL = ["network", "eval", "obfuscated", "env-bulk", "ai-config-write", "ai-cli-invoke", "token-harvest"];

// ── Helpers ───────────────────────────────────────────────────────────────

export function snippet(line, idx) {
  const start = Math.max(0, idx - 40);
  const s = line.slice(start, start + 120).trim();
  return (start > 0 ? "…" : "") + s + (start + 120 < line.length ? "…" : "");
}

export function add(caps, id, ev) {
  const list = caps[id] || (caps[id] = { count: 0, evidence: [] });
  list.count++;
  if (list.evidence.length < MAX_EVIDENCE) list.evidence.push(ev);
}

/** Shannon entropy in bits per character. */
export function entropy(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Obfuscation signals for one file (comment-blanked code).
 * Returns { flagged, signals: string[], line }.
 */
export function obfuscationSignals(code, { hasDynamicCode = false, evalRes = P.eval, decodeRe = null, strongEscapes = true } = {}) {
  const signals = [];
  let line = 1;
  let strong = 0;

  const obfIds = code.match(/\b_0x[0-9a-f]{4,6}\b/g);
  if (obfIds && obfIds.length >= 10) {
    strong++;
    signals.push(`${obfIds.length} obfuscator-style identifiers (_0x…)`);
    line = lineOf(code, code.search(/\b_0x[0-9a-f]{4,6}\b/));
  }

  // Printable characters only: ANSI colour codes (\x1b) and control bytes are normal.
  const hexEsc = code.match(/\\x[2-7][0-9a-fA-F]/g);
  if (hexEsc && hexEsc.length >= 50 && (hexEsc.length * 4) / code.length >= 0.05) {
    if (strongEscapes) strong++;
    signals.push(`\\x escape density ${Math.round(((hexEsc.length * 4) / code.length) * 100)}%`);
    if (line === 1) line = lineOf(code, code.indexOf("\\x"));
  }

  // Encoded blobs: long base64/hex runs, or shorter runs with high entropy.
  const blobs = [];
  for (const m of code.matchAll(/[A-Za-z0-9+/]{200,}={0,2}|\b[0-9a-fA-F]{400,}\b/g)) {
    const s = m[0];
    const before = code.slice(Math.max(0, m.index - 40), m.index);
    if (P.dataUri.test(before)) continue; // embedded image/font
    if (/^[a-z]+$/i.test(s)) continue; // a long word, not an encoding
    if (s.startsWith("AGFzbQ")) continue; // base64 WebAssembly module ("\0asm"), sandboxed
    const e = entropy(s.slice(0, 4000));
    const isHex = /^[0-9a-fA-F]+$/.test(s);
    if (s.length >= 1000 || (!isHex && e >= 5.0)) {
      blobs.push({ len: s.length, e, index: m.index, end: m.index + s.length, isHex });
      if (blobs.length >= 50) break;
    }
  }

  let longest = 0;
  for (const l of code.split("\n")) if (l.length > longest) longest = l.length;

  // The classic dropper: decode a blob and hand it to eval, all in one place.
  // Requires the blob, a decode call and dynamic code within a few thousand
  // characters of each other; any two of them far apart in a bundle is normal.
  let payload = null;
  if (blobs.length && hasDynamicCode) {
    const offsets = (res) => res.flatMap((re) => [...code.matchAll(new RegExp(re.source, "g"))].map((m) => m.index));
    const evals = offsets(evalRes);
    const decodes = decodeRe ? offsets([decodeRe]) : decodeOffsets(code);
    const near = (b, list) => list.some((o) => o >= b.index - PAYLOAD_WINDOW && o <= b.end + PAYLOAD_WINDOW);
    payload = blobs.find((b) => near(b, evals) && near(b, decodes)) || null;
  }
  const blob = payload || blobs[0];
  if (blob) signals.push(`${blob.isHex ? "hex" : "base64-like"} blob of ${blob.len} chars (entropy ${blob.e.toFixed(1)})`);
  if (longest >= 5000) signals.push(`line of ${longest} chars`);
  if (payload) signals.push("blob decoded and run with eval/new Function/vm");
  const flagged = strong > 0 || !!payload;
  if (flagged && line === 1 && payload) line = lineOf(code, payload.index);
  return { flagged, signals, line };
}

/** String literals on one line: [{ text, index }]. */
export function literalsOf(line) {
  const out = [];
  for (let i = 0; i < line.length; i++) {
    const q = line[i];
    if (q !== '"' && q !== "'" && q !== "`") continue;
    let k = i + 1;
    while (k < line.length && line[k] !== q) k += line[k] === "\\" ? 2 : 1;
    out.push({ text: line.slice(i + 1, k), index: i });
    i = k;
  }
  return out;
}

/** Script paths a line starts. */
function spawnedScripts(line) {
  const out = literalsOf(line).flatMap((x) => nodeScriptTargets(x.text));
  for (const m of line.matchAll(SPAWN_CALL_RE)) {
    const win = line.slice(m.index, m.index + 300);
    if (!/^fork/.test(m[0]) && !/^[^,]*(?:['"`]node(?:\.exe)?['"`]|process\.execPath)/.test(win.slice(m[0].length))) continue;
    const lit = win.match(SCRIPT_LITERAL_RE);
    if (lit) out.push(lit[1]);
  }
  return out;
}

export function lineOf(code, idx) {
  if (idx <= 0) return 1;
  let n = 1;
  for (let i = 0; i < idx; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

export function findLine(text, needle) {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) if (lines[i].includes(needle)) return i + 1;
  return 1;
}

// ── Per-file scan ─────────────────────────────────────────────────────────

/**
 * Scan one JS file's source. Returns { caps, fileFlags } where caps is
 * { capId: { count, evidence: [{ file, line, snippet }] } }.
 */
export function scanSource(src, file) {
  const caps = {};
  let partlyRead = false;
  const hasTemplates = src.includes("`");
  const code = blankComments(src);
  const lines = code.split("\n");
  const has = { shell: false, network: false, fsWrite: false, fsRead: false, outside: false, envBulk: false, eval: false };
  const firstHit = {};
  const netLines = [];
  const writeHits = [];
  const outsideLines = [];
  const aiConfigHits = [];
  const serialiseHits = [];
  const cmdHits = [];
  const spawned = [];

  const maybeShell = P.shell.some((re) => re.test(code));
  const maybeDecodedRequire = DECODED_REQUIRE_RE.test(code);
  let tplChecks = 0;
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    const lineStart = offset;
    offset += l.length + 1;
    if (!l.trim()) continue;
    const ev = (re) => {
      const m = l.match(re);
      return m ? { file, line: i + 1, snippet: snippet(l, m.index) } : null;
    };
    const hit = (id, res) => {
      for (const re of res) {
        const e = ev(re);
        if (e) { add(caps, id, e); return e; }
      }
      return null;
    };
    if (hit("shell", P.shell)) has.shell = true;
    // Command strings, in literals only.
    if (maybeShell && cmdHits.length < MAX_EVIDENCE && CMD_HINT.test(l)) {
      const literals = literalsOf(l);
      if (l.length > COMMAND_READ_LIMIT || literals.some((x) => walkStopsEarly(x.text))) partlyRead = true;
      const lit = literals.find((x) => INSTALL_SHELL_CMD.test(x.text))
        || (hasTemplates && INSTALL_SHELL_CMD.test(l) && tplChecks++ < 20 && (code.slice(0, lineStart).match(/(?<!\\)`/g) || []).length % 2 && { index: -1 });
      if (lit) {
        const e = { file, line: i + 1, snippet: snippet(l, lit.index) };
        cmdHits.push(e);
        const t = lit.index < 0 || l[lit.index] === "`" ? code.slice(lineStart + lit.index + 1, lineStart + 1000).split("`")[0] : lit.text;
        if (!firstHit.sendCmd && commandSends(t) && RECON_CMD.test(t)) firstHit.sendCmd = e;
      }
    }
    if (maybeShell && !firstHit.reconExec) firstHit.reconExec = ev(RECON_EXEC_RE);
    if (maybeShell && spawned.length < 20 && /\b(?:spawn|fork|exec)/.test(l)) spawned.push(...spawnedScripts(l));
    if (maybeDecodedRequire && !firstHit.decodedRequire) firstHit.decodedRequire = ev(DECODED_REQUIRE_RE);
    const net = hit("network", P.network);
    if (net) { has.network = true; netLines.push(i + 1); }
    hit("env", P.env);
    const bulk = hit("env-bulk", P.envBulk);
    if (bulk) { has.envBulk = true; if (P.envSerialise.test(l)) serialiseHits.push(bulk); }
    if (hit("eval", P.eval)) has.eval = true;
    hit("dynamic-require", P.dynamicRequire);
    hit("native", P.native);

    const w = ev(P.fsWriteCall);
    if (w) { has.fsWrite = true; writeHits.push(w); }
    if (P.outsidePath.test(l)) { has.outside = true; outsideLines.push(i + 1); }

    const aiCfg = ev(AI_CONFIG_RE);
    if (aiCfg) aiConfigHits.push(aiCfg);
    const aiCall = ev(AI_CLI_CALL_RE) || ev(AI_CLI_FLAG_RE);
    if (aiCall) firstHit.aiCli = firstHit.aiCli || aiCall;
    const ghCmd = ev(GH_TOKEN_CMD_RE);
    if (ghCmd) firstHit.ghCmd = firstHit.ghCmd || ghCmd;
    const ghFile = ev(GH_CRED_FILE_RE);
    if (ghFile) firstHit.ghFile = firstHit.ghFile || ghFile;
    if (P.fsReadCall.test(l)) has.fsRead = true;
    const ghShape = ev(GH_TOKEN_REGEX_RE);
    if (ghShape) firstHit.ghShape = firstHit.ghShape || ghShape;
  }

  // Writes outside the package: a write call within a few lines of a home
  // directory or system path reference.
  const near = (line, lines) => lines.some((n) => Math.abs(n - line) <= NEAR_WINDOW);
  const outsideWrite = writeHits.find((w) => near(w.line, outsideLines));
  if (outsideWrite) add(caps, "fs-write", outsideWrite);

  // AI agent config paths next to a write call. In the home directory (or
  // Claude Desktop's config, which only lives there) it is the s1ngularity
  // pattern. A project-level .mcp.json or .claude/ written by a CLI the user
  // runs (e.g. an `init` command) is normal, so that only counts when an
  // install hook runs the file (decided in scanPackage).
  const writeLines = writeHits.map((w) => w.line);
  const aiWrites = aiConfigHits.filter((h) => near(h.line, writeLines));
  const homeWrite = aiWrites.find((h) => near(h.line, outsideLines) || DESKTOP_CONFIG_RE.test(h.snippet));
  if (homeWrite) add(caps, "ai-config-write", homeWrite);
  const aiConfigProject = homeWrite ? null : aiWrites[0] || null;
  if (firstHit.aiCli && has.shell) add(caps, "ai-cli-invoke", firstHit.aiCli);
  // The token command only matters if the file can run it; the credential
  // files only matter if the file reads files or talks to the network.
  if (firstHit.ghCmd && has.shell) add(caps, "token-harvest", firstHit.ghCmd);
  else if (firstHit.ghFile && (has.fsRead || has.network)) add(caps, "token-harvest", firstHit.ghFile);
  else if (firstHit.ghShape && has.network && (has.envBulk || has.outside)) add(caps, "token-harvest", firstHit.ghShape);

  const obf = obfuscationSignals(code, { hasDynamicCode: has.eval });
  if (obf.flagged) {
    add(caps, "obfuscated", { file, line: obf.line, snippet: obf.signals.join("; ") });
  } else if (firstHit.decodedRequire) {
    add(caps, "obfuscated", { ...firstHit.decodedRequire, snippet: `module name decoded at runtime: ${firstHit.decodedRequire.snippet}` });
  }

  // Composite: the whole environment serialised within a few lines of network
  // code is the exfiltration shape. Enumerating keys to filter them is not.
  const exfil = serialiseHits.find((e) => netLines.some((n) => Math.abs(n - e.line) <= EXFIL_WINDOW)) || null;
  const remoteCode = has.eval ? remoteCodeAt(code, file) : null;
  const sendsOut = (has.shell && (firstHit.sendCmd || (has.network && firstHit.reconExec))) || null;
  return { caps, exfil, remoteCode, sendsOut, partlyRead, aiConfigProject, shellCmd: has.shell ? cmdHits[0] || null : null, spawned: has.shell ? spawned : [] };
}

/**
 * Network call, response handling, then eval/Function/vm within 800 chars and
 * 15 lines, or naming a parsed response within 40 lines. Not a sourceURL loader.
 */
function remoteCodeAt(code, file) {
  const at = (idx) => { const ln = lineOf(code, idx); return { file, line: ln, snippet: snippet(code.split("\n")[ln - 1], 0) }; };
  const cb = code.match(CALLBACK_RUN_RE);
  if (cb) return at(cb.index);
  const nets = [...code.matchAll(NET_CALL_RE)].slice(0, 200).map((m) => m.index);
  if (!nets.length) return null;
  const vars = [...code.matchAll(RESPONSE_VAR_RE)].filter((m) => m.index > nets[0]).slice(0, 50);
  const lines = (a, b) => code.slice(a, b).split("\n").length - 1;
  const ok = (a, b) => !code.slice(a, b).includes("sourceURL");
  for (const m of code.matchAll(RUN_CODE_RE)) {
    const n = nets.findLast((x) => x < m.index);
    if (n === undefined) continue;
    if (m.index - n <= 800 && lines(n, m.index) <= 15 && RESPONSE_RE.test(code.slice(n, m.index)) && ok(n, m.index)) return at(m.index);
    const args = code.slice(m.index, m.index + 400);
    if (vars.some((v) => v.index < m.index && m.index - v.index <= 8000 && lines(v.index, m.index) <= 40 && ok(v.index, m.index) &&
      new RegExp(String.raw`(?<![\w$.])${v[1].replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")}\b`).test(args))) return at(m.index);
  }
  return null;
}

export function mergeCaps(into, from) {
  for (const [id, v] of Object.entries(from)) {
    const t = into[id] || (into[id] = { count: 0, evidence: [] });
    t.count += v.count;
    for (const e of v.evidence) if (t.evidence.length < MAX_EVIDENCE) t.evidence.push(e);
  }
}

// ── Per-package scan ──────────────────────────────────────────────────────

const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];

/**
 * Script files an install hook runs with `node [flags] <file>`. Tokenized
 * rather than matched with one regex: hook commands come from the package
 * under inspection, so the parser must stay linear on hostile input.
 */
export function nodeScriptTargets(cmd) {
  const out = [];
  const tokens = String(cmd).slice(0, 4096).split(/\s+/);
  for (let i = 0; i < tokens.length; i++) {
    if (!/^(?:.*[\\/])?node(?:\.exe)?$/.test(tokens[i])) continue;
    let j = i + 1;
    while (j < tokens.length && tokens[j].startsWith("-")) j++;
    if (j < tokens.length && /^[\w./-]+$/.test(tokens[j])) out.push(tokens[j]);
  }
  return out;
}

/**
 * Scan a package through a source (see source.js).
 * @param {{ files(): string[], read(rel): Buffer, size(rel): number, anomaly?: string, truncated?: boolean }} source
 * @param {{ prefix?: string, iocs?: ReturnType<import("./iocs.js").loadIocs> }} opts prefix is
 *   prepended to evidence paths (e.g. node_modules/foo/); iocs are rule-pack indicators to look for
 * @returns {{ name, version, capabilities, installScripts, exfil, filesScanned, skipped, unscanned, iocHits }}
 *   unscanned: why the package could not be fully read (archive anomaly, no
 *   package.json, a code file too large to scan, more files than the source
 *   lists), else null. Callers must not treat such a package as clean.
 */
export function scanPackage(source, opts = {}) {
  const prefix = opts.prefix || "";
  const caps = {};
  const files = source.files();
  let pkg = {};
  let pkgText = "";
  // Install scripts come only from package.json, so a package whose archive or
  // manifest could not be read is unscanned, never clean (fail closed).
  let unscanned = source.anomaly || null;
  try {
    pkgText = source.read("package.json").toString("utf-8");
    pkg = JSON.parse(pkgText);
    if (!pkg || typeof pkg !== "object" || Array.isArray(pkg)) throw new Error("not an object");
  } catch {
    pkg = {};
    unscanned = unscanned || "package.json is missing or not valid JSON, so its install scripts are unknown";
  }
  const iocs = opts.iocs || null;
  const iocHits = iocs ? [...iocs.scanFiles(files, source, prefix), ...iocs.scanText(pkgText, `${prefix}package.json`)] : [];

  const installScripts = {};
  for (const hook of INSTALL_HOOKS) {
    const cmd = pkg.scripts?.[hook];
    if (typeof cmd === "string" && cmd.trim()) {
      installScripts[hook] = cmd;
      add(caps, "install-scripts", { file: `${prefix}package.json`, line: findLine(pkgText, `"${hook}"`), snippet: `${hook}: ${cmd}`.slice(0, 160) });
    }
  }
  // npm runs `node-gyp rebuild` implicitly when binding.gyp exists and no install hook does.
  if (files.includes("binding.gyp") && !installScripts.install && !installScripts.preinstall) {
    installScripts.install = "node-gyp rebuild (implicit, binding.gyp)";
    add(caps, "install-scripts", { file: `${prefix}binding.gyp`, line: 1, snippet: "binding.gyp: npm runs node-gyp rebuild on install" });
  }

  for (const f of files) {
    if (/\.node$/i.test(f)) add(caps, "native", { file: `${prefix}${f}`, line: 1, snippet: "prebuilt native addon" });
  }
  if (files.includes("binding.gyp")) add(caps, "native", { file: `${prefix}binding.gyp`, line: 1, snippet: "native addon built from source" });

  const exfil = [];
  const remoteCode = [];
  const fileCaps = {};
  const fileCmd = {};
  const fileSends = {};
  const fileSpawned = {};
  const aiConfigProject = {};
  let filesScanned = 0;
  const skipped = [];
  const tooBlank = [];
  const partlyRead = [];
  const binTargets = new Set(Object.values(typeof pkg.bin === "string" ? { x: pkg.bin } : pkg.bin || {}).map((p) => String(p).replace(/^\.\//, "")));
  for (const f of files) {
    const isJs = JS_EXT.test(f) || binTargets.has(f);
    if (!isJs || /\.d\.[cm]?ts$/i.test(f)) continue;
    if (source.size(f) > MAX_JS_BYTES) { skipped.push(f); continue; }
    let src;
    try { src = source.read(f).toString("utf-8"); } catch { continue; }
    if (tooBlankToScan(src)) { tooBlank.push(f); continue; }
    filesScanned++;
    if (iocs) iocHits.push(...iocs.scanText(src, `${prefix}${f}`));
    const r = scanSource(src, `${prefix}${f}`);
    fileCaps[f] = Object.keys(r.caps);
    if (r.aiConfigProject) aiConfigProject[f] = r.aiConfigProject;
    if (r.shellCmd) fileCmd[f] = r.shellCmd;
    if (r.sendsOut) fileSends[f] = r.sendsOut;
    if (r.remoteCode) remoteCode.push(r.remoteCode);
    if (r.spawned.length) fileSpawned[f] = r.spawned;
    mergeCaps(caps, r.caps);
    if (r.exfil) exfil.push(r.exfil);
    if (r.partlyRead) partlyRead.push(f);
  }
  // Code that was never read is not clean code: fail closed.
  if (source.truncated) {
    unscanned = unscanned || `the package has more than ${source.maxFiles} files, so some were never read`;
  }
  if (skipped.length) {
    unscanned = unscanned || `${skipped.length} code file(s) over ${MAX_JS_BYTES / 1024 / 1024} MB were not scanned (${skipped.slice(0, 3).join(", ")}${skipped.length > 3 ? ", ..." : ""})`;
  }

  if (tooBlank.length) {
    unscanned = unscanned || `${tooBlank.length} code file(s) full of blank lines were not scanned (${tooBlank.slice(0, 3).join(", ")}${tooBlank.length > 3 ? ", ..." : ""})`;
  }

  // Install scripts that are themselves suspicious: shell download pipes, or a
  // `node file.js` hook whose file reaches the network, decodes payloads, etc.
  const installRisk = [];
  const resolveScript = (t, from = "") => {
    for (const c of [new URL(t, `file:///${from}`), new URL(t, "file:///")].map((u) => decodeURIComponent(u.pathname.slice(1)))) {
      for (const f of [c, `${c}.js`, `${c}/index.js`]) if (fileCaps[f]) return f;
    }
    return null;
  };
  const riskOf = (file) => {
    const bad = fileCaps[file].filter((c) => RISKY_FOR_INSTALL.includes(c));
    if (fileCmd[file]) bad.push(`shell command at line ${fileCmd[file].line}`);
    return bad;
  };
  for (const [hook, cmd] of Object.entries(installScripts)) {
    if (INSTALL_SHELL_CMD.test(cmd)) installRisk.push(`${hook} runs \`${cmd.slice(0, 80)}\``);
    else if (commandTooLong(cmd)) installRisk.push(`${hook} is too long to read in full (\`${cmd.slice(0, 80)}\`)`);
    // Inline code (`node -e "..."`) is scanned like a file.
    const inline = Object.keys(scanSource(cmd, "package.json").caps).filter((c) => RISKY_FOR_INSTALL.includes(c));
    if (inline.length) installRisk.push(`${hook} inline code (${inline.join(", ")})`);
    // Files the hook runs: `node file.js` or `node -e "require('./file')"`.
    const targets = [
      ...nodeScriptTargets(cmd),
      ...[...cmd.slice(0, 4096).matchAll(/\brequire\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]),
    ].map((t) => t.replace(/^\.\//, ""));
    for (const target of new Set(targets)) {
      const file = resolveScript(target);
      if (!file) continue;
      const bad = riskOf(file);
      if (aiConfigProject[file]) {
        add(caps, "ai-config-write", aiConfigProject[file]);
        bad.push("ai-config-write");
      }
      if (bad.length) installRisk.push(`${hook} runs ${file} (${[...new Set(bad)].join(", ")})`);
      // One hop.
      for (const s of new Set(fileSpawned[file] || [])) {
        const next = resolveScript(s, file);
        if (!next || next === file) continue;
        const nextBad = riskOf(next);
        if (nextBad.length) installRisk.push(`${hook} runs ${file}, which starts ${next} (${[...new Set(nextBad)].join(", ")})`);
      }
    }
  }

  // Entry files run on load, no hook needed.
  const entries = [pkg.main || "index.js", pkg.module, ...JSON.stringify(pkg.exports ?? "").match(/[\w./-]+\.[cm]?js\b/g) || []];
  const sendsOut = [...new Set(entries.filter((e) => typeof e === "string").map((e) => resolveScript(e.replace(/^\.\//, ""))))].map((f) => f && fileSends[f]).filter(Boolean);

  // Dependencies from a URL off npm and the code hosts.
  const remoteDeps = Object.entries({ ...pkg.dependencies, ...pkg.optionalDependencies }).flatMap(([k, v]) => {
    const h = String(v).match(/^https?:\/\/([^/:?#]+)/i)?.[1];
    return h && !/(?:^|\.)(?:github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|npmjs\.org|yarnpkg\.com)$/i.test(h)
      ? [{ file: `${prefix}package.json`, line: findLine(pkgText, `"${k}"`), snippet: `${k}: ${v}`.slice(0, 160), host: h }] : [];
  });

  // Stable evidence order.
  for (const v of Object.values(caps)) {
    v.evidence.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  }
  const ordered = {};
  for (const id of CAPABILITY_ORDER) if (caps[id]) ordered[id] = caps[id];

  return {
    name: pkg.name || null,
    version: pkg.version || null,
    capabilities: ordered,
    installScripts,
    installRisk,
    exfil,
    remoteCode,
    sendsOut,
    remoteDeps,
    filesScanned,
    skipped,
    unscanned,
    partlyRead,
    iocHits,
  };
}
