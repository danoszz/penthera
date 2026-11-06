/**
 * Static capability detection for Python packages (`penthera deps`).
 *
 * The Python half of lib/deps/capabilities.js, with the same capability ids,
 * evidence shape and return value, so the diff, the PR comment, policy and the
 * install firewall treat a PyPI package like an npm one. Comments and
 * docstrings are blanked by a small tokenizer, then line-level patterns run
 * over the code. No AST, no interpreter, no network.
 *
 * Python-specific install-time and persistence paths:
 *   - setup.py with custom commands (cmdclass) runs when pip builds an sdist;
 *   - *.pth files in site-packages run every line that starts with "import"
 *     on each interpreter start, which malware uses for persistence;
 *   - a top-level sitecustomize.py or usercustomize.py is imported by site.py
 *     on each interpreter start too.
 * A wheel places files at the site-packages root from its top level and from
 * <name>-<version>.data/purelib/ and .data/platlib/ (litellm 1.107.0 shipped
 * its .pth there, OSV MAL-2026-2144), so both count as the root.
 *
 * Literals that name attack indicators are assembled at runtime (see
 * lib/deps/capabilities.js) so this file does not read like a payload.
 */
import { createHash } from "node:crypto";
import { pythonLines, lfLineBreaks } from "../../linear-text.js";
import {
  CAPABILITY_ORDER, INDICATORS, RISKY_FOR_INSTALL, INSTALL_SHELL_CMD, add, snippet, obfuscationSignals, mergeCaps, findLine, literalsOf,
} from "../capabilities.js";

const j = (...parts) => parts.join("");
// As for npm: a file over this is not read, and the package is then unscanned.
const MAX_PY_BYTES = 64 * 1024 * 1024;
const EXFIL_WINDOW = 40;
const NEAR_WINDOW = 30;
const PTH_WINDOW = 5;

// ── Tokenizer: blank comments and docstrings, keep strings and line numbers ──

const STRING_START = /[rRbBuUfF]{0,2}(?:"""|'''|"|')/y;

/**
 * Replace comments and bare string statements (docstrings) with spaces,
 * keeping newlines so line numbers stay true. Other strings stay intact: they
 * hold the paths, URLs and command names the patterns look for. A module that
 * decodes or runs its own __doc__ keeps its docstrings, since hiding a payload there and
 * exec'ing __doc__ is a known trick.
 */
export function blankPython(src) {
  const keepDocstrings = /\b(?:exec|eval|compile|\w*decode\w*|decompress|loads)\s*\([^)\n]*\b__doc__\b/.test(src);
  const n = src.length;
  const parts = [];
  let last = 0;
  let i = 0;
  let depth = 0;
  let stmtStart = true;
  const blank = (s) => s.replace(/[^\n]/g, " ");
  while (i < n) {
    const ch = src[i];
    if (ch === "#") {
      let end = src.indexOf("\n", i);
      if (end === -1) end = n;
      parts.push(src.slice(last, i), " ".repeat(end - i));
      i = last = end;
      continue;
    }
    if (ch === "\n") {
      if (depth === 0) stmtStart = true;
      i++;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\f") { i++; continue; }
    if (ch === "\\" && (src[i + 1] === "\n" || (src[i + 1] === "\r" && src[i + 2] === "\n"))) {
      i += src[i + 1] === "\n" ? 2 : 3;
      continue;
    }
    STRING_START.lastIndex = i;
    const sm = (i === 0 || !/[\w]/.test(src[i - 1])) && STRING_START.exec(src);
    if (sm) {
      const quote = sm[0].replace(/^[rRbBuUfF]+/, "");
      let k = i + sm[0].length;
      if (quote.length === 3) {
        while (k < n && !src.startsWith(quote, k)) k += src[k] === "\\" ? 2 : 1;
        k = Math.min(n, k + 3);
      } else {
        while (k < n && src[k] !== quote && src[k] !== "\n") k += src[k] === "\\" ? 2 : 1;
        if (src[k] === quote) k++;
      }
      if (stmtStart && depth === 0 && !keepDocstrings) {
        let after = k;
        while (after < n && (src[after] === " " || src[after] === "\t")) after++;
        if (after >= n || src[after] === "\n" || src[after] === "\r" || src[after] === "#" || src[after] === ";") {
          parts.push(src.slice(last, i), blank(src.slice(i, k)));
          last = k;
        }
      }
      stmtStart = false;
      i = k;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if ((ch === ")" || ch === "]" || ch === "}") && depth > 0) depth--;
    if (ch === ";" && depth === 0) stmtStart = true;
    else if (ch === ":" && depth === 0) stmtStart = true; // `def f(): "doc"` on one line
    else stmtStart = false;
    i++;
  }
  parts.push(src.slice(last));
  return parts.join("");
}

// ── Patterns ──────────────────────────────────────────────────────────────

const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** `import a, b.c as d` / `from a.b import c` for any of the given modules. */
const importRe = (mods) => {
  const m = mods.map(esc).join("|");
  return [
    new RegExp(String.raw`(?:^|[;:]\s*)\s*from\s+(?:${m})(?:\.[\w.]+)?\s+import\b`),
    new RegExp(String.raw`(?:^|[;:]\s*)\s*import\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*(?:${m})(?![\w])`),
  ];
};

const NET_MODS = ["socket", "urllib.request", "urllib2", "urllib3", "http.client", "httplib", "requests", "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib", "websocket", "websockets", "pycurl", "paramiko"];
const DECODE_CALL = String.raw`(?:base64\.\w*decode\w*|b64decode|b32decode|b85decode|a85decode|zlib\.decompress|decompress|marshal\.loads|bz2\.decompress|lzma\.decompress|gzip\.decompress|codecs\.decode|bytes\.fromhex|binascii\.\w+|unhexlify)`;
const HOME_VARS = "HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_CONFIG_HOME";

const P = {
  shell: [
    ...importRe(["subprocess", "pty", "commands"]),
    /\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)\s*\(/,
    /\bpty\.spawn\s*\(/,
    /\basyncio\.create_subprocess_(?:exec|shell)\s*\(/,
    /\b__import__\s*\(\s*['"](?:os|subprocess|pty)['"]\s*\)\s*\.\s*(?:system|popen|run|Popen|call|check_output|getoutput|spawn)\b/,
  ],
  network: [
    ...importRe(NET_MODS),
    /(?:^|[;:])\s*from\s+urllib\s+import\b[\w\s,()]*\b(?:request|urlopen)\b/,
    /\burlopen\s*\(/,
    /\b__import__\s*\(\s*['"](?:socket|urllib\.request|requests|http\.client)['"]/,
  ],
  env: [/\bos\.environ\b/, /\bos\.getenv\s*\(/, /\bos\.environb\b/],
  envSerialise: /\b(?:json\.dumps?|str|repr|pickle\.dumps?|base64\.\w*encode|yaml\.\w*dump|marshal\.dumps?|urlencode)\s*\(\s*(?:dict\s*\(\s*)?(?:\*\*\s*)?os\.environ\b(?!\s*[.[])|\b(?:json\.dumps?|str|repr)\s*\(\s*\{\s*\*\*\s*os\.environ\s*\}/,
  envBulk: [
    /\bos\.environ\.(?:items|keys|values)\s*\(/,
    /\bfor\b[\w\s,()]*\bin\s+os\.environ\s*:/,
  ],
  eval: [
    /(?<![\w.]|\bdef\s{1,4})eval\s*\(/,
    /(?<![\w.]|\bdef\s{1,4})exec\s*\(/,
    /(?<![\w.]|\bdef\s{1,4})execfile\s*\(/,
    /(?<![\w.]|\bdef\s{1,4})compile\s*\(/,
    /\btypes\.(?:FunctionType|CodeType)\s*\(/,
    /\brunpy\.run_(?:path|module)\s*\(/,
    /\bbuiltins['"]?\s*(?:\)\s*)?\.\s*(?:exec|eval)\s*\(/,
  ],
  dynamicRequire: [
    /(?<![\w.])__import__\s*\(\s*(?!['"][\w.]+['"]\s*[,)])(?!\))/,
    /\bimport_module\s*\(\s*(?!['"][\w.]+['"]\s*[,)])(?!\))/,
  ],
  deserialize: [
    /\b(?:pickle|cPickle|_pickle|dill|cloudpickle)\.(?:loads?|Unpickler)\s*\(/,
    /\bmarshal\.loads?\s*\(/,
    /\byaml\.unsafe_load(?:_all)?\s*\(/,
    /\byaml\.load(?:_all)?\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?(?:Safe|Base)Loader)/,
  ],
  native: [/\bctypes\.(?:CDLL|cdll|WinDLL|windll|PyDLL|LibraryLoader)\b/, /\bffi\.dlopen\s*\(/],
  fsReadCall: /(?<![\w.])open\s*\(|\.read_(?:text|bytes)\s*\(/,
  fsWriteCall: /(?<![\w])(?:io\.|codecs\.)?open\s*\([^#]*?(?:,\s*|mode\s*=\s*)[rbuf]?['"][rbt]*[wax][+bt]*['"]|\.(?:write_text|write_bytes)\s*\(|\bshutil\.(?:copy|copy2|copyfile|copytree|move)\s*\(|\bos\.(?:rename|replace|symlink|link|chmod)\s*\(/,
  outsidePath: new RegExp([
    String.raw`\bos\.path\.expanduser\s*\(`,
    String.raw`\bPath\.home\s*\(\s*\)`,
    String.raw`\bos\.(?:environ(?:\.get\s*\(|\s*\[)|getenv\s*\()\s*['"](?:${HOME_VARS})['"]`,
    String.raw`['"]~[/\\]`,
    String.raw`['"]/(?:etc|usr|var|Library|System)/`,
    String.raw`['"][A-Z]:\\\\(?:Windows|Users)`,
    String.raw`\bsite\.(?:getsitepackages|getusersitepackages|USER_SITE)\b`,
    String.raw`\bsysconfig\.get_paths?\s*\(`,
  ].join("|")),
  pthPath: /['"][^'"\n]*\.pth['"]/,
  // The classic dropper in one expression: exec(base64.b64decode(...)), exec(zlib.decompress(...)).
  // ...also through an alias: exec(f('<long encoded literal>')).
  execDecode: new RegExp(String.raw`(?<![\w.])(?:exec|eval)\s*\(\s*(?:(?:[\w.]+\s*\(\s*)*${DECODE_CALL}\s*\(|(?:[\w.]+\s*\(\s*)+[rbuf]{0,2}['"][\w+/=]{100})`),
  // A statement pushed off screen: `x()<150+ spaces>; exec(...)`.
  hidden: /\S[ \t]{150,};\s*[A-Za-z_]/,
  // Download to a file, then make it executable or start it.
  dl: /\burlretrieve\s*\(|\.write\s*\(\s*\w+\.content\b|\b(?:curl|wget)\b[^'"\n]*\s-\w*[oO]\b/i,
  runFile: /\bos\.startfile\s*\(|chmod\s+\+x|Start-Process|\bsubprocess\.(?:run|Popen|call|check_call)\s*\(\s*(?:\[\s*)?[a-z_]\w*\s*[\],)]|\bos\.system\s*\(\s*f?['"](?:\.\/|start\s)/i,
  execResp: /(?<![\w.])(?:exec|eval)\s*\(\s*(?:requests\.get\s*\(|urlopen\s*\(|\w+\.(?:text|content)\b|\w+\.read\(\))/,
  pyarmor: /\b__pyarmor__\b|\bpyarmor_runtime\b/,
};
const DECODE_RE = new RegExp(String.raw`\b${DECODE_CALL}\s*\(`);

const AI_CLI_CALL_RE = new RegExp(
  String.raw`\b(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput|system|popen|spawn|create_subprocess_exec|create_subprocess_shell)\s*\(\s*\[?\s*[rbuf]?['"](?:${INDICATORS.AI_CLIS.join("|")})(?:['"]|\s)`,
);
const GH_TOKEN_LIST_RE = new RegExp(j("['\"]gh['\"]\\s*,\\s*['\"]auth['\"]\\s*,\\s*['\"]", "token['\"]"));

// ── Code that runs at import ──────────────────────────────────────────────

const NET_IO = /\b(?:requests|httpx|urllib3|session)\.(?:get|post|put|patch|request|head)\s*\(|\b(?:urlopen|urlretrieve|getaddrinfo|gethostbyname|create_connection)\s*\(|\.connect\s*\(\s*\(|\bHTTPS?Connection\s*\(/;
const SHELL_CALL = /\bsubprocess\.\w+\s*\(|\bos\.(?:system|popen|startfile)\s*\(|(?<![\w.])(?:Popen|check_output|check_call|getoutput|call|run)\s*\(/;
const BLOCK_RE = /^\s*(?:(?:async\s+)?def\s+(\w+)|class\s|if\s+__name__\s*==)/;

/**
 * Line indexes that run when the module is imported: module-level statements
 * (not in a def, a class or the __main__ guard), plus the bodies of local
 * functions they call directly.
 */
export function importLines(code) {
  code = lfLineBreaks(code, "python");
  const ls = code.replace(/("""|''')[\s\S]*?\1/g, (m) => m.replace(/[^\n]/g, " ")).split("\n")
    .map((l) => l.replace(/(["'])(?:\\.|(?!\1)[^\\])*\1/g, "''"));
  const top = [];
  const fns = new Map();
  let skip = -1;
  let cur = null;
  let depth = 0;
  for (let i = 0; i < ls.length; i++) {
    const l = ls[i];
    const inside = depth > 0;
    for (const ch of l) depth = Math.max(0, depth + ("([{".includes(ch) ? 1 : ")]}".includes(ch) ? -1 : 0));
    if (!l.trim()) continue;
    const ind = l.length - l.trimStart().length;
    if ((skip >= 0 && (ind > skip || inside))) { if (cur) cur[1] = i; continue; }
    if (inside) { top.push(i); continue; }
    skip = -1;
    cur = null;
    const m = l.match(BLOCK_RE);
    if (m) { skip = ind; if (m[1]) fns.set(m[1], (cur = [i, i])); continue; }
    top.push(i);
  }
  const run = new Set(top);
  for (const i of top) {
    for (const m of ls[i].matchAll(/(?<![\w.])(\w+)\s*\(|\btarget\s*=\s*(\w+)/g)) {
      const r = fns.get(m[1] || m[2]);
      for (let k = r ? r[0] + 1 : 1; r && k <= r[1]; k++) run.add(k);
    }
  }
  return [...run].sort((a, b) => a - b);
}

// A chat bot token or a webhook with its key, written into the code: a channel to send data out.
const CHAT_KEY = new RegExp(String.raw`\b\d{8,10}:AA[\w-]{33}\b|discord(?:app)?\.com/api/${j("web", "hooks")}/\d{17,20}/[\w-]{60,}`);

function importRisk(code, lines, has, file) {
  if (!(has.network || has.shell)) return null;
  for (const i of importLines(code)) {
    const l = lines[i];
    if (has.network && NET_IO.test(l)) return { file, line: i + 1, cap: "network", what: "makes a network call", snippet: snippet(l, l.search(NET_IO)) };
    if (has.shell && SHELL_CALL.test(l) && lines.slice(i, i + 4).some((x) => literalsOf(x).some((s) => INSTALL_SHELL_CMD.test(s.text)))) {
      return { file, line: i + 1, cap: "shell", what: "runs a download or send command", snippet: snippet(l, l.search(SHELL_CALL)) };
    }
  }
  return null;
}

// ── Per-file scan ─────────────────────────────────────────────────────────

/**
 * Scan one Python file's source. Same return shape as scanSource() for JS:
 * { caps, exfil, aiConfigProject }, plus pthWrite (a write of a .pth file).
 */
export function scanPythonSource(src, file) {
  src = lfLineBreaks(src, "python"); // a lone CR ends a Python line too
  const caps = {};
  const code = blankPython(src);
  const lines = code.split("\n");
  const has = { shell: false, network: false, fsRead: false, outside: false, envBulk: false, eval: false };
  const firstHit = {};
  const netLines = [];
  const writeHits = [];
  const outsideLines = [];
  const pthLines = [];
  const aiConfigHits = [];
  const serialiseHits = [];
  const dlLines = [];

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
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
    if (hit("network", P.network)) { has.network = true; netLines.push(i + 1); }
    hit("env", P.env);
    const ser = ev(P.envSerialise);
    if (ser) { add(caps, "env-bulk", ser); has.envBulk = true; serialiseHits.push(ser); }
    else if (hit("env-bulk", P.envBulk)) has.envBulk = true;
    if (hit("eval", P.eval)) has.eval = true;
    hit("dynamic-require", P.dynamicRequire);
    hit("deserialize", P.deserialize);
    hit("native", P.native);

    const w = ev(P.fsWriteCall);
    if (w) writeHits.push(w);
    if (P.outsidePath.test(l)) { has.outside = true; outsideLines.push(i + 1); }
    if (P.pthPath.test(l)) pthLines.push(i + 1);
    if (P.fsReadCall.test(l)) has.fsRead = true;

    const aiCfg = ev(INDICATORS.AI_CONFIG_RE);
    if (aiCfg) aiConfigHits.push(aiCfg);
    const aiCall = ev(AI_CLI_CALL_RE) || ev(INDICATORS.AI_CLI_FLAG_RE);
    if (aiCall) firstHit.aiCli = firstHit.aiCli || aiCall;
    const ghCmd = ev(INDICATORS.GH_TOKEN_CMD_RE) || ev(GH_TOKEN_LIST_RE);
    if (ghCmd) firstHit.ghCmd = firstHit.ghCmd || ghCmd;
    const ghFile = ev(INDICATORS.GH_CRED_FILE_RE);
    if (ghFile) firstHit.ghFile = firstHit.ghFile || ghFile;
    const ghShape = ev(INDICATORS.GH_TOKEN_REGEX_RE);
    if (ghShape) firstHit.ghShape = firstHit.ghShape || ghShape;
    const dropper = ev(P.execDecode);
    if (dropper) firstHit.dropper = firstHit.dropper || dropper;
    const armor = ev(P.pyarmor);
    if (armor) firstHit.armor = firstHit.armor || armor;
    if (!firstHit.hidden && P.hidden.test(l)) firstHit.hidden = { file, line: i + 1, snippet: "a statement hidden after a long run of spaces" };
    if (P.dl.test(l)) dlLines.push(i + 1);
    const run = ev(P.runFile) || (has.network && ev(P.execResp));
    if (run && !firstHit.run && (P.execResp.test(l) || dlLines.some((d) => i + 1 - d <= 15))) firstHit.run = run;
  }

  const near = (line, list) => list.some((n) => Math.abs(n - line) <= NEAR_WINDOW);
  const outsideWrite = writeHits.find((w) => near(w.line, outsideLines));
  if (outsideWrite) add(caps, "fs-write", outsideWrite);
  // Writing a .pth file installs code that runs on every interpreter start.
  const pthWrite = writeHits.find((w) => pthLines.some((n) => Math.abs(n - w.line) <= PTH_WINDOW)) || null;
  if (pthWrite) add(caps, "startup-hook", { ...pthWrite, snippet: `writes a .pth file: ${pthWrite.snippet}` });

  const writeLines = writeHits.map((w) => w.line);
  const aiWrites = aiConfigHits.filter((h) => near(h.line, writeLines));
  const homeWrite = aiWrites.find((h) => near(h.line, outsideLines) || INDICATORS.DESKTOP_CONFIG_RE.test(h.snippet));
  if (homeWrite) add(caps, "ai-config-write", homeWrite);
  const aiConfigProject = homeWrite ? null : aiWrites[0] || null;
  if (firstHit.aiCli && has.shell) add(caps, "ai-cli-invoke", firstHit.aiCli);
  if (firstHit.ghCmd && has.shell) add(caps, "token-harvest", firstHit.ghCmd);
  else if (firstHit.ghFile && (has.fsRead || has.network)) add(caps, "token-harvest", firstHit.ghFile);
  else if (firstHit.ghShape && has.network && (has.envBulk || has.outside)) add(caps, "token-harvest", firstHit.ghShape);

  if (firstHit.dropper) {
    add(caps, "obfuscated", { ...firstHit.dropper, snippet: `decoded payload handed to exec/eval: ${firstHit.dropper.snippet}` });
  } else if (firstHit.armor) {
    add(caps, "obfuscated", { ...firstHit.armor, snippet: `PyArmor-protected code: ${firstHit.armor.snippet}` });
  } else if (firstHit.hidden) {
    add(caps, "obfuscated", firstHit.hidden);
  } else {
    // Byte literals full of \x escapes are normal in Python (palettes, fonts,
    // magic numbers); they only count next to dynamic code.
    const obf = obfuscationSignals(code, { hasDynamicCode: has.eval, evalRes: P.eval, decodeRe: DECODE_RE, strongEscapes: has.eval });
    if (obf.flagged) add(caps, "obfuscated", { file, line: obf.line, snippet: obf.signals.join("; ") });
  }

  const exfil = serialiseHits.find((e) => netLines.some((n) => Math.abs(n - e.line) <= EXFIL_WINDOW)) || null;
  const chat = has.network && code.match(CHAT_KEY);
  const chatKey = chat ? { file, line: code.slice(0, chat.index).split("\n").length, snippet: "a chat bot token or webhook key in the code" } : null;
  const remoteCode = ((has.network || has.shell) && firstHit.run) || null;
  return { caps, exfil, aiConfigProject, pthWrite, importRun: importRisk(code, lines, has, file), chatKey, remoteCode };
}

// ── .pth files ────────────────────────────────────────────────────────────

/**
 * Executable lines of a .pth file: site.py exec()s every line that starts
 * with "import" (followed by a space or tab). Other lines are path entries.
 */
export function pthImportLines(text) {
  // site.py reads .pth lines with universal newlines (3.12) or splitlines (3.13).
  return pythonLines(text).map((l, i) => ({ line: i + 1, text: l }))
    .filter((l) => /^import[ \t]/.test(l.text));
}

/** Top-level module names a .pth import line loads. */
function pthModules(lineText) {
  const out = [];
  for (const stmt of lineText.split(";")) {
    const m = stmt.trim().match(/^import\s+(\S.*)$/);
    if (m) for (const part of m[1].split(",")) out.push(part.trim().split(/\s+/)[0].split(".")[0]);
  }
  return out.filter((x) => /^[\w]+$/.test(x));
}

// Where a file lands relative to site-packages when the package is installed,
// or null when it lands elsewhere. Wheels install .data/purelib and
// .data/platlib at the root; .data/data is relative to sys.prefix, so a path
// under it that ends in site-packages/ also reaches the root.
const WHEEL_ROOT_RE = /^[^/]+\.data\/(?:purelib|platlib)\/(.+)$/;
const DATA_SITE_RE = /^[^/]+\.data\/data\/(?:.*\/)?site-packages\/(.+)$/;
export function installedPath(rel) {
  const m = rel.match(WHEEL_ROOT_RE) || rel.match(DATA_SITE_RE);
  return m ? m[1] : rel;
}
const STARTUP_MODULES = new Set(["sitecustomize.py", "usercustomize.py"]);

// ── setup.py ──────────────────────────────────────────────────────────────

// exec(open(p).read()): the local version-file idiom.
const LOCAL_EXEC = /\bexec\s*\(\s*(?:compile\s*\(\s*)?(?:open\s*\([^()]*\)|[\w.]+)\.read\s*\(\s*\)/g;
// Installing more packages from build code, past the resolver and any lockfile.
const PIP_INSTALL = /\bpip3?['",\s]+install\b/;
const RECON_LITERAL = /['"](?:whoami|hostname|uname(?: -a)?|id|ifconfig|ipconfig|printenv)['"]/;
const CMDCLASS_RE = /\bcmdclass\s*=|\bcmdclass\s*\[/;
const CUSTOM_CMD_RE = /\bclass\s+(\w+)\s*\(\s*(?:[\w.]*\b)?(install|develop|egg_info|build_py|build_ext|build|sdist|bdist_wheel|Command)\s*\)/;

// ── RECORD integrity ──────────────────────────────────────────────────────

/** RECORD hash of bytes: "sha256=<urlsafe base64, no padding>". */
export function recordHash(bytes, algo = "sha256") {
  return `${algo}=${createHash(algo).update(bytes).digest("base64url")}`;
}

// ── Per-package scan ──────────────────────────────────────────────────────

const PY_EXT = /\.pyw?$/i;
// Files a user's import does not load: tests, examples, docs, scripts, build files.
const NOT_IMPORTED = /(?:^|\/)(?:tests?|testing|examples?|docs?|scripts?|benchmarks?)\/|(?:^|\/)(?:test_[^/]*|[^/]*_test|conftest|setup|__main__|noxfile)\.py$/i;
const NATIVE_EXT = /\.(?:so(?:\.\d+)*|pyd|dylib|dll)$/i;

/**
 * Scan a Python package through a source (lib/deps/source.js interface; a
 * source may also expose recordHashes: Map<rel, "sha256=...">).
 * @param {{ files(): string[], read(rel): Buffer, size(rel): number, recordHashes?: Map, anomaly?: string, truncated?: boolean }} source
 * @param {{ prefix?: string, iocs?: ReturnType<import("../iocs.js").loadIocs> }} opts
 * @returns same shape as scanPackage() for npm (including unscanned: why the
 *   package could not be fully read, else null, and iocHits), plus
 *   startupHooks and modified
 */
export function scanPythonPackage(source, opts = {}) {
  const prefix = opts.prefix || "";
  const caps = {};
  const files = source.files();
  const iocs = opts.iocs || null;
  const iocHits = iocs ? iocs.scanFiles(files, source, prefix) : [];
  const fileSet = new Set(files);
  const fileCaps = {};
  const exfil = [];
  const importRun = [];
  const chatKey = [];
  const remoteCode = [];
  const skipped = [];
  const unread = []; // code or .pth files that could not be read
  const modified = [];
  const aiConfigProject = {};
  let filesScanned = 0;

  // A module an import of the package can load: at the top, or in a folder with an __init__.py.
  const importable = (f) => {
    const dir = f.slice(0, f.lastIndexOf("/") + 1);
    return !NOT_IMPORTED.test(installedPath(f)) && (!dir || /(?:^|\/)__init__\.py$/.test(f) || fileSet.has(`${dir}__init__.py`) || /^src\/[^/]+$/.test(f));
  };
  const checkRecord = (f, bytes) => {
    const expected = source.recordHashes?.get(f);
    if (!expected) return;
    const [algo] = expected.split("=");
    if (!/^sha(256|384|512)$/.test(algo)) return;
    if (recordHash(bytes, algo) !== expected) modified.push(`${prefix}${f}`);
  };

  for (const f of files) {
    if (NATIVE_EXT.test(f)) add(caps, "native", { file: `${prefix}${f}`, line: 1, snippet: "prebuilt native extension" });
  }

  for (const f of files) {
    if (!PY_EXT.test(f)) continue;
    if (source.size(f) > MAX_PY_BYTES) { skipped.push(f); continue; }
    let bytes;
    try { bytes = source.read(f); } catch { unread.push(f); continue; }
    checkRecord(f, bytes);
    filesScanned++;
    const text = bytes.toString("utf-8");
    if (iocs) iocHits.push(...iocs.scanText(text, `${prefix}${f}`));
    const r = scanPythonSource(text, `${prefix}${f}`);
    fileCaps[f] = Object.keys(r.caps);
    if (r.aiConfigProject) aiConfigProject[f] = r.aiConfigProject;
    mergeCaps(caps, r.caps);
    if (r.exfil) exfil.push(r.exfil);
    if (r.remoteCode) remoteCode.push(r.remoteCode);
    if (importable(f)) {
      if (r.importRun) importRun.push(r.importRun);
      if (r.chatKey) chatKey.push(r.chatKey);
    }
  }

  // Fail closed, as for npm: a package whose files were not all read is
  // unscanned, never clean. Every real wheel, sdist or installed distribution
  // has at least its metadata files, so an empty list means nothing was read.
  let unscanned = source.anomaly || null;
  if (!unscanned && files.length === 0) unscanned = "no files could be read for this package";
  if (!unscanned && source.truncated) unscanned = `the package has more than ${source.maxFiles} files, so some were never read`;
  // Fail closed: a file Python would run that could not be read leaves the package unscanned.
  if (!unscanned && unread.length) unscanned = `${unread.length} file(s) could not be read (${[...new Set(unread)].slice(0, 3).join(", ")}${unread.length > 3 ? ", ..." : ""})`;
  if (!unscanned && skipped.length) {
    unscanned = `${skipped.length} code file(s) over ${MAX_PY_BYTES / 1024 / 1024} MB were not scanned (${skipped.slice(0, 3).join(", ")}${skipped.length > 3 ? ", ..." : ""})`;
  }

  // Installed path -> file in the package (a wheel's .data/purelib counts as the root).
  const atRoot = new Map();
  for (const f of files) {
    const p = installedPath(f);
    if (!atRoot.has(p)) atRoot.set(p, f);
  }
  // Module name -> file, for resolving what a .pth or setup.py hook runs.
  // A package wins over a module of the same name, as in Python; sdists often keep code under src/.
  const moduleFile = (mod) => {
    const p = mod.replace(/\./g, "/");
    return [`${p}/__init__.py`, `${p}.py`, `src/${p}/__init__.py`, `src/${p}.py`].map((f) => atRoot.get(f)).find(Boolean) || null;
  };
  const riskyOf = (f) => (f && fileCaps[f] ? fileCaps[f].filter((c) => RISKY_FOR_INSTALL.includes(c) || c === "shell") : []);
  // Risky build code downloads and runs; running git, a compiler or a build tool is not.
  const buildRisk = (f) => {
    const code = fileCaps[f] ? blankPython(source.read(f).toString("utf-8")) : "";
    return riskyOf(f).filter((c) => (c === "shell" ? fileCaps[f].includes("network") || INSTALL_SHELL_CMD.test(code) || RECON_LITERAL.test(code) || PIP_INSTALL.test(code)
      : c !== "eval" || P.eval.some((re) => re.test(code.replace(LOCAL_EXEC, "")))));
  };

  // .pth files that land at the top level of site-packages (or of the package source).
  const startupHooks = [];
  for (const f of files.filter((x) => /^[^/]+\.pth$/i.test(installedPath(x)))) {
    let text;
    try {
      const bytes = source.read(f);
      checkRecord(f, bytes);
      text = bytes.toString("utf-8");
    } catch { unread.push(f); continue; }
    for (const l of pthImportLines(text)) {
      const ev = { file: `${prefix}${f}`, line: l.line, snippet: snippet(l.text, 0) };
      add(caps, "startup-hook", ev);
      const risk = [];
      const inline = scanPythonSource(l.text, `${prefix}${f}`);
      const inlineBad = Object.keys(inline.caps).filter((c) => RISKY_FOR_INSTALL.includes(c) || c === "shell");
      if (inlineBad.length) risk.push(`the line itself uses ${inlineBad.join(", ")}`);
      mergeCaps(caps, Object.fromEntries(Object.entries(inline.caps).filter(([id]) => id !== "env")));
      for (const mod of pthModules(l.text)) {
        const mf = moduleFile(mod);
        const bad = riskyOf(mf);
        if (bad.length) risk.push(`imports ${mf} (${bad.join(", ")})`);
      }
      startupHooks.push({ ...ev, risk });
    }
  }
  // sitecustomize / usercustomize at the root: imported on every interpreter
  // start, and installing one replaces whatever the environment had.
  for (const [p, f] of atRoot) {
    if (!STARTUP_MODULES.has(p)) continue;
    const ev = { file: `${prefix}${f}`, line: 1, snippet: `${p} is imported at every Python start` };
    add(caps, "startup-hook", ev);
    const bad = riskyOf(f);
    startupHooks.push({ ...ev, risk: [`a library has no reason to ship ${p}`, ...(bad.length ? [`${f} uses ${bad.join(", ")}`] : [])] });
  }

  // Install-time code: setup.py custom commands, or an in-tree build backend.
  const installScripts = {};
  const installRisk = [];
  if (fileSet.has("setup.py")) {
    let text = "";
    try { text = source.read("setup.py").toString("utf-8"); } catch { /* unreadable */ }
    const code = blankPython(text);
    const custom = code.match(CUSTOM_CMD_RE);
    const bad = riskyOf("setup.py");
    // Helper modules setup.py imports from the same tree, and the ones they import (three levels).
    const helperRisk = [];
    const seen = new Set(["setup.py"]);
    const helpers = (src, depth) => {
      for (const m of src.matchAll(/(?:^|\n)[ \t]*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))/g)) {
        const mf = moduleFile(m[1] || m[2]);
        if (!mf || seen.has(mf)) continue;
        seen.add(mf);
        // eval in a library module setup.py happens to import is too common to count.
        const b = buildRisk(mf).filter((c) => c !== "eval" || (depth === 0 && !m[1]?.includes(".")));
        if (b.length) helperRisk.push(`setup.py imports ${mf} (${b.join(", ")})`);
        else if (depth < 2 && fileCaps[mf]) helpers(blankPython(source.read(mf).toString("utf-8")), depth + 1);
      }
    };
    helpers(code, 0);
    if (CMDCLASS_RE.test(code) || custom || bad.length || helperRisk.length) {
      const needle = custom ? custom[0] : (code.match(CMDCLASS_RE)?.[0] || "setup(");
      const line = findLine(code, needle);
      const what = custom ? `custom ${custom[2]} command (${custom[1]})` : CMDCLASS_RE.test(code) ? "custom commands (cmdclass)" : "code at build time";
      installScripts["setup.py"] = what;
      add(caps, "install-scripts", { file: `${prefix}setup.py`, line, snippet: `setup.py: ${what}` });
      const risk = buildRisk("setup.py");
      if (risk.length) installRisk.push(`setup.py uses ${risk.join(", ")}`);
      if (aiConfigProject["setup.py"]) {
        add(caps, "ai-config-write", aiConfigProject["setup.py"]);
        installRisk.push("setup.py writes AI agent config");
      }
      installRisk.push(...helperRisk);
    }
  }
  if (fileSet.has("pyproject.toml")) {
    let text = "";
    try { text = source.read("pyproject.toml").toString("utf-8"); } catch { /* unreadable */ }
    if (/^[ \t]*backend-path\s*=/m.test(text)) {
      installScripts["pyproject.toml"] = "in-tree build backend (backend-path)";
      add(caps, "install-scripts", { file: `${prefix}pyproject.toml`, line: findLine(text, "backend-path"), snippet: "in-tree build backend (backend-path)" });
    }
  }

  // A .pth read above that failed is known only now.
  if (!unscanned && unread.length) unscanned = `${unread.length} file(s) could not be read (${[...new Set(unread)].slice(0, 3).join(", ")}${unread.length > 3 ? ", ..." : ""})`;
  for (const v of Object.values(caps)) v.evidence.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  const ordered = {};
  for (const id of CAPABILITY_ORDER) if (caps[id]) ordered[id] = caps[id];

  return {
    name: null,
    version: null,
    capabilities: ordered,
    installScripts,
    installRisk: [...new Set(installRisk)],
    exfil,
    importRun,
    chatKey,
    remoteCode,
    filesScanned,
    skipped,
    unscanned,
    startupHooks,
    modified,
    iocHits,
  };
}
