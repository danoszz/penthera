/**
 * Penthera — Internal Machine Security Audit
 *
 * Checks the local macOS machine for keyloggers, trojans, rootkits,
 * suspicious persistence, unauthorized network activity, and weak
 * security posture.
 *
 * Two tiers:
 *   1. Built-in macOS tools (zero installs needed):
 *      csrutil, spctl, xprotect, codesign, lsof, profiles, etc.
 *
 *   2. Optional open-source tools (if installed):
 *      osquery, ClamAV, rkhunter, chkrootkit
 *
 * Everything runs locally. No API keys, no cloud, no tokens.
 */

import { execSync, execFileSync } from "node:child_process";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { homedir } from "node:os";

// ── Helpers ─────────────────────────────────────────────────────────────

function run(cmd, opts = {}) {
  try {
    return execSync(cmd, {
      encoding: "utf-8",
      timeout: opts.timeout || 30_000,
      maxBuffer: 10 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch (e) {
    return e.stdout?.trim?.() || "";
  }
}

function runFile(file, args = [], opts = {}) {
  try {
    return execFileSync(file, args, {
      encoding: "utf-8",
      timeout: opts.timeout || 30_000,
      maxBuffer: 10 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch (e) {
    return e.stdout?.trim?.() || "";
  }
}

function which(bin) {
  try {
    const p = execSync(`which ${bin}`, { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    return p || null;
  } catch { return null; }
}

function safeReadDir(dir) {
  try { return readdirSync(dir); } catch { return []; }
}

function safeReadFile(path) {
  try { return readFileSync(path, "utf-8"); } catch { return ""; }
}

// ── 1. System Integrity Protection ──────────────────────────────────────

function checkSIP() {
  const out = run("csrutil status");
  const enabled = out.includes("enabled");
  return {
    name: "System Integrity Protection (SIP)",
    status: enabled ? "enabled" : "disabled",
    finding: enabled ? null : {
      severity: "critical",
      title: "System Integrity Protection (SIP) is disabled",
      description: "SIP protects core system files from modification. A disabled SIP is a major security risk and may indicate tampering.",
      category: "machine-integrity",
      source: "machine-audit",
    },
  };
}

// ── 2. Gatekeeper ───────────────────────────────────────────────────────

function checkGatekeeper() {
  const out = run("spctl --status 2>&1");
  const enabled = out.includes("assessments enabled");
  return {
    name: "Gatekeeper",
    status: enabled ? "enabled" : "disabled",
    finding: enabled ? null : {
      severity: "high",
      title: "Gatekeeper is disabled",
      description: "Gatekeeper blocks unsigned/unnotarized apps. Disabling it allows any app to run, including malware.",
      category: "machine-integrity",
      source: "machine-audit",
    },
  };
}

// ── 3. Firewall ─────────────────────────────────────────────────────────

function checkFirewall() {
  const out = run("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1");
  const enabled = out.includes("enabled");
  return {
    name: "Application Firewall",
    status: enabled ? "enabled" : "disabled",
    finding: enabled ? null : {
      severity: "medium",
      title: "macOS Application Firewall is disabled",
      description: "The built-in firewall blocks unauthorized incoming connections. Enable it in System Settings > Network > Firewall.",
      category: "machine-config",
      source: "machine-audit",
    },
  };
}

// ── 4. FileVault (disk encryption) ──────────────────────────────────────

function checkFileVault() {
  const out = run("fdesetup status 2>&1");
  const on = out.includes("FileVault is On");
  return {
    name: "FileVault (Disk Encryption)",
    status: on ? "enabled" : "disabled",
    finding: on ? null : {
      severity: "medium",
      title: "FileVault disk encryption is off",
      description: "Without FileVault, anyone with physical access can read your disk. Enable in System Settings > Privacy & Security > FileVault.",
      category: "machine-config",
      source: "machine-audit",
    },
  };
}

// ── 5. XProtect ─────────────────────────────────────────────────────────

function checkXProtect() {
  const version = run("xprotect version 2>&1");
  const status = run("xprotect status 2>&1");
  const upToDate = !status.includes("updates available");
  return {
    name: "XProtect (Apple Malware Detection)",
    status: version || "unknown",
    detail: status,
    finding: null, // XProtect is always on in modern macOS
  };
}

// ── 6. LaunchAgents & LaunchDaemons (persistence) ───────────────────────

function checkPersistence() {
  const home = homedir();
  const dirs = [
    { path: join(home, "Library/LaunchAgents"), scope: "user", risk: "medium" },
    { path: "/Library/LaunchAgents", scope: "system", risk: "high" },
    { path: "/Library/LaunchDaemons", scope: "system", risk: "high" },
  ];

  const items = [];
  const findings = [];

  // Known legitimate prefixes
  const KNOWN_PREFIXES = [
    "com.apple.", "com.google.", "com.microsoft.", "com.adobe.",
    "com.docker.", "com.github.", "com.spotify.", "com.dropbox.",
    "com.1password.", "com.objective-see.", "org.mozilla.", "com.brave.",
    "com.figma.", "com.notion.", "com.slack.", "com.zoom.", "us.zoom.",
    "com.logi.", "com.logitech.", "com.valvesoftware.", "org.virtualbox.",
    "com.parallels.", "io.tailscale.", "com.cloudflare.",
    "homebrew.", "org.nix.", "com.nordvpn.", "com.expressvpn.",
    "com.openai.", "ai.openclaw.", "com.anthropic.",
    "com.autodesk.", "com.wibu.", "com.jetbrains.",
    "com.linear.", "com.raycast.", "com.todoist.",
    "com.elgato.", "com.corsair.", "com.steelseries.",
    "org.pqrs.", "com.hegenberg.", "com.knollsoft.",
  ];

  for (const dir of dirs) {
    const files = safeReadDir(dir.path).filter((f) => f.endsWith(".plist"));
    for (const file of files) {
      const fullPath = join(dir.path, file);
      const content = safeReadFile(fullPath);
      const label = file.replace(/\.plist$/, "");

      // Extract the program/binary it runs
      const programMatch = content.match(/<key>Program<\/key>\s*<string>([^<]+)<\/string>/);
      const argMatch = content.match(/<key>ProgramArguments<\/key>\s*<array>\s*<string>([^<]+)<\/string>/);
      const program = programMatch?.[1] || argMatch?.[1] || "unknown";

      const isKnown = KNOWN_PREFIXES.some((p) => label.toLowerCase().startsWith(p));

      // Check code signature of the binary
      let signed = null;
      if (program !== "unknown" && existsSync(program)) {
        const sigOut = run(`codesign -v "${program}" 2>&1`);
        signed = sigOut === "" || sigOut.includes("valid on disk"); // empty = valid
      }

      items.push({
        label,
        path: fullPath,
        program,
        scope: dir.scope,
        known: isKnown,
        signed,
      });

      // Flag suspicious items
      if (!isKnown) {
        const severity = signed === false ? "high" : dir.risk === "high" ? "medium" : "low";
        findings.push({
          severity,
          title: `Unknown ${dir.scope} persistence: ${label}`,
          description: `${fullPath} → ${program}${signed === false ? " (UNSIGNED)" : ""}`,
          category: "persistence",
          source: "machine-audit",
        });
      }
    }
  }

  return { items, findings };
}

// ── 7. Login Items ──────────────────────────────────────────────────────

function checkLoginItems() {
  // Modern macOS (13+) uses SMAppService, older uses shared file list
  const out = run("osascript -e 'tell application \"System Events\" to get the name of every login item' 2>&1");
  const items = out && !out.includes("error")
    ? out.split(",").map((s) => s.trim()).filter(Boolean)
    : [];
  return { items };
}

// ── 8. Crontab ──────────────────────────────────────────────────────────

function checkCrontab() {
  const out = run("crontab -l 2>&1");
  const hasCron = out && !out.includes("no crontab");
  const entries = hasCron ? out.split("\n").filter((l) => l.trim() && !l.startsWith("#")) : [];
  const findings = entries.map((entry) => ({
    severity: "info",
    title: `Cron job: ${entry.slice(0, 80)}`,
    description: "Review this cron entry for unexpected scheduled tasks",
    category: "persistence",
    source: "machine-audit",
  }));
  return { entries, findings };
}

// ── 9. Suspicious network connections ───────────────────────────────────

function checkNetworkConnections() {
  const out = run("lsof -i -P -n -sTCP:ESTABLISHED 2>/dev/null");
  const lines = out.split("\n").filter((l) => l && !l.startsWith("COMMAND"));
  const connections = [];
  const findings = [];

  // Known suspicious ports or IPs to flag
  const SUSPICIOUS_PORTS = new Set(["4444", "5555", "6666", "6667", "1337", "31337", "12345", "54321"]);

  for (const line of lines) {
    const parts = line.split(/\s+/);
    const process = parts[0];
    const pid = parts[1];
    const name = parts[parts.length - 1]; // last field has the connection
    const remoteMatch = name.match(/->([^:]+):(\d+)/);

    if (remoteMatch) {
      const ip = remoteMatch[1];
      const port = remoteMatch[2];
      connections.push({ process, pid, ip, port });

      if (SUSPICIOUS_PORTS.has(port)) {
        findings.push({
          severity: "high",
          title: `Suspicious outbound connection: ${process} → ${ip}:${port}`,
          description: `PID ${pid} connected to port ${port} (commonly used by RATs/backdoors)`,
          category: "network",
          source: "machine-audit",
        });
      }
    }
  }

  return { connections, findings };
}

// ── 10. Keyboard event taps (keylogger detection) ───────────────────────

function checkEventTaps() {
  // CGEventTap is how keyloggers work on macOS
  // We can check via ioreg or by looking for processes with Input Monitoring TCC
  const findings = [];

  // Check for processes with accessibility or input monitoring
  // This requires checking the TCC database
  const home = homedir();
  const tccPath = join(home, "Library/Application Support/com.apple.TCC/TCC.db");

  if (existsSync(tccPath)) {
    // kTCCServiceAccessibility = accessibility access (can see keystrokes)
    // kTCCServiceListenEvent / kTCCServicePostEvent = input monitoring
    const services = ["kTCCServiceAccessibility", "kTCCServicePostEvent", "kTCCServiceListenEvent"];

    for (const service of services) {
      const out = run(`sqlite3 "${tccPath}" "SELECT client, auth_value FROM access WHERE service='${service}' AND auth_value=2" 2>&1`);
      if (out && !out.includes("Error") && !out.includes("unable")) {
        const lines = out.split("\n").filter(Boolean);
        for (const line of lines) {
          const client = line.split("|")[0];
          const label = service.replace("kTCCService", "");
          findings.push({
            severity: "info",
            title: `${label} access granted: ${client}`,
            description: `App has ${label} permission — can potentially monitor keyboard input`,
            category: "permissions",
            source: "machine-audit",
          });
        }
      }
    }
  }

  return { findings };
}

// ── 11. Chrome extensions ───────────────────────────────────────────────

function checkBrowserExtensions() {
  const home = homedir();
  const extensions = [];

  // Chrome
  const chromeExtDir = join(home, "Library/Application Support/Google/Chrome/Default/Extensions");
  const chromeExts = safeReadDir(chromeExtDir);
  for (const extId of chromeExts) {
    const extPath = join(chromeExtDir, extId);
    const versions = safeReadDir(extPath).filter((v) => !v.startsWith("."));
    if (versions.length === 0) continue;
    const manifestPath = join(extPath, versions[versions.length - 1], "manifest.json");
    const manifest = safeReadFile(manifestPath);
    try {
      const m = JSON.parse(manifest);
      extensions.push({
        browser: "Chrome",
        id: extId,
        name: m.name || extId,
        version: m.version || "?",
        permissions: m.permissions || [],
      });
    } catch { /* skip malformed */ }
  }

  // Flag extensions with dangerous permissions
  const findings = [];
  const DANGEROUS_PERMS = ["<all_urls>", "*://*/*", "webRequest", "webRequestBlocking", "nativeMessaging", "debugger", "clipboardRead"];

  for (const ext of extensions) {
    const dangerous = ext.permissions.filter((p) => DANGEROUS_PERMS.some((d) => p.includes?.(d)));
    if (dangerous.length > 0) {
      findings.push({
        severity: "info",
        title: `Chrome extension "${ext.name}" has broad permissions`,
        description: `Permissions: ${dangerous.join(", ")}`,
        category: "browser-extensions",
        source: "machine-audit",
      });
    }
  }

  return { extensions, findings };
}

// ── 12. MDM / Configuration Profiles ────────────────────────────────────

function checkProfiles() {
  const out = run("profiles status -type enrollment 2>&1");
  const enrolled = out.includes("Yes");
  const findings = [];

  if (enrolled) {
    findings.push({
      severity: "info",
      title: "Device is enrolled in MDM",
      description: "This Mac is managed by a Mobile Device Management server. Check System Settings > Profiles to review.",
      category: "machine-config",
      source: "machine-audit",
    });
  }

  return { enrolled, findings };
}

// ── 13. Suspicious processes ────────────────────────────────────────────

function checkProcesses() {
  const out = run("ps aux 2>/dev/null");
  const lines = out.split("\n").filter((l) => l && !l.startsWith("USER"));
  const findings = [];

  // Look for processes running from suspicious locations
  const SUSPICIOUS_PATHS = ["/tmp/", "/var/tmp/", "/dev/shm/", "/.hidden", "/Users/Shared/"];
  // Known-safe locations that use tmp-like paths
  const SAFE_PATH_PATTERNS = [".claude/", ".vscode/", ".cursor/", "node_modules/", "nix/store/"];
  // Match full binary name only (not substrings like "Sync", "Launch")
  const SUSPICIOUS_NAMES = [
    "ncat", "netcat", "socat", "meterpreter", "beacon",
    "cobaltstrike", "mimikatz", "lazagne", "keylogger",
    "reverse_shell", "bind_shell", "rat_server",
  ];

  for (const line of lines) {
    const parts = line.split(/\s+/);
    const processName = parts[10] || "";
    const cmd = parts.slice(10).join(" ");

    for (const path of SUSPICIOUS_PATHS) {
      if (cmd.includes(path) && !SAFE_PATH_PATTERNS.some((s) => cmd.includes(s))) {
        findings.push({
          severity: "high",
          title: `Process running from suspicious location`,
          description: `${cmd.slice(0, 120)}`,
          category: "suspicious-process",
          source: "machine-audit",
        });
        break;
      }
    }

    // Extract the actual binary name from the path
    const binaryName = basename(processName).toLowerCase();
    for (const name of SUSPICIOUS_NAMES) {
      if (binaryName === name || binaryName === `${name}.exe`) {
        findings.push({
          severity: "critical",
          title: `Suspicious process detected: ${name}`,
          description: `${cmd.slice(0, 120)}`,
          category: "suspicious-process",
          source: "machine-audit",
        });
        break;
      }
    }

    // Also check for netcat specifically — `nc` only if it's the exact process name
    if (binaryName === "nc") {
      findings.push({
        severity: "high",
        title: "Netcat (nc) process running",
        description: `${cmd.slice(0, 120)}`,
        category: "suspicious-process",
        source: "machine-audit",
      });
    }
  }

  return { count: lines.length, findings };
}

// ── 14. Recently modified executables in sensitive dirs ──────────────────

function checkRecentlyModified() {
  const findings = [];
  const dirs = ["/usr/local/bin", "/opt/homebrew/bin", "/tmp", "/var/tmp"];

  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    // Find files modified in the last 24 hours
    const out = run(`find "${dir}" -maxdepth 1 -type f -mtime -1 2>/dev/null`);
    const files = out.split("\n").filter(Boolean);

    for (const file of files) {
      if (dir.includes("tmp")) {
        // Only flag executables in tmp
        try {
          const st = statSync(file);
          if (st.mode & 0o111) { // executable bit set
            findings.push({
              severity: "medium",
              title: `Executable in temp directory: ${basename(file)}`,
              description: `${file} — recently modified executable in ${dir}`,
              category: "suspicious-files",
              source: "machine-audit",
            });
          }
        } catch { /* skip */ }
      }
    }
  }

  return { findings };
}

// ── 15. Optional: osquery ───────────────────────────────────────────────

async function checkOsquery() {
  const bin = which("osqueryi");
  if (!bin) return { available: false, results: {} };

  const queries = {
    listening_ports: "SELECT p.name, p.path, l.port, l.protocol, l.address FROM listening_ports l JOIN processes p ON l.pid = p.pid WHERE l.port != 0",
    kernel_extensions: "SELECT name, version, linked FROM kernel_extensions WHERE name NOT LIKE 'com.apple.%'",
    unsigned_apps: "SELECT path, authority FROM signature WHERE authority = '' AND path LIKE '/Applications/%'",
    ssh_keys: "SELECT * FROM user_ssh_keys",
  };

  const results = {};
  for (const [name, query] of Object.entries(queries)) {
    const out = run(`osqueryi --json "${query}" 2>/dev/null`, { timeout: 15_000 });
    try {
      results[name] = JSON.parse(out);
    } catch {
      results[name] = [];
    }
  }

  return { available: true, results };
}

// ── 16. Optional: ClamAV quick scan ─────────────────────────────────────

function checkClamAV(scanPath, opts = {}) {
  const bin = which("clamscan");
  if (!bin) return { available: false, infected: [] };

  const timeout = opts.timeout || 120_000;
  const out = run(`clamscan -r -i --no-summary "${scanPath}" 2>/dev/null`, { timeout });
  const infected = out.split("\n")
    .filter((l) => l.includes("FOUND"))
    .map((l) => {
      const [file, sig] = l.split(": ");
      return { file: file?.trim(), signature: sig?.replace(" FOUND", "").trim() };
    })
    .filter((r) => r.file);

  return { available: true, infected };
}

// ── 17. Optional: rkhunter ──────────────────────────────────────────────

// Known macOS false positives — rkhunter was built for Linux and doesn't
// understand many normal macOS behaviors. We filter these out so only
// genuinely suspicious findings surface.
const RKHUNTER_MACOS_FP = [
  // Normal macOS: Apple ships these as scripts, not binaries
  /replaced by a script.*\/usr\/bin\/(fuser|whatis|shasum|lsvfs)/i,
  // Normal macOS: launchd, not init.d
  /No system startup files found/i,
  // Normal macOS: ControlCenter AirPlay Receiver on port 5000/7000
  /port (5000|7000) is being used by.*ControlCenter/i,
  // Normal macOS: Thunderbolt bridge interfaces are always promiscuous
  /Possible promiscuous interfaces/i,
  // ifconfig dump lines (follow-on from promiscuous warning)
  /^\s*(lo0|gif0|stf0|anpi\d|en\d|bridge\d|ap\d|awdl\d|llw\d|utun\d|vmnet\d):/,
  /^\s+(options|ether|inet|nd6|media|status|Configuration|member|id |maxage|root |ipfilter|ifmaxaddr)/,
  /^\s+flags=/,
  // Normal macOS: stock hidden man page
  /Hidden file found:.*\/usr\/share\/man/i,
  // rkhunter setup messages (not actual threats)
  /rkhunter\.dat.*does not exist/i,
  /users responsibility to ensure/i,
  /propupd.*option/i,
  /files on their system are known to be genuine/i,
  /compare the current file properties/i,
  /report if any values differ/i,
  /cannot determine what has caused the change/i,
  /Checking for prerequisites\s+\[/i,
  /Checking for possible rootkit strings\s+\[/i,
  // ifconfig noise lines
  /^\s+\t/,
  // Continuation lines from the promiscuous dump
  /ifconfig.*command output/i,
  /Use the 'lsof -i'/i,
];

function isRkhunterFalsePositive(line) {
  return RKHUNTER_MACOS_FP.some((re) => re.test(line));
}

function classifyRkhunterWarning(line) {
  // SSH misconfig
  if (/SSH.*PermitRootLogin/i.test(line)) return { severity: "medium", category: "ssh-config" };
  if (/SSH.*Protocol/i.test(line)) return { severity: "low", category: "ssh-config" };
  if (/default value may be/i.test(line)) return null; // continuation line
  // Actual rootkit signatures
  if (/rootkit.*found/i.test(line) && !/not found/i.test(line)) return { severity: "critical", category: "rootkit" };
  // Suspicious files
  if (/Hidden file found/i.test(line)) return { severity: "medium", category: "hidden-files" };
  if (/suspicious.*string/i.test(line)) return { severity: "high", category: "rootkit" };
  // Suspicious ports
  if (/Network.*port.*is being used/i.test(line)) return { severity: "medium", category: "network" };
  // Modified system commands
  if (/replaced by a script/i.test(line)) return { severity: "medium", category: "system-commands" };
  // Default: medium
  return { severity: "medium", category: "rkhunter" };
}

function checkRkhunter(progress) {
  const bin = which("rkhunter");
  if (!bin) return { available: false, warnings: [], findings: [] };

  // Auto-initialize baseline if missing
  const datExists = run("ls /var/db/rkhunter/db/rkhunter.dat 2>/dev/null || ls /opt/homebrew/var/lib/rkhunter/db/rkhunter.dat 2>/dev/null || ls /usr/local/var/lib/rkhunter/db/rkhunter.dat 2>/dev/null");
  if (!datExists) {
    progress?.("Initializing rkhunter baseline (first run)...");
    run("sudo rkhunter --propupd 2>/dev/null", { timeout: 60_000 });
  }

  const out = run("sudo rkhunter --check --sk --rwo 2>/dev/null", { timeout: 120_000 });
  const rawLines = out.split("\n").filter(Boolean);

  // Filter macOS false positives
  const realWarnings = rawLines.filter((l) => !isRkhunterFalsePositive(l));

  // Deduplicate and classify
  const findings = [];
  const seen = new Set();
  for (const line of realWarnings) {
    const trimmed = line.replace(/^Warning:\s*/i, "").trim();
    if (!trimmed || trimmed.length < 10) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);

    const classification = classifyRkhunterWarning(line);
    if (!classification) continue;

    findings.push({
      severity: classification.severity,
      title: `rkhunter: ${trimmed.slice(0, 100)}`,
      description: trimmed,
      category: classification.category,
      source: "rkhunter",
    });
  }

  return {
    available: true,
    rawWarnings: rawLines.length,
    filteredWarnings: rawLines.length - realWarnings.length,
    warnings: realWarnings,
    findings,
  };
}

// ── Aggregate: Full Machine Audit ───────────────────────────────────────

/**
 * Run a full machine security audit.
 *
 * @param {object} opts - { onPhase, clamScanPath, skipOptional }
 * @returns {{ checks: object[], findings: object[], tools: object }}
 */
export async function auditMachine(opts = {}) {
  const progress = opts.onPhase || (() => {});
  const checks = [];
  const findings = [];

  // Track available optional tools
  const tools = {
    osquery: !!which("osqueryi"),
    clamav: !!which("clamscan"),
    rkhunter: !!which("rkhunter"),
    chkrootkit: !!which("chkrootkit"),
  };

  // ── Built-in checks (no installs needed) ──────────────────────────────

  progress("Checking System Integrity Protection (SIP)...");
  const sip = checkSIP();
  checks.push(sip);
  if (sip.finding) findings.push(sip.finding);

  progress("Checking Gatekeeper...");
  const gk = checkGatekeeper();
  checks.push(gk);
  if (gk.finding) findings.push(gk.finding);

  progress("Checking firewall...");
  const fw = checkFirewall();
  checks.push(fw);
  if (fw.finding) findings.push(fw.finding);

  progress("Checking FileVault disk encryption...");
  const fv = checkFileVault();
  checks.push(fv);
  if (fv.finding) findings.push(fv.finding);

  progress("Checking XProtect...");
  const xp = checkXProtect();
  checks.push(xp);

  progress("Scanning LaunchAgents & LaunchDaemons (persistence)...");
  const persistence = checkPersistence();
  checks.push({ name: "Persistence (LaunchAgents/Daemons)", count: persistence.items.length });
  findings.push(...persistence.findings);

  progress("Checking login items...");
  const loginItems = checkLoginItems();
  checks.push({ name: "Login Items", items: loginItems.items });

  progress("Checking crontab...");
  const cron = checkCrontab();
  checks.push({ name: "Crontab", entries: cron.entries.length });
  findings.push(...cron.findings);

  progress("Scanning network connections...");
  const network = checkNetworkConnections();
  checks.push({ name: "Network Connections", count: network.connections.length });
  findings.push(...network.findings);

  progress("Checking for keylogger indicators (event taps & TCC)...");
  const eventTaps = checkEventTaps();
  findings.push(...eventTaps.findings);

  progress("Auditing browser extensions...");
  const browser = checkBrowserExtensions();
  checks.push({ name: "Browser Extensions", count: browser.extensions.length });
  findings.push(...browser.findings);

  progress("Checking MDM enrollment...");
  const mdm = checkProfiles();
  findings.push(...mdm.findings);

  progress("Scanning running processes...");
  const procs = checkProcesses();
  checks.push({ name: "Running Processes", count: procs.count });
  findings.push(...procs.findings);

  progress("Checking for suspicious executables...");
  const recent = checkRecentlyModified();
  findings.push(...recent.findings);

  // ── Optional tools (if installed) ─────────────────────────────────────

  if (!opts.skipOptional) {
    if (tools.osquery) {
      progress("Running osquery security queries...");
      const osq = await checkOsquery();
      checks.push({ name: "osquery", ...osq.results });

      // Flag unsigned apps
      for (const app of osq.results.unsigned_apps || []) {
        findings.push({
          severity: "medium",
          title: `Unsigned application: ${basename(app.path)}`,
          description: app.path,
          category: "code-signing",
          source: "osquery",
        });
      }

      // Flag non-Apple kernel extensions
      for (const kext of osq.results.kernel_extensions || []) {
        findings.push({
          severity: "info",
          title: `Third-party kernel extension: ${kext.name}`,
          description: `Version ${kext.version}`,
          category: "kernel",
          source: "osquery",
        });
      }
    }

    if (tools.clamav) {
      const scanPath = opts.clamScanPath || homedir();
      progress(`Running ClamAV scan on ${scanPath} (this may take a while)...`);
      const clam = checkClamAV(scanPath, { timeout: 300_000 });
      checks.push({ name: "ClamAV", scanned: scanPath, infected: clam.infected.length });

      for (const hit of clam.infected) {
        findings.push({
          severity: "critical",
          title: `Malware detected: ${hit.signature}`,
          description: hit.file,
          category: "malware",
          source: "clamav",
        });
      }
    }

    if (tools.rkhunter) {
      progress("Running rkhunter rootkit scan...");
      const rk = checkRkhunter(progress);
      checks.push({
        name: "rkhunter",
        realWarnings: rk.findings.length,
        filteredFalsePositives: rk.filteredWarnings || 0,
      });
      findings.push(...rk.findings);
    }
  }

  // ── Missing tools advisory ────────────────────────────────────────────
  const missing = [];
  if (!tools.osquery)   missing.push("osquery (brew install --cask osquery)");
  if (!tools.clamav)    missing.push("ClamAV (brew install clamav)");
  if (!tools.rkhunter)  missing.push("rkhunter (brew install rkhunter)");

  return {
    checks,
    findings,
    tools,
    missing,
    persistence: persistence.items,
    network: network.connections,
    browserExtensions: browser.extensions,
    loginItems: loginItems.items,
  };
}
