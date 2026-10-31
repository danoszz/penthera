// Every user-facing sentence in one place, so the voice can be read and
// proofed as a whole. Rules: sentence case, "::" as connective, no
// exclamation marks, verbs first on buttons, empty states name the action
// that fills them, errors give the cause then the fix.

export const TAGLINE = "Your open-source cyber security agent"; // README headline

export const START = {
  title: "Welcome",
  intro: "No reports yet. Start with a scan of something you own :: your localhost, a preview URL, or this repo. Results land in the reports folder and this view fills in.",
  introSimple: "Nothing checked yet. Set up your project and run a first check: it takes a minute or two, and everything stays on this computer.",
  gate: "Only scan apps you own or have written permission to test.",
  steps: [
    { kind: "scan", title: "Scan your app", body: "TLS, headers, cookies, CORS, auth, exposed APIs and leaked secrets." },
    { kind: "deps", title: "Check your dependencies", body: "What every npm and Python package can do: install scripts, shell, network, obfuscated code." },
    { kind: "agents", title: "Audit your AI tooling", body: "Skills, MCP servers, hooks and rule files: hidden instructions, unpinned servers, wide permissions." },
  ],
  demo: "To look around first, stop this server and run",
};

export const KINDS = [
  { kind: "scan", label: "Scan", title: "Scan a site or folder", button: "Scan" },
  { kind: "deps", label: "Deps", title: "Check dependencies", button: "Check dependencies" },
  { kind: "agents", label: "AI tooling", title: "Audit AI tooling", button: "Audit AI tooling" },
  { kind: "loop", label: "Fix loop", title: "Run the fix loop", button: "Run the fix loop" },
];

export const NOTES = {
  scan: "Contacts only the URL's host while offline is on. A folder-only scan contacts nothing.",
  deps: "Reads lockfiles and installed packages. No network.",
  agents: "Read-only. No network.",
  loop: "Offline, on a local branch. Every diff waits for you. Nothing is pushed.",
};

export const EMPTY = {
  projects: "No projects yet. Run a scan to add one.",
  runs: "No runs yet.",
  findings: "No open findings in the latest scan.",
  filtered: "Nothing matches the filter. Press Esc to clear it.",
  deps: "No dependency report yet. Choose Scan ▸ Check dependencies in the menu bar.",
  ai: "No AI tooling report yet. Choose Scan ▸ Audit AI tooling in the menu bar.",
  inspector: "Pick a finding to read it here in plain words, with its evidence and the fix.",
  history: "No runs for this project yet.",
  evidence: "No bundles yet. Create one from the latest scan.",
  memory: "No memory yet. The fix loop and scans with --memory write it.",
  changes: "No fixes applied yet. Run the fix loop to apply one.",
};

/** How to know a fix worked, under every finding: the same rule decides. */
export const VERIFY = "run the check again. The same rule that found it decides: the fix worked when it is gone from this list.";

/** A run is "check and fix" mode, as on penthera.org: Back at its top left. */
export const FIX_MODE = { label: "Check and fix", back: "Back", backLabel: "Back to the project" };

export const ERR = {
  session: "The session ended. Restart penthera ui and open the new one-time link it prints.",
};

export const KEYS = [
  ["n", "new scan"], ["/", "search findings"], ["j k", "next / previous finding"], ["1-5", "switch tab (Advanced)"],
  ["[ ]", "toggle the side windows"], ["y n q", "apply, skip, stop a diff"], ["Esc", "close the detail or a menu"],
];

export const ABOUT = {
  line: "Your open-source cyber security agent: the security review you never had time for. This window reads your reports and runs scans on this machine.",
  license: "MIT",
  type: "Departure Mono by Helena Zhang (OFL)",
  local: "Bound to 127.0.0.1. Nothing on this page loads from another host.",
};

// ── Simple mode: the same data, in words a non-programmer uses ──────────

/** Severity as a word anyone reads the same way. */
export const SEV_WORD = { critical: "Critical", high: "Serious", medium: "Worth fixing", low: "Minor", info: "Note" };

export const SIMPLE_KINDS = [
  { kind: "scan", title: "Check my app", body: "Looks at your app and code for security problems. Takes a minute or two.", button: "Check my app" },
  { kind: "loop", title: "Fix problems for me", body: "Proposes a fix for each problem it knows how to fix. You approve every change; nothing is published.", button: "Start fixing" },
];

export const SETUP = {
  steps: 3,
  welcome: {
    title: "Welcome to Penthera",
    body: [
      "Penthera checks the apps you build for security problems, explains each one in plain words and can fix many of them for you.",
      "Everything runs on this computer. Nothing is sent anywhere, and no change is made without your OK.",
    ],
    gate: "Only check apps you own or have written permission to test.",
  },
  mode: {
    title: "How much do you want to see?",
    simple: { title: "Simple", body: "Is my app secure, and what do I do about it? Plain words, one list, one button at a time." },
    advanced: { title: "Advanced", body: "Everything: dependencies, AI tooling, run history, evidence for auditors, confidence and the raw diffs." },
    note: "You can switch any time in the Penthera menu.",
  },
  project: {
    title: "Your project",
    folder: "The folder with your app's code",
    folderNote: "Penthera reads only this folder. To add another, start it with penthera ui --project <folder>.",
    url: "Where your app runs (optional)",
    urlNote: "For example the address you open while building it. Leave it empty to check only the code.",
    check: "Check my app now",
    skip: "Skip, look around first",
  },
};

/** One sentence that answers "can I ship?" for a project or all of them. */
export function verdict({ counts, open, top, scanned, when }) {
  if (!scanned) return { text: "Not checked yet.", sub: "Run a first check to see where you stand." };
  const c = counts?.critical || 0;
  const hi = counts?.high || 0;
  const from = `From the check ${when}.`;
  if (c) return { level: "stop", text: `Not ready to ship: ${c === 1 ? "1 critical problem" : `${c} critical problems`} to fix first.`, sub: from, top };
  if (hi) return { level: "fix", text: `Fix ${hi === 1 ? "1 serious problem" : `${hi} serious problems`} before you ship.`, sub: from, top };
  if (open) return { level: "ok", text: `Nothing blocks a launch. ${open === 1 ? "1 smaller thing is" : `${open} smaller things are`} worth fixing.`, sub: from, top };
  return { level: "clear", text: "Nothing open. The last check found no problems.", sub: from };
}

// ── AI mode (docs/ai-mode.md) ────────────────────────────────────────────
// The consent lines say exactly what the terminal says (lib/ai/consent.js);
// a test compares them. AI_TEXT_VERSION must match CONSENT_TEXT_VERSION, and
// the server refuses a run whose page showed another version.

export const AI_TEXT_VERSION = 1;
export const AI_CLOUD_HOST = "ollama.com";

export const AI = {
  label: "AI mode",
  note: "A model on this computer looks for what rules can't see. Off by default.",
  title: "AI mode",
  intro: "AI mode: a model reads your code to look for problems the rules can't see.",
  flowAlt: (cloud) => cloud
    ? "Your code goes from Penthera to Ollama on this computer, and Ollama sends it to ollama.com."
    : "Your code goes from Penthera to Ollama on this computer. It does not go to the internet.",
  noModels: "Ollama has no models yet. Pull one in a terminal, for example: ollama pull qwen2.5-coder:7b",
  cloudConfirm: `This model runs on ${AI_CLOUD_HOST}, not on this computer. Type ${AI_CLOUD_HOST} to send your code there:`,
  notNow: "Not now",
  use: (model, cloud) => `Use ${model} ${cloud ? `on ${AI_CLOUD_HOST}` : "on this computer"}`,
  chosen: (model, cloud) => `${model} · ${cloud ? `on ${AI_CLOUD_HOST}: your code is sent there` : "on this computer: nothing sent off it"}`,
  change: "Change…",
  tag: (cloud) => (cloud ? `AI · ${AI_CLOUD_HOST}` : "AI · local"),
  tagDetail: (model, cloud) => cloud ? `${model} ran on ${AI_CLOUD_HOST}; your code was sent there through your local Ollama.` : `${model} ran on this computer; nothing was sent off it.`,
  unverified: (n) => `Model-proposed, not verified (${n})`,
  unverifiedNote: "No Penthera rule confirmed these. They are a model's claims: read the code before acting on them. They are not counted anywhere else and never fail CI.",
  done: (s) => `AI mode read ${s.read} of ${s.of} code parts${s.partial ? ` (stopped early: ${s.stopReason})` : ""}. ${s.confirmed} confirmed by a Penthera rule, ${s.unverified} not verified.`,
  settings: "AI mode asks on every run; nothing is remembered as permission. Each answer is logged on this computer only.",
  settingsEmpty: "No AI runs yet.",
};

/** The Model / Reads / Sends / Decides lines of the consent screen, as [label, text] pairs. */
export function aiLines({ route, model, project, maxUnits }) {
  const cloud = route === "ollama-cloud";
  return [
    ["Model", cloud ? `${model}, through your local Ollama, run on ${AI_CLOUD_HOST}` : `${model}, through Ollama on this computer (127.0.0.1)`],
    ["Reads", `up to ${maxUnits} parts of ${project}, with secrets masked`],
    ["Sends", cloud ? `those parts to ${AI_CLOUD_HOST} (you confirm the host next)` : "nothing off this computer"],
    ["Decides", "nothing. Penthera checks every model finding with its own rules. Unchecked ones are labelled and never fail CI."],
  ];
}
