// Every user-facing sentence in one place, so the voice can be read and
// proofed as a whole. Rules (voice.md): sentence case, "::" as connective,
// no exclamation marks, verbs first on buttons, empty states name the
// action that fills them, errors give the cause then the fix.

export const TAGLINE = "Open-source security for the apps and AI systems you ship"; // README headline; display lines take no period

export const SCREENS = {
  overview: { title: "Overview", lede: "Where each project stands, from the reports and memory on this machine." },
  findings: { title: "Findings", lede: "Every open finding in the latest report per project. Pick one to see what it means and how to fix it." },
  run: { title: "Run", lede: "Scan, check dependencies, audit AI tooling, or let the agent fix things. Every diff waits for you. Nothing is pushed." },
  history: { title: "History", lede: "Compare two scans of one project :: what is new, what got fixed, what is still open." },
  deps: { title: "Dependencies", lede: "What your npm and Python packages can do, what changed, and what the install firewall let in." },
  ai: { title: "AI tooling", lede: "Skills, MCP servers, hooks and rule files :: the grade, hidden content, and drift against penthera.lock." },
  evidence: { title: "Evidence", lede: "Hashed, signable bundles for an auditor. Create one from the latest scan, verify any of them in one click." },
  settings: { title: "Settings", lede: "For this session. Nothing here is written to disk except your theme choice." },
};

export const START = {
  welcome: "Welcome",
  intro: "No reports yet. Start with a scan of something you own :: your localhost, a preview URL, or this repo. Each step writes a report into the reports folder, and this screen fills in.",
  gate: "Only scan apps you own or have written permission to test.",
  steps: [
    { title: "Scan your app", body: "TLS, headers, cookies, CORS, auth, exposed APIs and leaked secrets. About a minute.", kind: "scan", action: "Scan app" },
    { title: "Check your dependencies", body: "What every npm package in the lockfile can do: install scripts, shell, network, obfuscated code.", kind: "deps", action: "Check dependencies" },
    { title: "Audit your AI tooling", body: "Skills, MCP servers, hooks and rule files: hidden instructions, unpinned servers, wide permissions.", kind: "agents", action: "Audit AI tooling" },
  ],
  demo: "Want to look around first? Stop this server and run",
};

export const NEXT = {
  heading: "What next?",
  overview: [
    { label: "Read the most serious finding", why: "what it means, how sure we are, the fix", go: ["findings"] },
    { label: "Fix what can be fixed", why: "the agent proposes diffs, you approve each one", go: ["run", { kind: "loop" }] },
    { label: "Compare with the last scan", why: "new, fixed, still open", go: ["history"] },
    { label: "Create evidence for an auditor", why: "a hashed bundle plus the auditor report", go: ["evidence"] },
  ],
  scan: [
    { label: "Read the findings", why: "start with the most serious one", go: ["findings"] },
    { label: "Fix them with the agent", why: "you approve every diff", go: ["run", { kind: "loop" }] },
    { label: "Compare with the previous scan", go: ["history"] },
  ],
  loop: [
    { label: "Compare before and after", why: "what the loop fixed", go: ["history"] },
    { label: "Create evidence for an auditor", go: ["evidence"] },
    { label: "Back to the overview", go: ["overview"] },
  ],
  deps: [
    { label: "See the capability diff", go: ["deps"] },
    { label: "Back to the overview", go: ["overview"] },
  ],
  agents: [
    { label: "See the grade and hidden content", go: ["ai"] },
    { label: "Back to the overview", go: ["overview"] },
  ],
};

export const RUN_KINDS = [
  { kind: "scan", label: "Scan app", needs: "url-or-folder", button: "Run scan" },
  { kind: "deps", label: "Check dependencies", needs: "folder", button: "Check dependencies" },
  { kind: "agents", label: "Audit AI tooling", needs: "folder", button: "Audit AI tooling" },
  { kind: "loop", label: "Fix loop", needs: "folder", button: "Run as agent" },
];

export const EMPTY = {
  findingsNone: "No findings in the reports folder yet. Run a scan from Run, or write one with penthera <url> -o reports/scan.json.",
  findingsFiltered: (which) => `Nothing matches :: ${which} hide${which.includes(",") ? "" : "s"} the rest. Clear them to see every finding.`,
  history: "No project has two scans yet. Scan the same target again and the comparison appears here.",
  deps: "No dependency report yet. Run Check dependencies, or penthera deps -o reports/deps.json.",
  ai: "No AI tooling report yet. Run Audit AI tooling, or penthera agents . -o reports/agents.json.",
  evidence: "No bundles yet. Create one from the latest scan of a project above.",
  memory: "No memory yet. The agent loop and scans with --memory write it to ~/.penthera/memory.",
  pastRuns: "No loop runs in the reports folder yet.",
};

export const ERR = {
  session: "The session ended. Restart penthera ui and open the new one-time link it prints.",
};
