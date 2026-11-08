/**
 * Recipe: move a hardcoded secret out of JS/TS source into an environment
 * variable and list that variable in .env.example. Guidance: remediation rule
 * "secrets", references/remediation.md#hardcoded-secrets.
 *
 * The secret is already burned: a diff can take it out of the code, but only
 * the owner can rotate it, so "rotate this secret" is always an owner action.
 * The plan's diff contains the old value on its "-" line; plans carry it in
 * `redactions` so anything that prints or stores a plan can mask it.
 */
import { findSecretsInText } from "../../whitebox/secrets.js";
import { createGit } from "../../../src/agent/git.js";
import { detectFramework, findEntryFile, hasDep, readText, walkCodeFiles, envExampleChange, toDiff, toEnvName } from "../util.js";

const JS_FILE = /\.(js|ts|mjs|cjs|jsx|tsx)$/;

// Env var names for provider keys that are not inside a named assignment.
const PROVIDER_ENV = [
  [/Anthropic/i, "ANTHROPIC_API_KEY"],
  [/OpenRouter/i, "OPENROUTER_API_KEY"],
  [/OpenAI/i, "OPENAI_API_KEY"],
  [/Google/i, "GOOGLE_API_KEY"],
  [/Groq/i, "GROQ_API_KEY"],
  [/Hugging Face/i, "HF_TOKEN"],
  [/Replicate/i, "REPLICATE_API_TOKEN"],
  [/xAI/i, "XAI_API_KEY"],
  [/Perplexity/i, "PERPLEXITY_API_KEY"],
  [/LangSmith/i, "LANGSMITH_API_KEY"],
  [/Pinecone/i, "PINECONE_API_KEY"],
  [/Stripe/i, "STRIPE_SECRET_KEY"],
  [/AWS/i, "AWS_ACCESS_KEY_ID"],
  [/GitHub/i, "GITHUB_TOKEN"],
];

/**
 * Locate the string literal holding a secret on one line.
 * Returns { start, end, value, envName } (offsets within the line) or null.
 */
function locate(line, hit) {
  const at = line.indexOf(hit.match);
  if (at < 0) return null;
  // Assignment rules match `key = "value"`; provider rules match the raw key.
  const assigned = hit.match.match(/^([\w$-]+)\s*[:=]\s*(['"])([^'"]*)\2$/);
  const value = assigned ? assigned[3] : hit.match;
  const valueAt = assigned ? at + hit.match.lastIndexOf(value) : at;
  const quote = line[valueAt - 1];
  if (!["'", '"', "`"].includes(quote) || line[valueAt + value.length] !== quote) return null; // not a whole literal
  if (quote === "`" && value.includes("${")) return null;
  // Name: the key the literal is assigned to, else the provider's usual name.
  const before = line.slice(0, valueAt - 1);
  const key = before.match(/(?<![\w$])([A-Za-z_$][\w$]*)['"]?\s*[:=]\s*$/)?.[1];
  const envName = (key && !/^(?:key|value|token|secret)$/i.test(key) && toEnvName(key))
    || PROVIDER_ENV.find(([re]) => re.test(hit.name))?.[1]
    || (key && toEnvName(key))
    || "SECRET_VALUE";
  return { start: valueAt - 1, end: valueAt + value.length + 1, value, envName };
}

function findSecret(source, title) {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const hit of findSecretsInText(lines[i])) {
      if (title && `${hit.name} in source` !== title) continue;
      const loc = locate(lines[i], hit);
      if (loc) return { line: i, ...loc, name: hit.name };
    }
  }
  return null;
}

const LISTEN = /^([ \t]*)(?:await\s+)?(?:[\w$.]+\.listen|serve)\(/m; // serve(): Hono on Node

/**
 * May a line go above this one and still always run before it? Only when the
 * line before clearly ends a statement or opens a block. Anything else could be
 * a guard with no braces, and a check placed under it would unguard listen, so
 * the recipe leaves the check out rather than guess.
 */
function safeToInsertAbove(source, listen) {
  const lines = source.slice(0, listen.index).split("\n");
  let i = lines.length - 1;
  while (i >= 0 && (!lines[i].trim() || /^\s*\/\//.test(lines[i]))) i--;
  if (i < 0) return true;
  // A comment on that line says nothing about the code: `if (main) // {` opens no block.
  // A line comment, then a block comment that closes the line, cut off in single scans.
  const slash = lines[i].indexOf("//");
  let code = slash >= 0 ? lines[i].slice(0, slash) : lines[i];
  const trimmed = code.trimEnd();
  const open = trimmed.endsWith("*/") ? trimmed.indexOf("/*") : -1;
  if (open >= 0 && open <= trimmed.length - 4) code = code.slice(0, open);
  if (/\{\s*$/.test(code)) return true;
  return /[;}]\s*$/.test(code) && lines[i].match(/^\s*/)[0].length >= listen[1].length;
}

/**
 * A clear error at start-up instead of a 500 at the first request. It goes just
 * before the server listens, in the entry file: a check where the secret was
 * would run before an entry file's dotenv.config(), since imports load first.
 * Next.js has no such line, and importing a route at build time must not throw.
 * @returns {{ file: string, source: string, after: string }|null}
 */
function startupCheck(repoPath, envName, edited) {
  if (!["express", "fastify", "hono"].includes(detectFramework(repoPath))) return null;
  const entry = findEntryFile(repoPath, LISTEN);
  if (!entry) return null;
  const source = entry.file === edited.file ? edited.after : entry.source;
  const m = source.match(LISTEN);
  if (!m || !safeToInsertAbove(source, m)) return null;
  const line = `${m[1]}if (!process.env.${envName}) throw new Error("Set ${envName} before starting the server.");\n`;
  return { file: entry.file, source, after: source.slice(0, m.index) + line + source.slice(m.index) };
}

/** Does git ignore this path? `.env*` in Next's default .gitignore covers .env.example, and the loop cannot commit an ignored file. */
function gitIgnores(repoPath, file) {
  try {
    return createGit(repoPath).tryRun("check-ignore", "-q", "--", file) !== null;
  } catch {
    return false;
  }
}

export default {
  id: "secret-to-env",
  title: "Move a hardcoded secret to an environment variable",
  // Only a secret in a JS or TS file: one in a .env, JSON or YAML file has no
  // code to move it out of, so the plan would give nothing.
  matches(finding) {
    return finding.category === "secrets" && JS_FILE.test(String(finding.url || finding.file || ""));
  },
  detect() {
    return "node";
  },
  plan(repoPath, finding) {
    const file = finding.url;
    if (!file || !JS_FILE.test(file) || !walkCodeFiles(repoPath).includes(file)) return null;
    const source = readText(repoPath, file);
    if (!source) return null;
    const hit = findSecret(source, finding.title);
    if (!hit) return null;

    const lines = source.split("\n");
    const l = lines[hit.line];
    // TypeScript types process.env values as string | undefined; the owner action says to set it.
    const ref = `process.env.${hit.envName}${/\.tsx?$/.test(file) ? " as string" : ""}`;
    lines[hit.line] = l.slice(0, hit.start) + ref + l.slice(hit.end);
    const edited = { file, after: lines.join("\n") };
    const check = startupCheck(repoPath, hit.envName, edited);
    const exampleIgnored = gitIgnores(repoPath, ".env.example");
    const change = toDiff([
      { file, before: source, after: check?.file === file ? check.after : edited.after },
      check && check.file !== file ? { file: check.file, before: check.source, after: check.after } : null,
      exampleIgnored ? null : envExampleChange(repoPath, hit.envName, "", `${hit.name}: set the real value in .env or your secret manager, never in code`),
    ]);
    if (!change) return null;

    const ownerActions = [
      `Rotate this secret at the provider now and treat the old value as compromised. A recipe can never rotate it for you.`,
      `Set ${hit.envName} in your local .env and in every deployment environment before deploying this change.`,
      "If the old value was ever committed or pushed, purge it from git history (git filter-repo or BFG) after rotating.",
    ];
    if (/^(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)/.test(hit.envName) || /^\s*['"]use client['"]/.test(source)) {
      ownerActions.push("This code runs in the browser, so an env var is still shipped to every visitor. Move the call that needs the secret to a server route.");
    }
    if (exampleIgnored) ownerActions.push(`Your .gitignore covers .env.example, so it was left alone. Add \`!.env.example\` to .gitignore if you want ${hit.envName} listed there.`);
    if (["express", "fastify", "hono"].includes(detectFramework(repoPath)) && !hasDep(repoPath, "dotenv") && !/--env-file/.test(readText(repoPath, "package.json") || "")) {
      ownerActions.push(`Nothing in this app loads .env. Start it with \`node --env-file=.env\`, or set ${hit.envName} in your shell.`);
    }
    const ignore = readText(repoPath, ".gitignore");
    if (!ignore || !/^\.env\b/m.test(ignore)) ownerActions.push("Add .env to .gitignore so the real value is never committed.");
    return { ...change, ownerActions, confidence: "high", redactions: [hit.value] };
  },
};
