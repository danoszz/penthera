/**
 * AI Bill of Materials (CycloneDX 1.6 ML-BOM) generator.
 *
 * Inventories the AI a repo uses, offline and read-only:
 * - AI SDK dependencies (openai, @anthropic-ai/sdk, @google/genai, ai,
 *   langchain, llamaindex, ollama, transformers, ...) as `library` components;
 * - model identifiers found as string literals in code and config
 *   (claude-*, gpt-*, gemini-*, llama*, Hugging Face repo ids, ...) as
 *   `machine-learning-model` components with a `modelCard` stub and
 *   file:line evidence;
 * - MCP servers (from lib/agents/discover.js) as `services`;
 * - Agent Skills and prompt files as `data` components with SHA-256 hashes.
 *
 * Spec: CycloneDX 1.6, which added `machine-learning-model` and `data`
 * component types and `modelCard` (ML-BOM), and models services with
 * endpoints and trust boundaries.
 *   https://cyclonedx.org/docs/1.6/json/
 *   https://cyclonedx.org/capabilities/mlbom/
 *   https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json
 * The schema is vendored in tests/fixtures/cyclonedx/ and every AI-BOM is
 * validated against it in tests/aibom.test.js.
 *
 * A model string in code says a model is referenced, not that it is used in
 * production; the evidence locations let a reviewer check.
 */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { relative, sep, basename, extname } from "node:path";
import { collectDependencies, purl } from "./sbom.js";
import { discoverAgentConfig, walk, readText, resolvesInside } from "../agents/discover.js";

// ── AI SDKs ────────────────────────────────────────────────────────────────

// [name or prefix*, provider]
const NPM_AI = [
  ["openai", "OpenAI"], ["@openai/agents", "OpenAI"], ["@azure/openai", "Microsoft"],
  ["@anthropic-ai/sdk", "Anthropic"], ["@anthropic-ai/claude-agent-sdk", "Anthropic"],
  ["@anthropic-ai/bedrock-sdk", "Anthropic"], ["@anthropic-ai/vertex-sdk", "Anthropic"],
  ["@google/genai", "Google"], ["@google/generative-ai", "Google"], ["@google-cloud/vertexai", "Google"],
  ["ai", "Vercel AI SDK"], ["@ai-sdk/*", "Vercel AI SDK"],
  ["langchain", "LangChain"], ["@langchain/*", "LangChain"],
  ["llamaindex", "LlamaIndex"], ["@llamaindex/*", "LlamaIndex"],
  ["ollama", "Ollama"],
  ["@huggingface/transformers", "Hugging Face"], ["@xenova/transformers", "Hugging Face"], ["@huggingface/inference", "Hugging Face"],
  ["@mistralai/mistralai", "Mistral AI"], ["cohere-ai", "Cohere"], ["groq-sdk", "Groq"],
  ["replicate", "Replicate"], ["together-ai", "Together AI"],
  ["@aws-sdk/client-bedrock-runtime", "AWS Bedrock"], ["@modelcontextprotocol/sdk", "Model Context Protocol"],
];
const PYPI_AI = [
  ["openai", "OpenAI"], ["openai-agents", "OpenAI"], ["anthropic", "Anthropic"], ["claude-agent-sdk", "Anthropic"],
  ["google-genai", "Google"], ["google-generativeai", "Google"],
  ["langchain", "LangChain"], ["langchain-*", "LangChain"], ["langgraph", "LangChain"],
  ["llama-index", "LlamaIndex"], ["llama-index-*", "LlamaIndex"], ["ollama", "Ollama"],
  ["transformers", "Hugging Face"], ["sentence-transformers", "Hugging Face"], ["huggingface-hub", "Hugging Face"],
  ["torch", "PyTorch"], ["tensorflow", "TensorFlow"], ["keras", "Keras"],
  ["mistralai", "Mistral AI"], ["cohere", "Cohere"], ["groq", "Groq"], ["litellm", "LiteLLM"], ["vllm", "vLLM"],
  ["replicate", "Replicate"], ["mcp", "Model Context Protocol"], ["crewai", "CrewAI"],
  ["autogen-agentchat", "AutoGen"], ["pyautogen", "AutoGen"], ["dspy", "DSPy"], ["dspy-ai", "DSPy"],
  ["instructor", "Instructor"], ["haystack-ai", "Haystack"],
];

function matchSdk(table, name) {
  for (const [pat, provider] of table) {
    if (pat.endsWith("*") ? name.startsWith(pat.slice(0, -1)) : name === pat) return provider;
  }
  return null;
}
const normPy = (n) => n.toLowerCase().replace(/[_.]+/g, "-");

/** pyproject.toml dependency names (PEP 621 list and Poetry table), best effort. */
function pyprojectDeps(text) {
  const out = [];
  for (const m of text.matchAll(/^\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*([<>=!~^][^"';]*)?["']\s*,?/gm)) {
    out.push({ name: m[1], version: (m[2] || "").replace(/^[=<>!~^\s]+/, "").split(",")[0].trim() || "unknown" });
  }
  const poetry = text.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetry) {
    for (const m of poetry[1].matchAll(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["']([^"']*)["']/gm)) {
      if (m[1] !== "python") out.push({ name: m[1], version: m[2].replace(/^[=<>!~^\s]+/, "") || "unknown" });
    }
  }
  return out;
}

// ── Model identifiers ─────────────────────────────────────────────────────

// Each pattern must match a whole string literal. distribution: hosted API vs open weights.
const MODEL_PATTERNS = [
  { provider: "Anthropic", distribution: "hosted-api", re: /^(?:(?:us|eu|apac|global)\.)?(?:anthropic\.)?claude-(?:opus|sonnet|haiku|instant|fable|\d)[a-z0-9.\-@:]*$/i },
  { provider: "OpenAI", distribution: "open-weights", re: /^(?:openai\/)?gpt-oss-[a-z0-9.\-]+$/i },
  { provider: "OpenAI", distribution: "hosted-api", re: /^(?:gpt-(?:\d|4o)[a-z0-9.\-]*|o[134](?:-mini|-pro|-preview)?(?:-\d{4}-\d{2}-\d{2})?|chatgpt-4o-latest|text-embedding-(?:3-small|3-large|ada-002)|dall-e-[23]|whisper-1|tts-1(?:-hd)?|codex-mini[a-z0-9.\-]*)$/i },
  { provider: "Google", distribution: "hosted-api", re: /^(?:models\/)?gemini-(?:\d|pro|ultra|flash|exp)[a-z0-9.\-]*$/i },
  { provider: "Google", distribution: "open-weights", re: /^gemma-?\d[a-z0-9.\-:]*$/i },
  { provider: "Meta", distribution: "open-weights", re: /^(?:meta\.)?llama-?\d[a-z0-9.\-:]*$/i },
  { provider: "Mistral AI", distribution: null, re: /^(?:mistral-(?:large|medium|small|tiny|embed|saba|nemo)[a-z0-9.\-]*|open-mi[sx]tral-[a-z0-9.\-]+|mixtral[a-z0-9.\-:]*|codestral[a-z0-9.\-:]*|ministral-[a-z0-9.\-]+|pixtral-[a-z0-9.\-]+)$/i },
  { provider: "DeepSeek", distribution: null, re: /^deepseek-(?:chat|coder|reasoner|r1|v\d)[a-z0-9.\-:]*$/i },
  { provider: "Alibaba (Qwen)", distribution: "open-weights", re: /^qwen\d[a-z0-9.\-:]*$/i },
  { provider: "Microsoft", distribution: "open-weights", re: /^phi-?\d[a-z0-9.\-:]*$/i },
  { provider: "Cohere", distribution: "hosted-api", re: /^(?:command-(?:r|a|light|nightly)[a-z0-9.\-]*|embed-(?:english|multilingual)-[a-z0-9.\-]+|rerank-[a-z0-9.\-]+)$/i },
  { provider: "xAI", distribution: "hosted-api", re: /^grok-\d[a-z0-9.\-]*$/i },
];

const PROVIDER_DOCS = {
  Anthropic: "https://docs.anthropic.com/en/docs/about-claude/models",
  OpenAI: "https://platform.openai.com/docs/models",
  Google: "https://ai.google.dev/gemini-api/docs/models",
};

// Hugging Face orgs common enough that `org/name` is almost surely a model id.
const HF_ORGS = new Set([
  "meta-llama", "mistralai", "google", "microsoft", "qwen", "deepseek-ai", "sentence-transformers", "baai",
  "openai", "openai-community", "tiiuae", "bigscience", "eleutherai", "stabilityai", "facebook", "facebookai",
  "intfloat", "nomic-ai", "huggingfaceh4", "huggingfacetb", "xenova", "onnx-community", "thenlper", "jinaai",
  "mixedbread-ai", "cross-encoder", "google-bert", "distilbert", "allenai", "salesforce", "nvidia", "ibm-granite",
  "cohereforai", "unsloth", "thebloke", "lmsys", "nousresearch", "black-forest-labs", "runwayml", "compvis",
  "snowflake", "alibaba-nlp", "answerdotai", "cardiffnlp", "deepset", "bigcode", "codellama", "hf-internal-testing",
]);
const HF_ID = /^([A-Za-z0-9][\w.-]{0,95})\/([A-Za-z0-9][\w.-]{0,95})$/;
const HF_CONTEXT = /from_pretrained|pipeline\s*\(|SentenceTransformer|hf_hub_download|snapshot_download|HfInference|InferenceClient|huggingface|AutoModel|AutoTokenizer|model_id|model_name|repo_id/i;
const FILEISH = /\.(?:m?[jt]sx?|cjs|json|ya?ml|toml|py|md|txt|html?|css|png|jpe?g|svg|lock|sh|go|rs)$/i;

function classifyModel(literal, line) {
  for (const p of MODEL_PATTERNS) {
    if (p.re.test(literal)) return { name: literal, provider: p.provider, distribution: p.distribution };
  }
  const hf = literal.match(HF_ID);
  if (hf && !FILEISH.test(literal) && /[a-z]/i.test(hf[2])) {
    if (HF_ORGS.has(hf[1].toLowerCase()) || HF_CONTEXT.test(line)) {
      return { name: literal, provider: hf[1], distribution: "open-weights", huggingFace: true };
    }
  }
  return null;
}

const CODE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".py", ".go", ".rb", ".java", ".kt", ".rs", ".php", ".cs", ".swift", ".json", ".jsonc", ".yaml", ".yml", ".toml"]);
const SKIP_FILES = /(?:^|[/\\])(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|[^/\\]*\.cdx\.json|[^/\\]*\.min\.js|[^/\\]*\.map)$/i;
const MAX_SCAN_BYTES = 1024 * 1024;
const MAX_OCCURRENCES = 20;
const LITERAL = /(["'`])((?:(?!\1)[^\\\n]|\\.){2,200})\1/g;
const CONFIG_VALUE = /^\s*["']?[\w.-]*model[\w.-]*["']?\s*[:=]\s*([A-Za-z0-9][\w.:/@-]*)\s*(?:#.*)?$/i;

function findModels(root, files) {
  const models = new Map();
  for (const file of files) {
    const rel = relative(root, file).split(sep).join("/");
    if (!CODE_EXT.has(extname(file).toLowerCase()) || SKIP_FILES.test(rel)) continue;
    const text = readText(file);
    if (typeof text !== "string" || text.length > MAX_SCAN_BYTES) continue;
    const lines = text.split(/\r?\n/);
    const isConfig = /\.(?:ya?ml|toml)$/i.test(file);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const literals = [];
      for (const m of line.matchAll(LITERAL)) if (!m[2].includes("${")) literals.push(m[2]);
      if (isConfig) { const m = line.match(CONFIG_VALUE); if (m) literals.push(m[1]); }
      for (const lit of literals) {
        const hit = classifyModel(lit.trim(), line);
        if (!hit) continue;
        const key = hit.name;
        if (!models.has(key)) models.set(key, { ...hit, occurrences: [] });
        const occ = models.get(key).occurrences;
        if (occ.length < MAX_OCCURRENCES && !occ.some((o) => o.location === rel && o.line === i + 1)) {
          occ.push({ location: rel, line: i + 1 });
        }
      }
    }
  }
  return [...models.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// ── Prompt files ──────────────────────────────────────────────────────────

const PROMPT_FILE = /\.(?:prompt|prompty)$|\.prompt\.(?:md|ya?ml|json|txt)$/i;
const PROMPT_DIR_EXT = /\.(?:md|txt|ya?ml|json|j2|jinja2?|hbs|mustache|tmpl|tpl|prompt)$/i;

function isPromptFile(rel) {
  if (PROMPT_FILE.test(rel)) return true;
  const parts = rel.split("/");
  return parts.slice(0, -1).some((p) => p.toLowerCase() === "prompts") && PROMPT_DIR_EXT.test(rel);
}

/** Only a regular file inside the repo: a link must not reach /dev/zero or a file elsewhere. */
export function sha256File(path, root) {
  try {
    if (!resolvesInside(path, root) || !statSync(path).isFile()) return null;
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch {
    return null;
  }
}

// ── MCP servers ───────────────────────────────────────────────────────────

const RUNNERS = new Set(["npx", "bunx", "uvx", "pipx", "dlx"]);

function mcpPackage(def) {
  const cmd = basename(String(def.command || ""));
  const args = Array.isArray(def.args) ? def.args.map(String) : [];
  let rest = args;
  if (cmd === "pnpm" || cmd === "yarn") rest = args[0] === "dlx" ? args.slice(1) : [];
  else if (!RUNNERS.has(cmd)) return null;
  const pkg = rest.find((a) => !a.startsWith("-"));
  return pkg && /^(?:@[\w.-]+\/)?[\w.-]+(?:@[\w.^~<>=-]+)?$/.test(pkg) ? pkg : null;
}

function mcpService(server) {
  const def = server.def || {};
  const url = typeof def.url === "string" ? def.url : typeof def.serverUrl === "string" ? def.serverUrl : null;
  const transport = def.type || def.transport || (url ? "http" : "stdio");
  const props = [
    { name: "penthera:ai-kind", value: "mcp-server" },
    { name: "penthera:mcp-transport", value: String(transport) },
    { name: "penthera:config-file", value: String(server.file || "") },
  ];
  if (def.command) props.push({ name: "penthera:mcp-command", value: basename(String(def.command)) });
  const pkg = mcpPackage(def);
  if (pkg) props.push({ name: "penthera:mcp-package", value: pkg });
  const envKeys = def.env && typeof def.env === "object" ? Object.keys(def.env) : [];
  if (envKeys.length) props.push({ name: "penthera:mcp-env-keys", value: envKeys.join(", ") }); // names only, never values
  const svc = {
    "bom-ref": `mcp:${server.name}`,
    name: server.name,
    description: `MCP server (${transport})`,
    "x-trust-boundary": !!url,
    properties: props,
  };
  if (url && /^https?:\/\//i.test(url)) svc.endpoints = [url];
  return svc;
}

// ── Build ─────────────────────────────────────────────────────────────────

/**
 * Build a CycloneDX 1.6 AI-BOM for a repo. Always returns a BOM (possibly with
 * no AI components, which is itself evidence).
 * @param {string} repoPath
 * @param {object} opts - { serialNumber, timestamp, toolVersion }
 */
export function buildAiBom(repoPath, opts = {}) {
  const { components: deps, sources, rootName, rootVersion } = collectDependencies(repoPath);
  const inv = discoverAgentConfig(repoPath);
  const root = inv.root;
  const { files } = walk(root);
  const usedRefs = new Set();
  const uniqueRef = (ref) => { let r = ref; let n = 2; while (usedRefs.has(r)) r = `${ref}#${n++}`; usedRefs.add(r); return r; };
  usedRefs.add("root");

  // AI SDK libraries
  const sdkSeen = new Set();
  const sdks = [];
  for (const d of deps) {
    const eco = d.ecosystem || "npm";
    const provider = eco === "pypi" ? matchSdk(PYPI_AI, normPy(d.name)) : matchSdk(NPM_AI, d.name);
    if (!provider) continue;
    sdks.push({ ...d, ecosystem: eco, provider });
  }
  const pyprojectText = readText(`${root}/pyproject.toml`);
  if (typeof pyprojectText === "string") {
    for (const d of pyprojectDeps(pyprojectText)) {
      const provider = matchSdk(PYPI_AI, normPy(d.name));
      if (provider && !sdks.some((s) => s.ecosystem === "pypi" && normPy(s.name) === normPy(d.name))) {
        sdks.push({ name: d.name, version: d.version, ecosystem: "pypi", provider, resolved: false });
      }
    }
    if (!sources.includes("pyproject.toml")) sources.push("pyproject.toml");
  }
  const sdkComponents = [];
  for (const s of sdks) {
    const p = purl(s.ecosystem, s.name, s.version);
    if (sdkSeen.has(p)) continue;
    sdkSeen.add(p);
    const props = [
      { name: "penthera:ai-kind", value: "sdk" },
      { name: "penthera:ai-provider", value: s.provider },
    ];
    if (!s.resolved) props.push({ name: "penthera:version-note", value: "declared range, not a resolved version" });
    sdkComponents.push({
      "bom-ref": uniqueRef(p),
      type: "library",
      name: s.name,
      version: s.version,
      ...(s.scope ? { scope: s.scope } : {}),
      purl: p,
      tags: ["ai", "ai-sdk"],
      properties: props,
    });
  }

  // Models
  const modelComponents = findModels(root, files).map((m) => {
    const props = [{ name: "penthera:ai-kind", value: "model-reference" }];
    if (m.distribution) props.push({ name: "penthera:model-distribution", value: m.distribution });
    const ext = [];
    if (m.huggingFace) ext.push({ type: "model-card", url: `https://huggingface.co/${m.name}` });
    else if (PROVIDER_DOCS[m.provider]) ext.push({ type: "documentation", url: PROVIDER_DOCS[m.provider] });
    return {
      "bom-ref": uniqueRef(`model:${m.name}`),
      type: "machine-learning-model",
      supplier: { name: m.provider },
      name: m.name,
      description: `${m.provider} model referenced in code`,
      tags: ["ai", "model"],
      modelCard: {
        properties: [{ name: "penthera:model-card-status", value: "stub: complete task, datasets and considerations from the provider's model card" }],
      },
      ...(ext.length ? { externalReferences: ext } : {}),
      evidence: { occurrences: m.occurrences },
      properties: props,
    };
  });

  // Skills
  const skillComponents = inv.skills.map((s) => {
      const rel = relative(root, s.skillFile).split(sep).join("/");
      const hash = sha256File(s.skillFile, root);
      const desc = typeof s.frontmatter?.description === "string" ? s.frontmatter.description.slice(0, 500) : undefined;
      return {
        "bom-ref": uniqueRef(`skill:${s.name}`),
        type: "data",
        name: s.name,
        ...(desc ? { description: desc } : {}),
        tags: ["ai", "agent-skill"],
        ...(hash ? { hashes: [{ alg: "SHA-256", content: hash }] } : {}),
        data: [{ type: "configuration", name: rel, description: "Agent Skill instructions (SKILL.md)" }],
        evidence: { occurrences: [{ location: rel }] },
        properties: [{ name: "penthera:ai-kind", value: "skill" }],
      };
    });

  // Prompt files
  const promptComponents = files
    .map((f) => ({ f, rel: relative(root, f).split(sep).join("/") }))
    .filter(({ rel }) => isPromptFile(rel))
    .map(({ f, rel }) => {
      const hash = sha256File(f, root);
      return {
        "bom-ref": uniqueRef(`prompt:${rel}`),
        type: "data",
        name: rel,
        tags: ["ai", "prompt"],
        ...(hash ? { hashes: [{ alg: "SHA-256", content: hash }] } : {}),
        data: [{ type: "configuration", name: rel, description: "Prompt template" }],
        evidence: { occurrences: [{ location: rel }] },
        properties: [{ name: "penthera:ai-kind", value: "prompt" }],
      };
    });

  // MCP servers
  const services = inv.mcpServers.map((s) => {
    const svc = mcpService(s);
    svc["bom-ref"] = uniqueRef(svc["bom-ref"]);
    return svc;
  });

  const components = [...sdkComponents, ...modelComponents, ...skillComponents, ...promptComponents];
  const refs = [...components, ...services].map((c) => c["bom-ref"]);

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    ...(opts.serialNumber ? { serialNumber: opts.serialNumber } : {}),
    version: 1,
    metadata: {
      ...(opts.timestamp ? { timestamp: opts.timestamp } : {}),
      tools: { components: [{ type: "application", name: "penthera", ...(opts.toolVersion ? { version: opts.toolVersion } : {}) }] },
      component: { "bom-ref": "root", type: "application", name: rootName, version: rootVersion },
      properties: [
        { name: "penthera:bom-kind", value: "ai-bom" },
        { name: "penthera:sources", value: [...sources, "source files", "agent config"].join(", ") },
        { name: "penthera:summary", value: `${sdkComponents.length} AI SDKs, ${modelComponents.length} models, ${services.length} MCP servers, ${skillComponents.length} skills, ${promptComponents.length} prompt files` },
      ],
    },
    components,
    ...(services.length ? { services } : {}),
    dependencies: [{ ref: "root", dependsOn: refs }],
  };
}

/** Counts for CLI output. */
export function aiBomSummary(bom) {
  const kind = (c) => c.properties?.find((p) => p.name === "penthera:ai-kind")?.value;
  const comps = bom?.components || [];
  return {
    sdks: comps.filter((c) => kind(c) === "sdk").length,
    models: comps.filter((c) => c.type === "machine-learning-model").length,
    mcpServers: (bom?.services || []).length,
    skills: comps.filter((c) => kind(c) === "skill").length,
    prompts: comps.filter((c) => kind(c) === "prompt").length,
  };
}
