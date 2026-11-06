/**
 * Optional local-model fallback for findings no recipe matches.
 *
 * Talks to Ollama on this machine only (http://127.0.0.1:11434), with a model
 * the user names via --fix-model. The host is fixed: there is no option to point
 * it anywhere else, redirects are refused, and the URL is checked before every
 * request. Off by default. Its output is always labelled
 * confidence "needs-human-review" and source "local-model", and a diff that
 * does not parse, leaves the repo, or fails to apply is dropped. A diff that
 * edits a protected file (tests, test config, Penthera's own files: see
 * lib/fix/apply.js) throws FixError PROTECTED, so the attempt is reported.
 */
import { existsSync, realpathSync } from "node:fs";
import { readRepoFile } from "../fs-safe.js";
import { isAbsolute, join, relative, sep } from "node:path";
import { readJson } from "../../src/utils/http.js";
import { applyDiff } from "./apply.js";
import { parsePatch } from "./diff.js";
import { detectFramework, walkCodeFiles, findEntryFile } from "./util.js";

export const OLLAMA_ORIGIN = "http://127.0.0.1:11434";
const MAX_CONTEXT_CHARS = 12_000;

/** Throws unless `url` is the local Ollama endpoint. Exported for tests. */
export function assertLocalModelUrl(url) {
  const u = new URL(url);
  if (u.origin !== OLLAMA_ORIGIN) throw new Error(`Refusing to contact ${u.origin}: the fix model may only use ${OLLAMA_ORIGIN}`);
  return u;
}

/** True when `file` (repo-relative) really lives in the repo once symlinks are resolved. */
function insideRepo(repoPath, file) {
  try {
    const rel = relative(realpathSync(repoPath), realpathSync(join(repoPath, file)));
    return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
  } catch {
    return false;
  }
}

/** The one repo file whose source goes into the prompt; never a file outside the repo. */
function contextFile(repoPath, finding) {
  const file = pickContextFile(repoPath, finding);
  return file && insideRepo(repoPath, file) ? file : null;
}

function pickContextFile(repoPath, finding) {
  const files = walkCodeFiles(repoPath);
  if (finding.url && files.includes(finding.url)) return finding.url;
  const fw = detectFramework(repoPath);
  if (fw === "next") {
    for (const f of ["next.config.mjs", "next.config.js", "next.config.ts"]) if (existsSync(join(repoPath, f))) return f;
  }
  return findEntryFile(repoPath, /\S/)?.file || null;
}

export function buildPrompt(finding, file, source) {
  return [
    "You fix one security finding in a web app. Reply with a single unified diff and nothing else.",
    "Rules: change as little as possible; edit only the file shown unless a new file is unavoidable;",
    "use paths relative to the repo root with a/ and b/ prefixes; add no dependencies; never invent secrets.",
    "If you cannot fix it safely, reply with NO_FIX.",
    "",
    `Finding: ${JSON.stringify({ title: finding.title, category: finding.category, severity: finding.severity, description: finding.description })}`,
    "",
    `File: ${file}`,
    "```",
    source.slice(0, MAX_CONTEXT_CHARS),
    "```",
  ].join("\n");
}

/** Pull a unified diff out of a model reply (fenced or bare). */
export function extractDiff(text) {
  if (!text || /^\s*NO_FIX\b/.test(text)) return null;
  const fenced = text.match(/```(?:diff|patch)?[ \t]*\r?\n([\s\S]*?)```/);
  const body = fenced ? fenced[1] : text;
  const start = body.search(/^--- /m);
  if (start < 0) return null;
  const diff = body.slice(start).trimEnd() + "\n";
  return diff;
}

/**
 * @param {{ model: string, fetch?: typeof fetch, timeout?: number }} opts
 * @returns {{ model: string, plan(repoPath: string, finding: object): Promise<object|null> }}
 */
export function createModelFixer({ model, fetch: fetchImpl = globalThis.fetch, timeout = 120_000 } = {}) {
  if (!model || typeof model !== "string") throw new Error("A local model name is required (--fix-model <name>)");
  const url = assertLocalModelUrl(`${OLLAMA_ORIGIN}/api/generate`).href;

  return {
    model,
    async plan(repoPath, finding) {
      const file = contextFile(repoPath, finding);
      if (!file) return null;
      const source = readRepoFile(join(repoPath, file), { root: repoPath, maxBytes: 5 * 1024 * 1024 });
      assertLocalModelUrl(url);
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model, prompt: buildPrompt(finding, file, source), stream: false, options: { temperature: 0 } }),
        redirect: "error",
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) return null;
      const data = await readJson(res, { maxBytes: 4 * 1024 * 1024, timeout });
      const diff = extractDiff(data?.response);
      if (!diff) return null;
      let files;
      try {
        files = parsePatch(diff).map((f) => f.newPath);
        // Validates paths stay inside the repo and every hunk applies; writes nothing.
        applyDiff(repoPath, diff, { dryRun: true, allowDirty: true });
      } catch (e) {
        if (e?.code === "PROTECTED") throw e; // an edit to the checker is reported, never quietly dropped
        return null;
      }
      return {
        diff,
        files,
        ownerActions: ["A local model wrote this diff, not a deterministic recipe. Read every line before applying, then re-scan."],
        confidence: "needs-human-review",
        source: "local-model",
        model,
      };
    },
  };
}
