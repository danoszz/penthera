/**
 * Shared terminal prompt helpers (TTY + piped stdin).
 */
import { createInterface } from "node:readline";

let _pipedLines = null;
let _rl = null;

export async function initPrompt() {
  if (process.stdin.isTTY) {
    _rl = createInterface({ input: process.stdin, output: process.stdout });
  } else {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    _pipedLines = Buffer.concat(chunks).toString().split("\n").map((l) => l.trim());
  }
}

export function closePrompt() {
  if (_rl) _rl.close();
}

export function ask(question) {
  if (_pipedLines) {
    process.stdout.write(question);
    const answer = _pipedLines.shift() || "";
    process.stdout.write(answer + "\n");
    return Promise.resolve(answer);
  }
  return new Promise((resolve) => {
    _rl.question(question, (answer) => resolve(answer.trim()));
  });
}

/** Normalize user URL input (adds http/https). */
export function normalizeUrlInput(raw, forceLocal = false) {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
    const looksLocal = forceLocal ||
      /^(localhost|127\.|0\.0\.0|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01]))/.test(trimmed);
    return looksLocal ? `http://${trimmed}` : `https://${trimmed}`;
  }
  return trimmed;
}

/** Single-choice menu. Returns selected option id. */
export async function choose(question, options) {
  process.stdout.write(`\n${question}\n`);
  options.forEach((opt, i) => {
    process.stdout.write(`  ${i + 1}. ${opt.label}\n`);
  });
  const answer = await ask(`\n  Choice [1-${options.length}]: `);
  const idx = parseInt(answer, 10) - 1;
  if (idx >= 0 && idx < options.length) return options[idx].id;
  return options[0].id;
}

export async function confirm(question, defaultYes = true) {
  const hint = defaultYes ? "[Y/n]" : "[y/N]";
  const answer = await ask(`${question} ${hint}: `);
  if (!answer) return defaultYes;
  return answer.toLowerCase() === "y" || answer.toLowerCase() === "yes";
}
