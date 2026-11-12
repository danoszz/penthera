import { readFileSync } from "node:fs";

/**
 * Commands in hints have to run for the reader. Under npx there is no `penthera`
 * on the PATH, so they need the prefix, and they name the version that is
 * running: a bare `npx penthera` resolves to whatever npm has as newest, which
 * would step an agent off the version it pinned (Hermes catalog review, 10 Nov).
 */
const ranThroughNpx = ({ env, argv1 }) => env.npm_command === "exec" && /[\\/]node_modules[\\/]/.test(argv1 || "");

const RUNNING_VERSION = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8")).version;

/** Every `penthera` command in a line of text, as the reader can run it. */
export function hintCommand(text, { env = process.env, argv1 = process.argv[1], version = RUNNING_VERSION } = {}) {
  if (!ranThroughNpx({ env, argv1 })) return text;
  // A command that already names a version keeps it; a bare one gets the running version.
  return String(text).replace(/(?<![\w./~-])(?:npx\s+(?:-y\s+)?)?penthera(@[\w.+-]+)?(?![\w./@-])/g, (m, pinned) => (pinned ? m : `npx -y penthera@${version}`));
}
