/**
 * Commands in hints have to run for the reader. Under npx there is no `penthera`
 * on the PATH, so they need the prefix.
 */
const ranThroughNpx = ({ env, argv1 }) => env.npm_command === "exec" && /[\\/]node_modules[\\/]/.test(argv1 || "");

/** Every `penthera` command in a line of text, as the reader can run it. */
export function hintCommand(text, { env = process.env, argv1 = process.argv[1] } = {}) {
  if (!ranThroughNpx({ env, argv1 })) return text;
  return String(text).replace(/(?<![\w./~-])(npx\s+)?penthera(?![\w./-])/g, (m, npx) => (npx ? m : `npx ${m}`));
}
