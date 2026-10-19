/**
 * One-line footer at the end of human-readable Markdown output: the default
 * report, audience reports, the PR comment and the evidence bundle README.
 * Never added to SARIF or JSON. `--no-footer` turns it off.
 */
export const FOOTER = "Checked by Penthera, open-source security for the apps and AI systems you ship · https://github.com/danoszz/penthera";

/** Lines to push at the very end of a Markdown document, or none when opted out. */
export function footerLines({ footer = true } = {}) {
  return footer === false ? [] : [FOOTER, ""];
}
