/**
 * ANSI helpers + brand styling — respects NO_COLOR and terminal width.
 */
const off = !!process.env.NO_COLOR;

export const bold = (s) => off ? s : `\x1b[1m${s}\x1b[0m`;
export const dim = (s) => off ? s : `\x1b[2m${s}\x1b[0m`;
export const cyan = (s) => off ? s : `\x1b[36m${s}\x1b[0m`;
export const green = (s) => off ? s : `\x1b[32m${s}\x1b[0m`;
export const yellow = (s) => off ? s : `\x1b[33m${s}\x1b[0m`;
export const red = (s) => off ? s : `\x1b[31m${s}\x1b[0m`;

// ── Brand ──────────────────────────────────────────────────────────────────
// Penthera blue: #0000ed (rgb 0,0,237). Truecolor + bold, with graceful
// degradation under NO_COLOR.
const BRAND = "\x1b[1m\x1b[38;2;0;0;237m";
const RESET = "\x1b[0m";
export const brand = (s) => off ? s : `${BRAND}${s}${RESET}`;

// "PENTHERA" — ANSI Shadow block letters (~67 cols wide).
const LOGO_BIG = [
  "██████╗ ███████╗███╗   ██╗████████╗██╗  ██╗███████╗██████╗  █████╗ ",
  "██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔══██╗",
  "██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║█████╗  ██████╔╝███████║",
  "██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██╔══╝  ██╔══██╗██╔══██║",
  "██║     ███████╗██║ ╚████║   ██║   ██║  ██║███████╗██║  ██║██║  ██║",
  "╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝",
];

// Compact wordmark for narrow terminals / nested output.
const LOGO_SMALL = "▌▌ P E N T H E R A";

/**
 * Render the Penthera logo. Falls back to a compact wordmark when the
 * terminal is narrower than the block art.
 */
export function logo(tagline = "security check for your vibecoded app") {
  const cols = process.stdout.columns || 80;
  const lines = [""];

  if (cols >= 72) {
    for (const row of LOGO_BIG) lines.push("  " + brand(row));
  } else {
    lines.push("  " + brand(LOGO_SMALL));
  }

  lines.push("");
  if (tagline) lines.push("  " + dim(tagline));
  lines.push("");
  return lines.join("\n");
}

// Back-compat alias — older callers import `banner`.
export function banner() {
  return logo();
}

export function box(title, lines) {
  const out = [`  ${bold(title)}`, ""];
  for (const line of lines) out.push(`  ${line}`);
  out.push("");
  return out.join("\n");
}

/** Dim horizontal rule sized to the terminal (capped). */
export function hr(width) {
  const cols = process.stdout.columns || 60;
  const len = Math.min(width || 58, Math.max(20, cols - 4));
  return dim("─".repeat(len));
}
