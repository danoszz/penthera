#!/usr/bin/env bash
#
# Penthera installer — clones the repo, links the CLI, and installs the
# Agent Skill into Cursor and Claude Code if it finds them.
#
#   curl -fsSL https://raw.githubusercontent.com/danoszz/penthera/main/install.sh | bash
#
# This script is intentionally short and readable — review it before running.
# It uses no sudo, makes no network calls beyond `git clone` + `npm install`,
# and only writes to ~/.penthera and your agent skill folders.
#
set -euo pipefail

REPO="https://github.com/danoszz/penthera.git"
DIR="${PENTHERA_DIR:-$HOME/.penthera}"
BLUE='\033[1;38;2;0;0;237m'; DIM='\033[2m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; OFF='\033[0m'

say()  { printf "%b\n" "$1"; }
ok()   { printf "  %b+%b %s\n" "$GREEN" "$OFF" "$1"; }
warn() { printf "  %b!%b %s\n" "$YELLOW" "$OFF" "$1"; }
die()  { printf "  %bx%b %s\n" "$RED" "$OFF" "$1" >&2; exit 1; }

say ""
say "  ${BLUE}P E N T H E R A${OFF}  ${DIM}installer${OFF}"
say ""

# ── Prerequisites ───────────────────────────────────────────────────────────
command -v git  >/dev/null 2>&1 || die "git is required. Install it and re-run."
command -v node >/dev/null 2>&1 || die "Node.js 18+ is required: https://nodejs.org"

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 18 ] || die "Node 18+ required (found $(node -v))."
ok "Node $(node -v)"

# ── Clone or update ─────────────────────────────────────────────────────────
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only --quiet && ok "Updated $DIR"
else
  git clone --depth 1 --quiet "$REPO" "$DIR" && ok "Cloned to $DIR"
fi

# ── Install dependencies + link CLI ─────────────────────────────────────────
cd "$DIR"
if [ -f package-lock.json ]; then
  npm ci --omit=dev --silent
else
  npm install --omit=dev --silent
fi
ok "Installed dependencies"

if npm link >/dev/null 2>&1; then
  ok "Linked CLI — run: penthera --version"
else
  warn "Could not link globally (permission?). Run from $DIR: node bin/penthera.js"
fi

# ── Install the Agent Skill into detected agents ────────────────────────────
install_skill() {
  local target="$1" name="$2"
  mkdir -p "$target"
  rm -rf "$target/penthera"
  cp -R "$DIR/skills/penthera" "$target/penthera"
  ok "Installed skill for $name → $target/penthera"
}

INSTALLED_ANY=0
[ -d "$HOME/.cursor" ] && { install_skill "$HOME/.cursor/skills" "Cursor"; INSTALLED_ANY=1; }
[ -d "$HOME/.claude" ] && { install_skill "$HOME/.claude/skills" "Claude Code"; INSTALLED_ANY=1; }
if [ "$INSTALLED_ANY" -eq 0 ]; then
  warn "No Cursor/Claude Code config found. Cross-agent install: npx skills add danoszz/penthera"
fi

# ── Done ────────────────────────────────────────────────────────────────────
say ""
say "  ${GREEN}Done.${OFF} Restart your agent, then just ask it:"
say ""
say "    ${DIM}\"Scan my localhost:3000 for security issues\"${OFF}"
say "    ${DIM}\"Run a pre-deploy security audit on staging.myapp.com\"${OFF}"
say "    ${DIM}\"Find hardcoded secrets in this repo\"${OFF}"
say ""
say "  Or from your terminal:  ${BLUE}penthera${OFF}   ${DIM}(interactive wizard)${OFF}"
say ""
say "  ${YELLOW}Only scan systems you own or are authorized to test.${OFF}"
say ""
