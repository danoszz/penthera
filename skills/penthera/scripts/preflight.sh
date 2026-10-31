#!/usr/bin/env bash
# Penthera preflight, run before first scan in a session.
# Usage: bash <skill folder>/scripts/preflight.sh [URL], run from the project folder.
# In a Penthera checkout the skill folder is skills/penthera; installed with
# `npx skills add` or as a plugin it lives under ~/.claude (or another agent's folder).

set -euo pipefail

TARGET_URL="${1:-}"
# The Penthera checkout this script sits in, if any (for node bin/penthera.js).
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
# The project being scanned: where the agent runs this, and where reports/ goes.
PROJECT_DIR="$(pwd)"

fail() {
  echo "preflight: ERROR: $*" >&2
  exit 1
}

warn() {
  echo "preflight: WARN: $*" >&2
}

ok() {
  echo "preflight: OK: $*"
}

# Node.js 22+
if ! command -v node >/dev/null 2>&1; then
  fail "Node.js not found. Install Node.js 22+ from https://nodejs.org/"
fi

NODE_MAJOR=$(node -e "process.stdout.write(String(process.version).replace(/^v/, '').split('.')[0])")
if [ "$NODE_MAJOR" -lt 22 ]; then
  fail "Node.js $(node -v) is too old. Requires Node.js 22+."
fi
ok "Node.js $(node -v)"

# Penthera CLI: installed, this checkout, or npx (no install needed)
PENTHERA_CMD=""
if command -v penthera >/dev/null 2>&1; then
  PENTHERA_CMD="penthera"
elif [ -f "$REPO_ROOT/bin/penthera.js" ]; then
  PENTHERA_CMD="node $REPO_ROOT/bin/penthera.js"
elif command -v npx >/dev/null 2>&1; then
  PENTHERA_CMD="npx -y penthera@2.1.2"
else
  fail "Penthera CLI not found, and npx is missing. Install Node.js 22+ (it includes npx), or run: npm install -g penthera@2.1.2"
fi

if [ "$PENTHERA_CMD" = "npx -y penthera@2.1.2" ]; then
  # Only ask the npx cache: preflight never downloads anything.
  VERSION=$(npx --no-install penthera@2.1.2 --version 2>/dev/null || true)
  if [ -n "$VERSION" ]; then
    ok "Penthera $VERSION, through npx (use: npx -y penthera@2.1.2 ...)"
  else
    ok "Penthera runs through npx (use: npx -y penthera@2.1.2 ...); the first run downloads it from npm"
  fi
else
  VERSION=$($PENTHERA_CMD --version 2>/dev/null || true)
  if [ -z "$VERSION" ]; then
    fail "Could not run Penthera CLI ($PENTHERA_CMD --version failed)"
  fi
  ok "Penthera $VERSION"
fi

# Reports directory (create if missing)
mkdir -p "$PROJECT_DIR/reports"
ok "reports/ directory ready in $PROJECT_DIR"

# Non-localhost warning
if [ -n "$TARGET_URL" ]; then
  case "$TARGET_URL" in
    http://localhost*|https://localhost*|http://127.0.0.1*|https://127.0.0.1*|'http://[::1]'*|'https://[::1]'*)
      ok "Target is localhost, authorization satisfied for local testing"
      ;;
    *)
      warn "Target is not localhost ($TARGET_URL). Confirm user owns this system or has written authorization before scanning."
      ;;
  esac
fi

echo "preflight: All checks passed. Ready to scan."
