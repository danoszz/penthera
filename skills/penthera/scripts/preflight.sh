#!/usr/bin/env bash
# Penthera preflight — run before first scan in a session.
# Usage: bash skills/penthera/scripts/preflight.sh [URL]

set -euo pipefail

TARGET_URL="${1:-}"
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

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

# Node.js 18+
if ! command -v node >/dev/null 2>&1; then
  fail "Node.js not found. Install Node.js 18+ from https://nodejs.org/"
fi

NODE_MAJOR=$(node -e "process.stdout.write(String(process.version).replace(/^v/, '').split('.')[0])")
if [ "$NODE_MAJOR" -lt 18 ]; then
  fail "Node.js $(node -v) is too old. Requires Node.js 18+."
fi
ok "Node.js $(node -v)"

# Penthera CLI
PENTHERA_CMD=""
if command -v penthera >/dev/null 2>&1; then
  PENTHERA_CMD="penthera"
elif [ -f "$REPO_ROOT/bin/penthera.js" ]; then
  PENTHERA_CMD="node $REPO_ROOT/bin/penthera.js"
else
  fail "Penthera CLI not found. Run 'npm link' from repo root or use node bin/penthera.js"
fi

VERSION=$($PENTHERA_CMD --version 2>/dev/null || true)
if [ -z "$VERSION" ]; then
  fail "Could not run Penthera CLI ($PENTHERA_CMD --version failed)"
fi
ok "Penthera $VERSION"

# Reports directory (create if missing)
mkdir -p "$REPO_ROOT/reports"
ok "reports/ directory ready"

# Non-localhost warning
if [ -n "$TARGET_URL" ]; then
  case "$TARGET_URL" in
    http://localhost*|https://localhost*|http://127.0.0.1*|https://127.0.0.1*|http://[::1]*|https://[::1]*)
      ok "Target is localhost — authorization satisfied for local testing"
      ;;
    *)
      warn "Target is not localhost ($TARGET_URL). Confirm user owns this system or has written authorization before scanning."
      ;;
  esac
fi

echo "preflight: All checks passed. Ready to scan."
