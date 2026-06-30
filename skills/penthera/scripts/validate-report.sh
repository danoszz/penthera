#!/usr/bin/env bash
# Validate a Penthera JSON scan report.
# Usage: bash skills/penthera/scripts/validate-report.sh [report.json]

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
REPORT="${1:-reports/scan.json}"
node "$REPO_ROOT/skills/penthera/scripts/validate-report.mjs" "$REPORT"
