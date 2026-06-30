#!/usr/bin/env bash
# Package the Agent Skill for Claude.ai upload or GitHub Releases.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist"
ZIP="$OUT/penthera-skill.zip"

mkdir -p "$OUT"
rm -f "$ZIP"

cd "$ROOT/skills"
zip -r "$ZIP" penthera/ -x "*.DS_Store"

echo "Created $ZIP"
ls -lh "$ZIP"
