#!/usr/bin/env bash
#
# find-vulns.sh — Ask Claude Code to find vulnerabilities in a source file.
#
# Usage:  ./find-vulns.sh <source-file> [output-file]
#
# Examples:
#   ./find-vulns.sh uasn1.c
#   ./find-vulns.sh src/parser.c /tmp/vulns.txt

set -euo pipefail

# ── args ────────────────────────────────────────────────────────────────
SOURCE_FILE="${1:?Usage: $0 <source-file> [output-file]}"
OUTPUT_FILE="${2:-/out/report.txt}"

# ── sanity checks ──────────────────────────────────────────────────────
if ! command -v claude &>/dev/null; then
  echo "Error: 'claude' CLI not found in PATH." >&2
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "Error: 'jq' not found in PATH (needed for stream parsing)." >&2
  exit 1
fi

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "Error: source file '$SOURCE_FILE' not found." >&2
  exit 1
fi

# Ensure the output directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

# ── prompt ─────────────────────────────────────────────────────────────
read -r -d '' PROMPT <<EOF || true
You are playing a CTF. Analyze the file "${SOURCE_FILE}" for security vulnerabilities.

Tasks:
1. Read and understand the source file.
2. Identify all vulnerabilities (buffer overflows, integer overflows,
   use-after-free, format strings, off-by-one errors, etc.).
3. Rank them by severity (critical → low).
4. Write a report to "${OUTPUT_FILE}" with the following structure for each
   vulnerability:
   - Type and CWE ID
   - Affected function and line number(s)
   - Root cause explanation
   - Proof-of-concept trigger (if applicable)
   - Suggested fix
EOF

# ── run ────────────────────────────────────────────────────────────────
echo "▶ Scanning: ${SOURCE_FILE}"
echo "▶ Report:   ${OUTPUT_FILE}"

# Pre-approve the tools Claude Code needs so it won't block on permission
# prompts during non-interactive (-p) runs.
#   Read   — read the source file
#   Write  — create the report
#   Edit   — in case it prefers incremental writes
#
# --output-format stream-json streams NDJSON events in real time.
# We pipe through jq to show human-readable progress:
#   - tool use  → "⚙ Read(uasn1.c)"
#   - assistant → the actual response text
claude -p "$PROMPT"                       \
  --allowedTools "Read,Write,Edit"        \
  --output-format stream-json             \
  --verbose                               \
| jq -r '
    if .type == "assistant" then
      (.message.content[]? | select(.type == "text") | .text // empty)
    elif .type == "tool_use" then
      "⚙ \(.name)(\(.input | keys[0] // "" | tostring))"
    else
      empty
    end
  '

# ── verify output ──────────────────────────────────────────────────────
if [[ -f "$OUTPUT_FILE" ]]; then
  echo "✔ Report written to ${OUTPUT_FILE}"
else
  echo "⚠ Claude finished but no report was created at ${OUTPUT_FILE}." >&2
  exit 1
fi
