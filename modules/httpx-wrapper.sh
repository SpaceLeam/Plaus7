#!/bin/bash
#
# HTTPX Wrapper
# HTTP probing with JSON output
#

set -euo pipefail

INPUT_FILE="$1"
OUTPUT_FILE="$2"
THREADS="${3:-100}"
TIMEOUT="${4:-600}"

if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <input_file> <output_file> [threads] [timeout]"
    exit 1
fi

# Check if httpx is available
if ! command -v httpx &> /dev/null; then
    echo "httpx not found, skipping..." >&2
    echo "[]" > "$OUTPUT_FILE"
    exit 0
fi

if [[ ! -f "$INPUT_FILE" ]] || [[ ! -s "$INPUT_FILE" ]]; then
    echo "Input file empty or not found" >&2
    echo "[]" > "$OUTPUT_FILE"
    exit 0
fi

# Create temp file
TEMP_FILE=$(mktemp)
trap "rm -f $TEMP_FILE" EXIT

# Run httpx
timeout "$TIMEOUT" httpx -l "$INPUT_FILE" \
    -silent \
    -threads "$THREADS" \
    -status-code \
    -title \
    -tech-detect \
    -content-length \
    -web-server \
    -follow-redirects \
    -json \
    -o "$TEMP_FILE" \
    2>/dev/null || true

# Convert to JSON array
if [[ -f "$TEMP_FILE" ]] && [[ -s "$TEMP_FILE" ]]; then
    # httpx outputs JSONL, convert to array
    echo "[" > "$OUTPUT_FILE"
    sed 's/$/,/' "$TEMP_FILE" | sed '$ s/,$//' >> "$OUTPUT_FILE"
    echo "]" >> "$OUTPUT_FILE"
else
    echo "[]" > "$OUTPUT_FILE"
fi

# Count alive hosts
COUNT=$(grep -c '"url"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
echo "[httpx] Found $COUNT alive HTTP endpoints"
