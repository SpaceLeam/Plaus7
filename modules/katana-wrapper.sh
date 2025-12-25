#!/bin/bash
#
# Katana Wrapper
# Web crawling and endpoint discovery
#

set -euo pipefail

INPUT_FILE="$1"
OUTPUT_FILE="$2"
DEPTH="${3:-5}"
THREADS="${4:-50}"
TIMEOUT="${5:-900}" # 15 minutes default

if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <input_file> <output_file> [depth] [threads] [timeout]"
    exit 1
fi

# Check if katana is available
if ! command -v katana &> /dev/null; then
    echo "katana not found, skipping..." >&2
    touch "$OUTPUT_FILE"
    exit 0
fi

if [[ ! -f "$INPUT_FILE" ]] || [[ ! -s "$INPUT_FILE" ]]; then
    echo "Input file empty or not found" >&2
    touch "$OUTPUT_FILE"
    exit 0
fi

# Create temp files
TEMP_FILE=$(mktemp)
JS_FILE=$(mktemp)
trap "rm -f $TEMP_FILE $JS_FILE" EXIT

# Run katana
echo "[katana] Crawling with depth $DEPTH"

timeout "$TIMEOUT" katana -list "$INPUT_FILE" \
    -silent \
    -d "$DEPTH" \
    -c "$THREADS" \
    -jc \
    -kf all \
    -ef "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot" \
    -o "$TEMP_FILE" \
    2>/dev/null || true

# Extract JavaScript files for additional analysis
grep -E '\.js(\?|$)' "$TEMP_FILE" 2>/dev/null | sort -u > "$JS_FILE" || true

# Main output
if [[ -f "$TEMP_FILE" ]]; then
    sort -u "$TEMP_FILE" > "$OUTPUT_FILE"
fi

# Output stats
TOTAL=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo "0")
JS_COUNT=$(wc -l < "$JS_FILE" 2>/dev/null || echo "0")

echo "[katana] Discovered $TOTAL endpoints ($JS_COUNT JavaScript files)"

# Store JS files separately for pattern detection
JS_OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
if [[ -s "$JS_FILE" ]]; then
    cp "$JS_FILE" "${JS_OUTPUT_DIR}/js_files.txt"
fi
