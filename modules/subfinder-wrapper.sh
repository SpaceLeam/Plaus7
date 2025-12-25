#!/bin/bash
#
# Subfinder Wrapper
# Handles timeout and output normalization
#

set -euo pipefail

DOMAIN="$1"
OUTPUT_FILE="$2"
THREADS="${3:-100}"
TIMEOUT="${4:-600}" # 10 minutes default

if [[ -z "$DOMAIN" ]] || [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <domain> <output_file> [threads] [timeout]"
    exit 1
fi

# Check if subfinder is available
if ! command -v subfinder &> /dev/null; then
    echo "subfinder not found, skipping..." >&2
    touch "$OUTPUT_FILE"
    exit 0
fi

# Create temp file for json output
TEMP_FILE=$(mktemp)
trap "rm -f $TEMP_FILE" EXIT

# Run subfinder with timeout
timeout "$TIMEOUT" subfinder -d "$DOMAIN" \
    -silent \
    -t "$THREADS" \
    -all \
    -o "$TEMP_FILE" \
    2>/dev/null || true

# Normalize output (remove wildcards, sort, dedupe)
if [[ -f "$TEMP_FILE" ]]; then
    grep -v '^\*\.' "$TEMP_FILE" 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | \
        sort -u >> "$OUTPUT_FILE"
fi

COUNT=$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo "0")
echo "[subfinder] Found $COUNT subdomains for $DOMAIN"
