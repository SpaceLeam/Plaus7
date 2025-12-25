#!/bin/bash
#
# Nuclei Wrapper
# Vulnerability scanning with template selection
#

set -euo pipefail

INPUT_FILE="$1"
OUTPUT_FILE="$2"
SEVERITY="${3:-low,medium,high,critical}"
THREADS="${4:-25}"
TIMEOUT="${5:-1800}" # 30 minutes default

if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <input_file> <output_file> [severity] [threads] [timeout]"
    exit 1
fi

# Check if nuclei is available
if ! command -v nuclei &> /dev/null; then
    echo "nuclei not found, skipping..." >&2
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

# Update templates first (with timeout)
timeout 60 nuclei -update-templates 2>/dev/null || true

# Run nuclei
echo "[nuclei] Scanning with severity: $SEVERITY"

timeout "$TIMEOUT" nuclei -l "$INPUT_FILE" \
    -silent \
    -severity "$SEVERITY" \
    -c "$THREADS" \
    -bulk-size 25 \
    -rate-limit 100 \
    -timeout 10 \
    -retries 1 \
    -json \
    -o "$TEMP_FILE" \
    -tags "exposure,misconfig,cve,default-login,file" \
    2>/dev/null || true

# Convert to JSON array
if [[ -f "$TEMP_FILE" ]] && [[ -s "$TEMP_FILE" ]]; then
    # nuclei outputs JSONL, convert to array
    echo "[" > "$OUTPUT_FILE"
    sed 's/$/,/' "$TEMP_FILE" | sed '$ s/,$//' >> "$OUTPUT_FILE"
    echo "]" >> "$OUTPUT_FILE"
else
    echo "[]" > "$OUTPUT_FILE"
fi

# Count findings by severity
CRITICAL=$(grep -c '"critical"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
HIGH=$(grep -c '"high"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
MEDIUM=$(grep -c '"medium"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
LOW=$(grep -c '"low"' "$OUTPUT_FILE" 2>/dev/null || echo "0")

echo "[nuclei] Findings: Critical=$CRITICAL, High=$HIGH, Medium=$MEDIUM, Low=$LOW"
