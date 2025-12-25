#!/bin/bash
#
# Pattern Matcher
# Scans content for vulnerability patterns defined in YAML
#

set -euo pipefail

INPUT_DIR="$1"
PATTERNS_DIR="$2"
OUTPUT_FILE="$3"

if [[ -z "$INPUT_DIR" ]] || [[ -z "$PATTERNS_DIR" ]] || [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <input_dir> <patterns_dir> <output_file>"
    exit 1
fi

# Initialize output
echo '{"findings": [], "stats": {}}' > "$OUTPUT_FILE"

FINDINGS_FILE=$(mktemp)
trap "rm -f $FINDINGS_FILE" EXIT

echo "[]" > "$FINDINGS_FILE"

# Counter for stats
declare -A SEVERITY_COUNT
SEVERITY_COUNT[critical]=0
SEVERITY_COUNT[high]=0
SEVERITY_COUNT[medium]=0
SEVERITY_COUNT[low]=0

TOTAL_FINDINGS=0

# Define patterns and search
search_pattern() {
    local name="$1"
    local regex="$2"
    local severity="$3"
    local file="$4"
    
    while IFS= read -r match; do
        if [[ -n "$match" ]]; then
            # Check for false positives
            if echo "$match" | grep -qiE 'example|test|sample|dummy|placeholder'; then
                continue
            fi
            
            TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
            SEVERITY_COUNT[$severity]=$((SEVERITY_COUNT[$severity] + 1))
            
            # Add to findings (basic JSON)
            local line_num=$(grep -n "$match" "$file" 2>/dev/null | head -1 | cut -d: -f1 || echo "0")
            printf '{"id":%d,"name":"%s","severity":"%s","match":"%s","file":"%s","line":%s}\n' \
                "$TOTAL_FINDINGS" \
                "$name" \
                "$severity" \
                "$(echo "$match" | head -c 100 | sed 's/"/\\"/g')" \
                "$(basename "$file")" \
                "$line_num"
        fi
    done
}

# API Key patterns
scan_api_keys() {
    local file="$1"
    
    # AWS Access Key
    grep -oE 'AKIA[0-9A-Z]{16}' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "AWS Access Key" "$match" "critical" "$file"
        done
    
    # GitHub Token
    grep -oE 'gh[pousr]_[0-9a-zA-Z]{36}' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "GitHub Token" "$match" "high" "$file"
        done
    
    # Slack Token
    grep -oE 'xox[baprs]-[0-9a-zA-Z-]+' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "Slack Token" "$match" "high" "$file"
        done
    
    # Google API Key
    grep -oE 'AIza[0-9A-Za-z\-_]{35}' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "Google API Key" "$match" "high" "$file"
        done
    
    # Stripe Key
    grep -oE 'sk_live_[0-9a-zA-Z]{24}' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "Stripe Secret Key" "$match" "critical" "$file"
        done
    
    # Private Key
    grep -l "BEGIN RSA PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY" "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "Private Key Exposed" "$match" "critical" "$file"
        done
    
    # JWT (just log, not always sensitive)
    grep -oE 'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+' "$file" 2>/dev/null | head -5 | \
        while read -r match; do
            search_pattern "JWT Token" "$(echo "$match" | head -c 50)..." "medium" "$file"
        done
    
    # Generic API Key pattern
    grep -oiE '(api[_-]?key|apikey)["\x27]?\s*[:=]\s*["\x27][0-9a-zA-Z_-]{20,}["\x27]' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "Generic API Key" "$match" "medium" "$file"
        done
}

# Config/Debug exposure patterns
scan_config_exposure() {
    local file="$1"
    
    # Database connection strings
    grep -oE 'mongodb(\+srv)?://[^"\x27\s]+' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "MongoDB Connection String" "$match" "high" "$file"
        done
    
    grep -oE 'postgres(ql)?://[^"\x27\s]+' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "PostgreSQL Connection String" "$match" "high" "$file"
        done
    
    # Hardcoded passwords
    grep -oiE 'password["\x27]?\s*[:=]\s*["\x27][^"\x27]{8,}["\x27]' "$file" 2>/dev/null | \
        grep -viE 'example|test|sample|changeme|your_password' | head -5 | \
        while read -r match; do
            search_pattern "Hardcoded Password" "$match" "high" "$file"
        done
    
    # Internal IPs
    grep -oE '(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})' "$file" 2>/dev/null | \
        sort -u | head -10 | \
        while read -r match; do
            search_pattern "Internal IP Address" "$match" "low" "$file"
        done
    
    # Debug enabled
    grep -oiE 'debug\s*[:=]\s*true' "$file" 2>/dev/null | \
        while read -r match; do
            search_pattern "Debug Enabled" "$match" "medium" "$file"
        done
}

# Scan all text files
echo "[pattern-matcher] Scanning files in $INPUT_DIR"

SCAN_COUNT=0
find "$INPUT_DIR" -type f \( -name "*.txt" -o -name "*.json" -o -name "*.js" -o -name "*.html" \) 2>/dev/null | \
while read -r file; do
    if [[ -f "$file" ]] && [[ -s "$file" ]]; then
        # Skip binary files
        if file "$file" | grep -q "text"; then
            scan_api_keys "$file" >> "$FINDINGS_FILE"
            scan_config_exposure "$file" >> "$FINDINGS_FILE"
            SCAN_COUNT=$((SCAN_COUNT + 1))
        fi
    fi
done

# Generate final output
{
    echo '{'
    echo '  "findings": ['
    
    # Read findings and format
    FIRST=true
    while IFS= read -r finding; do
        if [[ -n "$finding" ]]; then
            if [[ "$FIRST" == true ]]; then
                FIRST=false
            else
                echo ','
            fi
            echo "    $finding"
        fi
    done < "$FINDINGS_FILE"
    
    echo '  ],'
    echo '  "stats": {'
    echo "    \"total\": $TOTAL_FINDINGS,"
    echo "    \"critical\": ${SEVERITY_COUNT[critical]},"
    echo "    \"high\": ${SEVERITY_COUNT[high]},"
    echo "    \"medium\": ${SEVERITY_COUNT[medium]},"
    echo "    \"low\": ${SEVERITY_COUNT[low]}"
    echo '  }'
    echo '}'
} > "$OUTPUT_FILE"

echo "[pattern-matcher] Found $TOTAL_FINDINGS potential issues"
echo "[pattern-matcher] Critical: ${SEVERITY_COUNT[critical]}, High: ${SEVERITY_COUNT[high]}, Medium: ${SEVERITY_COUNT[medium]}, Low: ${SEVERITY_COUNT[low]}"
