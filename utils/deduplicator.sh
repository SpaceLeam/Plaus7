#!/bin/bash
#
# Deduplicator
# Removes duplicate findings using hash comparison
#

set -euo pipefail

INPUT_FILE="$1"
OUTPUT_FILE="${2:-$INPUT_FILE}"

if [[ -z "$INPUT_FILE" ]]; then
    echo "Usage: $0 <input_file> [output_file]"
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Input file not found: $INPUT_FILE"
    exit 1
fi

echo "[deduplicator] Processing $INPUT_FILE"

# Detect file type
if head -1 "$INPUT_FILE" | grep -q '^{'; then
    # JSON/JSONL file
    dedupe_json
elif head -1 "$INPUT_FILE" | grep -q '^\['; then
    # JSON array
    dedupe_json_array
else
    # Plain text
    dedupe_text
fi

dedupe_text() {
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" RETURN
    
    local original=$(wc -l < "$INPUT_FILE")
    
    # Sort and remove duplicates
    sort -u "$INPUT_FILE" > "$temp_file"
    mv "$temp_file" "$OUTPUT_FILE"
    
    local final=$(wc -l < "$OUTPUT_FILE")
    local removed=$((original - final))
    
    echo "[deduplicator] Removed $removed duplicates ($original → $final)"
}

dedupe_json() {
    if ! command -v jq &> /dev/null; then
        echo "[deduplicator] jq not found, skipping JSON deduplication"
        cp "$INPUT_FILE" "$OUTPUT_FILE"
        return
    fi
    
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" RETURN
    
    # Deduplicate JSONL by generating hash of key fields
    local original=0
    local final=0
    
    declare -A seen
    
    while IFS= read -r line; do
        original=$((original + 1))
        
        # Generate hash from key fields
        local hash=$(echo "$line" | jq -r '[.url, .host, .name, .template] | @json' 2>/dev/null | md5sum | cut -d' ' -f1)
        
        if [[ -z "${seen[$hash]:-}" ]]; then
            seen[$hash]=1
            echo "$line" >> "$temp_file"
            final=$((final + 1))
        fi
    done < "$INPUT_FILE"
    
    mv "$temp_file" "$OUTPUT_FILE"
    
    local removed=$((original - final))
    echo "[deduplicator] Removed $removed duplicate JSON entries ($original → $final)"
}

dedupe_json_array() {
    if ! command -v jq &> /dev/null; then
        echo "[deduplicator] jq not found, skipping JSON deduplication"
        cp "$INPUT_FILE" "$OUTPUT_FILE"
        return
    fi
    
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" RETURN
    
    local original=$(jq 'length' "$INPUT_FILE" 2>/dev/null || echo 0)
    
    # Unique by key combination
    jq 'unique_by([.url, .host, .name, .template] | join(":"))' "$INPUT_FILE" > "$temp_file"
    
    local final=$(jq 'length' "$temp_file" 2>/dev/null || echo 0)
    
    mv "$temp_file" "$OUTPUT_FILE"
    
    local removed=$((original - final))
    echo "[deduplicator] Removed $removed duplicate array entries ($original → $final)"
}

# Deduplicate URLs specifically
dedupe_urls() {
    local input="$1"
    local output="$2"
    
    if [[ ! -f "$input" ]]; then
        return
    fi
    
    local temp_file=$(mktemp)
    trap "rm -f $temp_file" RETURN
    
    # Normalize and dedupe URLs
    while IFS= read -r url; do
        # Remove trailing slashes
        url="${url%/}"
        
        # Remove common tracking parameters
        url=$(echo "$url" | sed -E 's/[?&](utm_[^&=]+=[^&]*)//g')
        
        # Remove fragments
        url="${url%%#*}"
        
        echo "$url"
    done < "$input" | sort -u > "$temp_file"
    
    mv "$temp_file" "$output"
}

# Call appropriate function
case "${INPUT_FILE##*.}" in
    json)
        if head -1 "$INPUT_FILE" | grep -q '^\['; then
            dedupe_json_array
        else
            dedupe_json
        fi
        ;;
    *)
        dedupe_text
        ;;
esac
