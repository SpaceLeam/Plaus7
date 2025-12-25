#!/bin/bash
#
# Context Analyzer
# Analyzes findings with context to reduce false positives
#

set -euo pipefail

INPUT_FILE="$1"
OUTPUT_FILE="$2"

if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <input_file> <output_file>"
    exit 1
fi

# Known false positive patterns
FALSE_POSITIVES=(
    "example.com"
    "test.example"
    "localhost"
    "127.0.0.1"
    "AKIAIOSFODNN7EXAMPLE"
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    "your-api-key"
    "YOUR_API_KEY"
    "xxx"
    "changeme"
    "password123"
    "sample"
    "dummy"
    "placeholder"
    "replace_me"
    "insert_here"
)

# Entropy calculation (pseudo, using unique char ratio)
calculate_entropy() {
    local str="$1"
    local len=${#str}
    
    if [[ $len -eq 0 ]]; then
        echo "0"
        return
    fi
    
    # Count unique characters
    local unique=$(echo "$str" | fold -w1 | sort -u | wc -l)
    
    # Simple entropy approximation
    echo "$((unique * 100 / len))"
}

# Check if string is likely false positive
is_false_positive() {
    local match="$1"
    local match_lower=$(echo "$match" | tr '[:upper:]' '[:lower:]')
    
    # Check against known false positives
    for fp in "${FALSE_POSITIVES[@]}"; do
        if [[ "$match_lower" == *"$fp"* ]]; then
            return 0 # Is false positive
        fi
    done
    
    # Check entropy for secrets (should be high for real secrets)
    if [[ "$match" =~ ^[a-zA-Z0-9_-]{20,}$ ]]; then
        local entropy=$(calculate_entropy "$match")
        if [[ $entropy -lt 30 ]]; then
            return 0 # Low entropy, likely false positive
        fi
    fi
    
    # Check for repeated patterns
    if [[ "$match" =~ ^(.)\1+$ ]]; then
        return 0 # All same character
    fi
    
    return 1 # Not a false positive
}

# Process findings
echo "[context-analyzer] Analyzing findings in $INPUT_FILE"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Input file not found"
    echo '{"findings": [], "filtered_count": 0}' > "$OUTPUT_FILE"
    exit 0
fi

# Read and filter findings
TEMP_FILE=$(mktemp)
trap "rm -f $TEMP_FILE" EXIT

TOTAL=0
FILTERED=0

# Process JSON findings if jq is available
if command -v jq &> /dev/null; then
    # Extract findings array
    jq -c '.findings[]' "$INPUT_FILE" 2>/dev/null | while read -r finding; do
        TOTAL=$((TOTAL + 1))
        
        match=$(echo "$finding" | jq -r '.match')
        
        if is_false_positive "$match"; then
            FILTERED=$((FILTERED + 1))
            continue
        fi
        
        # Add confidence score based on analysis
        severity=$(echo "$finding" | jq -r '.severity')
        
        # Calculate confidence
        confidence=0.5
        if [[ "$severity" == "critical" ]]; then
            confidence=0.9
        elif [[ "$severity" == "high" ]]; then
            confidence=0.7
        fi
        
        # Check for supporting context
        name=$(echo "$finding" | jq -r '.name')
        if [[ "$name" == *"AWS"* ]] && [[ "$match" == AKIA* ]]; then
            confidence=0.95
        fi
        
        # Output enhanced finding
        echo "$finding" | jq ". + {confidence: $confidence}" >> "$TEMP_FILE"
    done
    
    # Build final output
    {
        echo '{'
        echo '  "findings": ['
        
        FIRST=true
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                if [[ "$FIRST" == true ]]; then
                    FIRST=false
                else
                    echo ','
                fi
                echo "    $line"
            fi
        done < "$TEMP_FILE"
        
        echo '  ],'
        echo "  \"original_count\": $TOTAL,"
        echo "  \"filtered_count\": $FILTERED"
        echo '}'
    } > "$OUTPUT_FILE"
else
    # Fallback: just copy file
    cp "$INPUT_FILE" "$OUTPUT_FILE"
fi

echo "[context-analyzer] Filtered $FILTERED false positives"
