#!/bin/bash
#
# Secrets Loader - Secure .env loading
#

load_secrets() {
    local env_file="${1:-.env}"
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    
    # Try multiple locations
    local env_paths=(
        "$env_file"
        "${script_dir}/.env"
        "${script_dir}/../.env"
    )
    
    local found=""
    for path in "${env_paths[@]}"; do
        if [[ -f "$path" ]]; then
            found="$path"
            break
        fi
    done
    
    if [[ -z "$found" ]]; then
        # No .env file, use defaults
        return 0
    fi
    
    # Check file permissions (warn if insecure)
    if command -v stat &> /dev/null; then
        local perms=$(stat -c %a "$found" 2>/dev/null || stat -f %A "$found" 2>/dev/null || echo "")
        if [[ -n "$perms" ]] && [[ "$perms" != "600" ]] && [[ "$perms" != "400" ]]; then
            echo "[secrets] WARNING: .env has permissions $perms, should be 600" >&2
        fi
    fi
    
    # Load variables
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # Extract key=value
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"
            
            # Remove surrounding quotes
            value="${value#\"}"
            value="${value%\"}"
            value="${value#\'}"
            value="${value%\'}"
            
            # Only set if not already set (env vars take precedence)
            if [[ -z "${!key:-}" ]]; then
                export "$key=$value"
            fi
        fi
    done < "$found"
}

# Validate required secrets
validate_secrets() {
    local missing=()
    
    for var in "$@"; do
        if [[ -z "${!var:-}" ]]; then
            missing+=("$var")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "[secrets] ERROR: Missing required: ${missing[*]}" >&2
        return 1
    fi
    
    return 0
}

# Auto-load when sourced
load_secrets "${1:-}"
