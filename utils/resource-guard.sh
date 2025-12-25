#!/bin/bash
#
# Resource Guard - Prevents resource exhaustion
#

set -euo pipefail

# Thresholds (can be overridden via env)
MAX_DISK_USAGE="${MAX_DISK_USAGE:-90}"
MAX_MEM_USAGE="${MAX_MEM_USAGE:-85}"
MIN_FREE_DISK_GB="${MIN_FREE_DISK_GB:-5}"

log() {
    echo "[resource-guard] $*"
}

check_disk_space() {
    local path="${1:-.}"
    
    # Get disk usage percentage
    local usage=$(df "$path" 2>/dev/null | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [[ -z "$usage" ]]; then
        log "WARNING: Could not determine disk usage"
        return 0
    fi
    
    if [[ $usage -ge $MAX_DISK_USAGE ]]; then
        log "ERROR: Disk usage at ${usage}% (max: ${MAX_DISK_USAGE}%)"
        return 1
    fi
    
    # Get free space in GB
    local free_gb=$(df -BG "$path" 2>/dev/null | awk 'NR==2 {print $4}' | sed 's/G//')
    
    if [[ -n "$free_gb" ]] && [[ $free_gb -lt $MIN_FREE_DISK_GB ]]; then
        log "ERROR: Only ${free_gb}GB free (min: ${MIN_FREE_DISK_GB}GB)"
        return 1
    fi
    
    log "Disk OK: ${usage}% used, ${free_gb:-?}GB free"
    return 0
}

check_memory() {
    local usage=0
    
    # Try different methods to get memory usage
    if command -v free &> /dev/null; then
        usage=$(free | awk 'NR==2 {printf "%.0f", $3/$2 * 100}')
    elif [[ -f /proc/meminfo ]]; then
        local total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
        local avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
        if [[ -n "$total" ]] && [[ -n "$avail" ]] && [[ $total -gt 0 ]]; then
            usage=$(( (total - avail) * 100 / total ))
        fi
    else
        log "WARNING: Could not determine memory usage"
        return 0
    fi
    
    if [[ $usage -ge $MAX_MEM_USAGE ]]; then
        log "ERROR: Memory usage at ${usage}% (max: ${MAX_MEM_USAGE}%)"
        return 1
    fi
    
    log "Memory OK: ${usage}% used"
    return 0
}

cleanup_old_outputs() {
    local output_dir="${1:-.}"
    local retention_days="${2:-7}"
    
    log "Cleaning up outputs older than $retention_days days in $output_dir"
    
    local deleted=0
    
    # Delete old files
    while IFS= read -r -d '' file; do
        rm -f "$file"
        deleted=$((deleted + 1))
    done < <(find "$output_dir" -type f -mtime +"$retention_days" -print0 2>/dev/null)
    
    # Remove empty directories
    find "$output_dir" -type d -empty -delete 2>/dev/null || true
    
    log "Deleted $deleted old files"
}

enforce_limits() {
    # Set process limits (ignore errors if not permitted)
    ulimit -n 10000 2>/dev/null || true  # Max open files
}

# Main function
main() {
    local output_dir="${1:-.}"
    local auto_cleanup="${2:-false}"
    
    log "Checking resources..."
    
    if ! check_disk_space "$output_dir"; then
        if [[ "$auto_cleanup" == "true" ]]; then
            log "Attempting auto-cleanup..."
            cleanup_old_outputs "$output_dir" 3
            
            if ! check_disk_space "$output_dir"; then
                log "FATAL: Still insufficient disk space after cleanup"
                exit 3
            fi
        else
            exit 3
        fi
    fi
    
    if ! check_memory; then
        log "FATAL: Insufficient memory"
        exit 3
    fi
    
    enforce_limits
    
    log "All resource checks passed ✓"
}

main "$@"
