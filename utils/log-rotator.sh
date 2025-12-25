#!/bin/bash
#
# Log Rotator - Manages log files
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${1:-${SCRIPT_DIR}/output/logs}"
MAX_SIZE_MB="${LOG_MAX_SIZE_MB:-100}"
MAX_AGE_DAYS="${LOG_RETENTION_DAYS:-7}"
COMPRESS="${2:-true}"

log() {
    echo "[log-rotator] $(date '+%H:%M:%S') $*"
}

rotate_logs() {
    if [[ ! -d "$LOG_DIR" ]]; then
        log "Log directory does not exist: $LOG_DIR"
        return 0
    fi
    
    log "Rotating logs in $LOG_DIR (max: ${MAX_SIZE_MB}MB, age: ${MAX_AGE_DAYS}d)"
    
    local rotated=0
    local deleted=0
    local compressed=0
    
    # Find and rotate logs larger than MAX_SIZE
    while IFS= read -r -d '' logfile; do
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local rotated_file="${logfile}.${timestamp}"
        
        mv "$logfile" "$rotated_file"
        touch "$logfile"  # Create new empty log
        
        if [[ "$COMPRESS" == "true" ]]; then
            gzip "$rotated_file" &
            compressed=$((compressed + 1))
        fi
        
        rotated=$((rotated + 1))
    done < <(find "$LOG_DIR" -name "*.log" -size +"${MAX_SIZE_MB}M" -print0 2>/dev/null)
    
    # Wait for background compressions
    wait
    
    # Delete old logs
    while IFS= read -r -d '' oldfile; do
        rm -f "$oldfile"
        deleted=$((deleted + 1))
    done < <(find "$LOG_DIR" -name "*.log*" -mtime +"$MAX_AGE_DAYS" -print0 2>/dev/null)
    
    # Compress old uncompressed rotated logs (older than 1 day)
    if [[ "$COMPRESS" == "true" ]]; then
        find "$LOG_DIR" -name "*.log.*" ! -name "*.gz" -mtime +1 -exec gzip {} \; 2>/dev/null || true
    fi
    
    log "Done: rotated=$rotated, compressed=$compressed, deleted=$deleted"
}

rotate_logs
