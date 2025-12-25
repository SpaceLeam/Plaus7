#!/bin/bash
#
# Cleanup - Removes temporary files and old scan data
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
RETENTION_DAYS="${1:-7}"
DRY_RUN="${2:-false}"

log() {
    echo "[cleanup] $(date '+%H:%M:%S') $*"
}

cleanup_temp_files() {
    log "Cleaning temporary files..."
    
    local count=0
    
    # Remove temp files in /tmp
    for pattern in "recon_*" "*.tmp" "*.temp"; do
        while IFS= read -r -d '' file; do
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "Would delete: $file"
            else
                rm -f "$file"
            fi
            count=$((count + 1))
        done < <(find /tmp -maxdepth 1 -name "$pattern" -user "$USER" -print0 2>/dev/null)
    done
    
    log "Cleaned $count temp files"
}

cleanup_old_scans() {
    log "Cleaning scans older than $RETENTION_DAYS days..."
    
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log "Output directory not found: $OUTPUT_DIR"
        return 0
    fi
    
    local count=0
    local size_before=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1 || echo "0")
    
    # Archive old scan directories
    for dir in "$OUTPUT_DIR"/*/; do
        if [[ -d "$dir" ]]; then
            local dir_age=$(find "$dir" -maxdepth 0 -mtime +"$RETENTION_DAYS" 2>/dev/null)
            
            if [[ -n "$dir_age" ]]; then
                local dirname=$(basename "$dir")
                
                if [[ "$DRY_RUN" == "true" ]]; then
                    echo "Would archive: $dirname"
                else
                    # Compress to archive
                    local archive="${OUTPUT_DIR}/archive/${dirname}_$(date +%Y%m%d).tar.gz"
                    mkdir -p "${OUTPUT_DIR}/archive"
                    
                    tar -czf "$archive" -C "$OUTPUT_DIR" "$dirname" 2>/dev/null && \
                    rm -rf "$dir"
                    
                    log "Archived: $dirname"
                fi
                count=$((count + 1))
            fi
        fi
    done
    
    # Delete very old archives (3x retention)
    local archive_retention=$((RETENTION_DAYS * 3))
    find "${OUTPUT_DIR}/archive" -name "*.tar.gz" -mtime +"$archive_retention" -delete 2>/dev/null || true
    
    # Clean raw directory
    find "${OUTPUT_DIR}/raw" -type f -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
    
    # Remove empty directories
    find "$OUTPUT_DIR" -type d -empty -delete 2>/dev/null || true
    
    local size_after=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1 || echo "0")
    log "Archived $count old scans ($size_before → $size_after)"
}

cleanup_state_files() {
    log "Cleaning state files..."
    
    # Remove old state files
    rm -f "${SCRIPT_DIR}/.recon_state.old" 2>/dev/null || true
    rm -f "${SCRIPT_DIR}/.watchdog.pid" 2>/dev/null || true
    
    # Clean old state files (completed scans)
    if [[ -f "${SCRIPT_DIR}/.recon_state" ]]; then
        local state_age=$(find "${SCRIPT_DIR}/.recon_state" -mtime +1 2>/dev/null)
        if [[ -n "$state_age" ]]; then
            # State file is old, likely from completed/failed scan
            mv "${SCRIPT_DIR}/.recon_state" "${SCRIPT_DIR}/.recon_state.old" 2>/dev/null || true
        fi
    fi
    
    log "State files cleaned"
}

show_usage() {
    cat << EOF
Usage: $(basename "$0") [retention_days] [--dry-run]

Options:
    retention_days  Days to keep scan data (default: 7)
    --dry-run       Show what would be deleted without deleting

Examples:
    $(basename "$0")           # Clean with 7-day retention
    $(basename "$0") 14        # Clean with 14-day retention  
    $(basename "$0") 7 --dry-run  # Preview cleanup

EOF
}

main() {
    # Parse args
    for arg in "$@"; do
        case "$arg" in
            --dry-run|-n)
                DRY_RUN="true"
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            [0-9]*)
                RETENTION_DAYS="$arg"
                ;;
        esac
    done
    
    log "Starting cleanup (retention: ${RETENTION_DAYS}d, dry-run: ${DRY_RUN})"
    
    cleanup_temp_files
    cleanup_old_scans
    cleanup_state_files
    
    # Run log rotation
    if [[ -x "${SCRIPT_DIR}/utils/log-rotator.sh" ]]; then
        "${SCRIPT_DIR}/utils/log-rotator.sh"
    fi
    
    log "Cleanup complete ✓"
}

main "$@"
