#!/bin/bash
#
# Watchdog - Monitors pipeline health and restarts on failure
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${SCRIPT_DIR}/.watchdog.pid"
STATE_FILE="${SCRIPT_DIR}/.recon_state"
MAX_FAILURES=3
FAILURE_COUNT=0
CHECK_INTERVAL=60
STALL_TIMEOUT=600  # 10 minutes without state change = stalled

log() {
    echo "[watchdog] $(date '+%H:%M:%S') $*"
}

get_state_mtime() {
    if [[ -f "$STATE_FILE" ]]; then
        stat -c %Y "$STATE_FILE" 2>/dev/null || stat -f %m "$STATE_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

check_stalled() {
    local last_mtime=$(get_state_mtime)
    local now=$(date +%s)
    local age=$((now - last_mtime))
    
    if [[ $age -gt $STALL_TIMEOUT ]]; then
        return 0  # Stalled
    fi
    return 1  # Active
}

kill_stalled_process() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "Killing stalled process $pid"
            kill -TERM "$pid" 2>/dev/null || true
            sleep 5
            kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
}

monitor_pipeline() {
    local target="$1"
    shift
    local args=("$@")
    
    log "Starting watchdog for target: $target"
    
    # Initial start
    "${SCRIPT_DIR}/recon-master.sh" "$target" "${args[@]}" &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    log "Started process $pid"
    
    while true; do
        sleep "$CHECK_INTERVAL"
        
        if [[ -f "$PID_FILE" ]]; then
            local pid=$(cat "$PID_FILE")
            
            # Check if process is alive
            if ! kill -0 "$pid" 2>/dev/null; then
                # Process died
                FAILURE_COUNT=$((FAILURE_COUNT + 1))
                
                if [[ $FAILURE_COUNT -ge $MAX_FAILURES ]]; then
                    log "Max failures ($MAX_FAILURES) reached, exiting"
                    exit 1
                fi
                
                log "Process died, restarting (attempt $FAILURE_COUNT/$MAX_FAILURES)"
                "${SCRIPT_DIR}/recon-master.sh" "$target" --resume "${args[@]}" &
                pid=$!
                echo "$pid" > "$PID_FILE"
                log "Restarted as process $pid"
                continue
            fi
            
            # Check if stalled
            if check_stalled; then
                log "Process appears stalled, restarting..."
                kill_stalled_process
                
                FAILURE_COUNT=$((FAILURE_COUNT + 1))
                if [[ $FAILURE_COUNT -ge $MAX_FAILURES ]]; then
                    log "Max failures reached after stall, exiting"
                    exit 1
                fi
                
                "${SCRIPT_DIR}/recon-master.sh" "$target" --resume "${args[@]}" &
                pid=$!
                echo "$pid" > "$PID_FILE"
                log "Restarted after stall as process $pid"
            fi
        fi
    done
}

cleanup() {
    log "Watchdog shutting down"
    kill_stalled_process
    rm -f "$PID_FILE"
}

trap cleanup EXIT INT TERM

# Usage check
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target> [recon-master options...]"
    echo "Example: $0 example.com -t 200 -v"
    exit 1
fi

monitor_pipeline "$@"
