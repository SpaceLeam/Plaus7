#!/bin/bash
#
# Exit Code Standards for Recon Suite
#

# Standard exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_GENERAL_ERROR=1
readonly EXIT_INVALID_ARGS=2
readonly EXIT_RESOURCE_ERROR=3
readonly EXIT_NETWORK_ERROR=4
readonly EXIT_TIMEOUT=5
readonly EXIT_PERMISSION_ERROR=6
readonly EXIT_CONFIG_ERROR=7
readonly EXIT_PARTIAL_SUCCESS=8
readonly EXIT_USER_INTERRUPT=130

# Exit with code and optional message
exit_with_code() {
    local code="$1"
    local message="${2:-}"
    
    if [[ -n "$message" ]]; then
        case "$code" in
            0) echo "[SUCCESS] $message" ;;
            *) echo "[ERROR] $message" >&2 ;;
        esac
    fi
    
    exit "$code"
}

# Get description for exit code
describe_exit_code() {
    case "$1" in
        0) echo "Success" ;;
        1) echo "General error" ;;
        2) echo "Invalid arguments" ;;
        3) echo "Resource exhaustion (disk/memory)" ;;
        4) echo "Network error" ;;
        5) echo "Timeout" ;;
        6) echo "Permission denied" ;;
        7) echo "Configuration error" ;;
        8) echo "Partial success (some stages failed)" ;;
        130) echo "User interrupt (Ctrl+C)" ;;
        *) echo "Unknown error ($1)" ;;
    esac
}
