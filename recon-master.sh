#!/bin/bash
#
# Smart Recon Automation Suite 2025
# Main Orchestrator Script
#
# Usage: ./recon-master.sh <domain> [options]
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/settings.yaml"
STATE_FILE="${SCRIPT_DIR}/.recon_state"
LOG_DIR="${SCRIPT_DIR}/output/logs"
LOG_FILE="${LOG_DIR}/recon_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default settings
THREADS=100
TIMEOUT=30
VERBOSE=false
RESUME=false

# =============================================================================
# PIPELINE STAGES
# =============================================================================

STAGES=(
    "subdomain_enum"
    "dns_resolution"
    "port_scanning"
    "http_probing"
    "content_discovery"
    "pattern_detection"
    "vulnerability_analysis"
    "report_generation"
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[DONE]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" | tee -a "$LOG_FILE"
}

show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ____                        ____        _ _       
 |  _ \ ___  ___ ___  _ __   / ___| _   _(_) |_ ___ 
 | |_) / _ \/ __/ _ \| '_ \  \___ \| | | | | __/ _ \
 |  _ <  __/ (_| (_) | | | |  ___) | |_| | | ||  __/
 |_| \_\___|\___\___/|_| |_| |____/ \__,_|_|\__\___|
                                                    
             Smart Recon Automation Suite 2025
EOF
    echo -e "${NC}"
}

show_usage() {
    cat << EOF
Usage: $(basename "$0") <domain> [options]

Options:
    -t, --threads NUM     Number of concurrent threads (default: 100)
    -T, --timeout SECS    Timeout in seconds (default: 30)
    -r, --resume          Resume from last checkpoint
    -v, --verbose         Enable verbose output
    -c, --config FILE     Custom config file
    -o, --output DIR      Output directory
    -h, --help            Show this help message

Examples:
    $(basename "$0") example.com
    $(basename "$0") example.com -t 200 -v
    $(basename "$0") example.com --resume

EOF
}

# =============================================================================
# STATE MANAGEMENT
# =============================================================================

save_state() {
    local stage="$1"
    local status="$2"
    echo "${stage}:${status}:$(date -Iseconds)" >> "$STATE_FILE"
}

get_last_completed_stage() {
    if [[ -f "$STATE_FILE" ]]; then
        grep ":completed:" "$STATE_FILE" | tail -1 | cut -d: -f1
    fi
}

is_stage_completed() {
    local stage="$1"
    if [[ -f "$STATE_FILE" ]]; then
        grep -q "^${stage}:completed:" "$STATE_FILE"
    else
        return 1
    fi
}

clear_state() {
    rm -f "$STATE_FILE"
}

# =============================================================================
# PROGRESS TRACKING
# =============================================================================

show_progress() {
    local current="$1"
    local total="$2"
    local stage="$3"
    local width=40
    
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\r${CYAN}[%${filled}s%${empty}s]${NC} %3d%% | Stage: %s" \
        "$(printf '=%.0s' $(seq 1 $filled))" "" "$percent" "$stage"
}

# =============================================================================
# STAGE EXECUTION
# =============================================================================

execute_stage() {
    local stage="$1"
    
    case "$stage" in
        subdomain_enum)
            run_subdomain_enumeration
            ;;
        dns_resolution)
            run_dns_resolution
            ;;
        port_scanning)
            run_port_scanning
            ;;
        http_probing)
            run_http_probing
            ;;
        content_discovery)
            run_content_discovery
            ;;
        pattern_detection)
            run_pattern_detection
            ;;
        vulnerability_analysis)
            run_vulnerability_analysis
            ;;
        report_generation)
            run_report_generation
            ;;
        *)
            log_error "Unknown stage: $stage"
            return 1
            ;;
    esac
}

# =============================================================================
# RECON STAGES IMPLEMENTATION
# =============================================================================

run_subdomain_enumeration() {
    log_info "Starting subdomain enumeration for $TARGET"
    
    local output_file="${OUTPUT_DIR}/raw/subdomains.txt"
    local json_output="${OUTPUT_DIR}/raw/subdomains.json"
    
    mkdir -p "${OUTPUT_DIR}/raw"
    
    # Run subfinder if available
    if command -v subfinder &> /dev/null; then
        log_info "Running subfinder..."
        "${SCRIPT_DIR}/modules/subfinder-wrapper.sh" "$TARGET" "$output_file" "$THREADS"
    fi
    
    # Run our Go scanner
    if [[ -x "${SCRIPT_DIR}/scanner/scanner" ]]; then
        log_info "Running Go subdomain scanner..."
        "${SCRIPT_DIR}/scanner/scanner" subdomain -d "$TARGET" \
            -c "$THREADS" \
            -passive \
            -o "$json_output" 2>&1 | tee -a "$LOG_FILE"
        
        # Extract subdomains from JSON and append to txt
        if [[ -f "$json_output" ]]; then
            jq -r '.[].subdomain' "$json_output" >> "$output_file" 2>/dev/null || true
        fi
    fi
    
    # Deduplicate
    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
        local count=$(wc -l < "$output_file")
        log_success "Found $count unique subdomains"
    else
        log_warning "No subdomains found"
        touch "$output_file"
    fi
}

run_dns_resolution() {
    log_info "Starting DNS resolution"
    
    local input_file="${OUTPUT_DIR}/raw/subdomains.txt"
    local output_file="${OUTPUT_DIR}/raw/resolved.txt"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log_warning "No subdomains to resolve"
        touch "$output_file"
        return 0
    fi
    
    # Use dnsx if available
    if command -v dnsx &> /dev/null; then
        log_info "Running dnsx..."
        dnsx -l "$input_file" -a -resp -silent -t "$THREADS" | \
            cut -d' ' -f1 | sort -u > "$output_file"
    else
        # Fallback: simple dig resolution
        log_info "Running basic DNS resolution..."
        while read -r subdomain; do
            if host "$subdomain" &>/dev/null; then
                echo "$subdomain" >> "$output_file"
            fi
        done < "$input_file"
    fi
    
    if [[ -f "$output_file" ]]; then
        local count=$(wc -l < "$output_file")
        log_success "Resolved $count live hosts"
    fi
}

run_port_scanning() {
    log_info "Starting port scanning"
    
    local input_file="${OUTPUT_DIR}/raw/resolved.txt"
    local output_file="${OUTPUT_DIR}/raw/ports.json"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log_warning "No hosts to scan"
        echo "[]" > "$output_file"
        return 0
    fi
    
    # Use naabu if available
    if command -v naabu &> /dev/null; then
        log_info "Running naabu..."
        naabu -list "$input_file" -top-ports 1000 -silent -json -o "$output_file"
    elif [[ -x "${SCRIPT_DIR}/scanner/scanner" ]]; then
        log_info "Running Go port scanner..."
        "${SCRIPT_DIR}/scanner/scanner" portscan -t "$input_file" \
            -p "1-1000" \
            -c "$THREADS" \
            -o "$output_file" 2>&1 | tee -a "$LOG_FILE"
    fi
    
    log_success "Port scanning complete"
}

run_http_probing() {
    log_info "Starting HTTP probing"
    
    local input_file="${OUTPUT_DIR}/raw/resolved.txt"
    local output_file="${OUTPUT_DIR}/raw/alive.json"
    local alive_urls="${OUTPUT_DIR}/raw/alive_urls.txt"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log_warning "No hosts to probe"
        echo "[]" > "$output_file"
        return 0
    fi
    
    # Use httpx if available
    if command -v httpx &> /dev/null; then
        log_info "Running httpx..."
        "${SCRIPT_DIR}/modules/httpx-wrapper.sh" "$input_file" "$output_file" "$THREADS"
        
        # Extract URLs
        jq -r '.url' "$output_file" 2>/dev/null > "$alive_urls" || true
    elif [[ -x "${SCRIPT_DIR}/scanner/scanner" ]]; then
        log_info "Running Go HTTP prober..."
        "${SCRIPT_DIR}/scanner/scanner" probe -l "$input_file" \
            -c "$THREADS" \
            -o "$output_file" 2>&1 | tee -a "$LOG_FILE"
        
        jq -r '.[].url' "$output_file" 2>/dev/null > "$alive_urls" || true
    fi
    
    if [[ -f "$alive_urls" ]]; then
        local count=$(wc -l < "$alive_urls")
        log_success "Found $count alive HTTP endpoints"
    fi
}

run_content_discovery() {
    log_info "Starting content discovery"
    
    local input_file="${OUTPUT_DIR}/raw/alive_urls.txt"
    local output_dir="${OUTPUT_DIR}/raw/crawled"
    
    mkdir -p "$output_dir"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log_warning "No URLs to crawl"
        return 0
    fi
    
    # Use katana if available
    if command -v katana &> /dev/null; then
        log_info "Running katana..."
        "${SCRIPT_DIR}/modules/katana-wrapper.sh" "$input_file" "$output_dir/endpoints.txt"
    fi
    
    log_success "Content discovery complete"
}

run_pattern_detection() {
    log_info "Starting pattern detection"
    
    local output_file="${OUTPUT_DIR}/filtered/findings.json"
    mkdir -p "${OUTPUT_DIR}/filtered"
    
    # Run pattern matcher on crawled content
    if [[ -x "${SCRIPT_DIR}/detectors/pattern-matcher.sh" ]]; then
        "${SCRIPT_DIR}/detectors/pattern-matcher.sh" \
            "${OUTPUT_DIR}/raw" \
            "${SCRIPT_DIR}/config/patterns" \
            "$output_file"
    fi
    
    log_success "Pattern detection complete"
}

run_vulnerability_analysis() {
    log_info "Starting vulnerability analysis"
    
    local input_file="${OUTPUT_DIR}/raw/alive_urls.txt"
    local output_file="${OUTPUT_DIR}/vulnerabilities/nuclei.json"
    
    mkdir -p "${OUTPUT_DIR}/vulnerabilities"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        log_warning "No URLs for vulnerability scanning"
        return 0
    fi
    
    # Use nuclei if available
    if command -v nuclei &> /dev/null; then
        log_info "Running nuclei..."
        "${SCRIPT_DIR}/modules/nuclei-wrapper.sh" "$input_file" "$output_file"
    fi
    
    log_success "Vulnerability analysis complete"
}

run_report_generation() {
    log_info "Generating reports"
    
    local report_dir="${OUTPUT_DIR}/reports"
    mkdir -p "$report_dir"
    
    # Generate reports using reporter utility
    if [[ -x "${SCRIPT_DIR}/utils/reporter.sh" ]]; then
        "${SCRIPT_DIR}/utils/reporter.sh" \
            "$OUTPUT_DIR" \
            "$report_dir" \
            "$TARGET"
    fi
    
    log_success "Reports generated in $report_dir"
}

# =============================================================================
# MAIN PIPELINE
# =============================================================================

run_pipeline() {
    local start_idx=0
    local total_stages=${#STAGES[@]}
    
    # Find resume point if resuming
    if [[ "$RESUME" == true ]]; then
        local last_completed=$(get_last_completed_stage)
        if [[ -n "$last_completed" ]]; then
            for i in "${!STAGES[@]}"; do
                if [[ "${STAGES[$i]}" == "$last_completed" ]]; then
                    start_idx=$((i + 1))
                    log_info "Resuming from stage: ${STAGES[$start_idx]:-complete}"
                    break
                fi
            done
        fi
    else
        clear_state
    fi
    
    # Execute pipeline
    for ((i=start_idx; i<total_stages; i++)); do
        local stage="${STAGES[$i]}"
        
        show_progress $((i + 1)) "$total_stages" "$stage"
        echo ""
        
        log_info "=== Stage $((i + 1))/$total_stages: $stage ==="
        save_state "$stage" "running"
        
        if execute_stage "$stage"; then
            save_state "$stage" "completed"
            log_success "Stage $stage completed"
        else
            save_state "$stage" "failed"
            log_error "Stage $stage failed"
            return 1
        fi
    done
    
    echo ""
    log_success "Pipeline completed successfully!"
}

# =============================================================================
# CLEANUP
# =============================================================================

cleanup() {
    log_info "Cleaning up..."
    # Remove temporary files
    rm -f /tmp/recon_$$_*
}

trap cleanup EXIT

# =============================================================================
# MAIN
# =============================================================================

main() {
    show_banner
    
    # Parse arguments
    if [[ $# -lt 1 ]]; then
        show_usage
        exit 1
    fi
    
    TARGET="$1"
    shift
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -T|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -r|--resume)
                RESUME=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Set default output directory
    OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output/${TARGET}}"
    
    # Create directories
    mkdir -p "$OUTPUT_DIR" "$LOG_DIR"
    
    log_info "Target: $TARGET"
    log_info "Output: $OUTPUT_DIR"
    log_info "Threads: $THREADS"
    log_info "Config: $CONFIG_FILE"
    
    # Run pipeline
    run_pipeline
    
    # Send notifications if configured
    if [[ -x "${SCRIPT_DIR}/utils/notifier.sh" ]]; then
        "${SCRIPT_DIR}/utils/notifier.sh" \
            "Recon completed for $TARGET" \
            "$OUTPUT_DIR/reports"
    fi
}

main "$@"
