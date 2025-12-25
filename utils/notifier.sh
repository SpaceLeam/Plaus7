#!/bin/bash
#
# Notifier
# Sends notifications to Slack, Discord, or Telegram
#

set -euo pipefail

MESSAGE="${1:-Recon completed}"
REPORT_DIR="${2:-}"

# Load environment variables if .env exists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    source "$SCRIPT_DIR/.env"
fi

# Get from environment
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

send_slack() {
    local message="$1"
    
    if [[ -z "$SLACK_WEBHOOK" ]]; then
        return 0
    fi
    
    echo "[notifier] Sending Slack notification..."
    
    local payload=$(cat << EOF
{
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🔍 Recon Complete",
                "emoji": true
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "$message"
            }
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "📅 $(date '+%Y-%m-%d %H:%M:%S')"
                }
            ]
        }
    ]
}
EOF
)
    
    curl -s -X POST "$SLACK_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null
}

send_discord() {
    local message="$1"
    
    if [[ -z "$DISCORD_WEBHOOK" ]]; then
        return 0
    fi
    
    echo "[notifier] Sending Discord notification..."
    
    local payload=$(cat << EOF
{
    "embeds": [{
        "title": "🔍 Recon Complete",
        "description": "$message",
        "color": 3447003,
        "footer": {
            "text": "Smart Recon Suite"
        },
        "timestamp": "$(date -Iseconds)"
    }]
}
EOF
)
    
    curl -s -X POST "$DISCORD_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null
}

send_telegram() {
    local message="$1"
    
    if [[ -z "$TELEGRAM_BOT_TOKEN" ]] || [[ -z "$TELEGRAM_CHAT_ID" ]]; then
        return 0
    fi
    
    echo "[notifier] Sending Telegram notification..."
    
    local text="🔍 *Recon Complete*

$message

📅 $(date '+%Y-%m-%d %H:%M:%S')"
    
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${text}" \
        -d "parse_mode=Markdown" > /dev/null
}

# Build message with stats if report dir provided
build_message() {
    local base_msg="$1"
    local msg="$base_msg"
    
    if [[ -n "$REPORT_DIR" ]] && [[ -f "$REPORT_DIR/report.json" ]]; then
        if command -v jq &> /dev/null; then
            local stats=$(jq -r '.statistics | "📊 Stats:\n• Subdomains: \(.subdomains_found)\n• Live Hosts: \(.live_hosts)\n• Open Ports: \(.open_ports)\n• Vulnerabilities: \(.vulnerabilities)"' "$REPORT_DIR/report.json" 2>/dev/null || echo "")
            if [[ -n "$stats" ]]; then
                msg="$base_msg

$stats"
            fi
        fi
    fi
    
    echo "$msg"
}

main() {
    local full_message=$(build_message "$MESSAGE")
    
    # Send to all configured channels
    send_slack "$full_message"
    send_discord "$full_message"
    send_telegram "$full_message"
    
    echo "[notifier] Notifications sent"
}

main
