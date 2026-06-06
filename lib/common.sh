#!/bin/bash
# =============================================================================
# Raithani-Scan - Common Library
# Colors, logging, banner, argument parsing, dependency checking
# =============================================================================

# Colors
R="\033[1;31m"    # Red (CRITICAL)
G="\033[1;32m"    # Green (INFO/OK)
Y="\033[1;33m"    # Yellow (WARNING/HIGH)
B="\033[1;34m"    # Blue (phases)
M="\033[1;35m"    # Magenta (headers)
C="\033[1;36m"    # Cyan (scanning)
W="\033[1;37m"    # White (bold)
D="\033[0;37m"    # Dim gray
NC="\033[0m"      # No Color

# Global state
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=""
TARGET_DOMAIN=""
TARGET_URL=""
OUTPUT_DIR=""
SCAN_LEVEL=2
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
START_TIME=0
CURRENT_PHASE=""
PHASE_NUM=0
TOTAL_PHASES=10
PORT_EXPLOIT_ENABLED=false
BUG_BOUNTY_ENABLED=true
TWOFA_BYPASS_ENABLED=true
CDN_TYPE=""
SKIP_PHASES=()

# Severity counters
declare -i CRIT_COUNT=0 HIGH_COUNT=0 MED_COUNT=0 LOW_COUNT=0 INFO_COUNT=0

# Findings array
FINDINGS=()
WAF_DETECTED=""
WAF_TYPE=""

# Load config
load_config() {
    local config_file="$SCRIPT_DIR/config/default.conf"
    if [[ -f "$config_file" ]]; then
        source "$config_file"
    fi
}

# Banner
show_banner() {
    echo -e "${R}"
    echo "██████╗  █████╗ ██╗████████╗██╗  ██╗ █████╗ ███╗   ██╗██╗"
    echo "██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║██╔══██╗████╗  ██║██║"
    echo "██████╔╝███████║██║   ██║   ███████║███████║██╔██╗ ██║██║"
    echo "██╔══██╗██╔══██║██║   ██║   ██╔══██║██╔══██║██║╚██╗██║██║"
    echo "██║  ██║██║  ██║██║   ██║   ██║  ██║██║  ██║██║ ╚████║██║"
    echo "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝"
    echo -e "${W}       Vulnerability Scanner for Kali Linux${NC}"
    echo -e "${C}       [ Raithani-Scan v1.0 ]${NC}"
    echo ""
}

# Usage
show_usage() {
    echo "Usage: $0 -t <target-url> [options]"
    echo ""
    echo "Options:"
    echo "  -t <url>       Target URL (required) e.g., https://example.com"
    echo "  -o <dir>       Output directory (default: output/<domain>)"
    echo "  -l <1-3>       Scan level: 1=quick, 2=standard, 3=exhaustive"
    echo "  --quick        Alias for -l 1 (skip slow scans)"
    echo "  --no-tools     Custom HTTP checks only, skip external tools"
    echo "  --danger-mode  Enable destructive payload testing"
    echo "  --exploit      Enable port exploitation phase (tests open ports for"
    echo "                 weak configs, default creds, and brute-force)"
    echo "  --bugbounty    Enable advanced bug bounty testing (subdomain takeover,"
    echo "                 SAST/DAST, cloud buckets, OAuth/SSO, Google dorking,"
    echo "                 origin IP discovery, HTTP smuggling, race conditions)"
    echo "  --skip-2fa     Skip 2FA bypass check phase"
    echo "  --skip-bugbounty Skip bug bounty testing phase"
    echo "  --skip <list>  Skip phases by name or number (e.g. --skip waf,recon,2fa)"
    echo "                 Names: waf, recon, port-scan, web-enum, 2fa, bugbounty,"
    echo "                 vuln, exploit, tools, report"
    echo "  --resume       Resume from last checkpoint"
    echo "  --ignore-robots Ignore robots.txt restrictions"
    echo "  -h, --help     Show this help"
    echo ""
    echo "Example:"
    echo "  $0 -t https://example.com -l 3 -o ~/scan-results"
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t)
                TARGET="$2"
                shift 2
                ;;
            -o)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -l)
                SCAN_LEVEL="$2"
                shift 2
                ;;
            --quick)
                SCAN_LEVEL=1
                shift
                ;;
            --no-tools)
                TOOL_INTEGRATION_ENABLED=false
                shift
                ;;
            --danger-mode)
                DANGER_MODE=true
                shift
                ;;
            --exploit)
                PORT_EXPLOIT_ENABLED=true
                shift
                ;;
            --bugbounty)
                BUG_BOUNTY_ENABLED=true
                shift
                ;;
            --skip-2fa)
                TWOFA_BYPASS_ENABLED=false
                shift
                ;;
            --skip-bugbounty)
                BUG_BOUNTY_ENABLED=false
                shift
                ;;
            --skip)
                IFS=',' read -ra parsed <<< "$2"
                SKIP_PHASES+=("${parsed[@]}")
                shift 2
                ;;
            --resume)
                RESUME_MODE=true
                shift
                ;;
            --ignore-robots)
                IGNORE_ROBOTS=true
                shift
                ;;
            -h|--help)
                show_banner
                show_usage
                exit 0
                ;;
            *)
                echo -e "${R}[!] Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done

    # Interactive target input if no -t provided
    if [[ -z "$TARGET" ]]; then
        echo ""
        echo -e "${Y}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${Y}║${NC} ${W}No target specified — entering interactive mode             ${NC}${Y}║${NC}"
        echo -e "${Y}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -en "${C}[?] Enter target URL:${NC} "
        read -r TARGET
        TARGET=$(echo "$TARGET" | xargs)  # trim whitespace
        if [[ -z "$TARGET" ]]; then
            echo -e "${R}[!] No target entered. Exiting.${NC}"
            show_usage
            exit 1
        fi
    fi

    # Normalize target
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        TARGET="https://$TARGET"
    fi
    TARGET_URL="$TARGET"
    TARGET_DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | sed 's|/.*$||')
    
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$SCRIPT_DIR/output/${TARGET_DOMAIN}_${TIMESTAMP}"
    fi
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/evidence"
}

# Logging functions
log_banner() {
    echo ""
    echo -e "${M}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${M}│${NC} ${B}$1${NC}"
    echo -e "${M}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

log_step() {
    echo -e "${C}[*]${NC} $1"
}

log_ok() {
    echo -e "${G}[+]${NC} $1"
}

log_warn() {
    echo -e "${Y}[!]${NC} $1"
}

log_error() {
    echo -e "${R}[x]${NC} $1"
}

log_critical() {
    echo -e "${R}[CRIT]${NC} $1"
}

log_info() {
    echo -e "${D}[i]${NC} $1"
}

log_high() {
    echo -e "${Y}[HIGH]${NC} $1"
}

log_medium() {
    echo -e "${Y}[MED]${NC} $1"
}

log_low() {
    echo -e "${D}[LOW]${NC} $1"
}

log_separator() {
    echo -e "${D}───────────────────────────────────────────────────────────────${NC}"
}

# Finding recording
record_finding() {
    local severity="$1"
    local title="$2"
    local detail="$3"
    local remediation="$4"
    local evidence_file="$5"

    FINDINGS+=("$severity|$title|$detail|$remediation|$evidence_file")
    case "$severity" in
        CRITICAL) CRIT_COUNT+=1 ;;
        HIGH)     HIGH_COUNT+=1 ;;
        MEDIUM)   MED_COUNT+=1 ;;
        LOW)      LOW_COUNT+=1 ;;
        INFO)     INFO_COUNT+=1 ;;
    esac

    # Print to terminal
    case "$severity" in
        CRITICAL)
            echo -e "  ${R}[CRITICAL]${NC} $title"
            echo -e "  ${D}└─ $detail${NC}"
            ;;
        HIGH)
            echo -e "  ${Y}[HIGH]${NC} $title"
            echo -e "  ${D}└─ $detail${NC}"
            ;;
        MEDIUM)
            echo -e "  ${Y}[MEDIUM]${NC} $title"
            ;;
        LOW)
            echo -e "  ${D}[LOW]${NC} $title"
            ;;
        INFO)
            echo -e "  ${D}[INFO]${NC} $title"
            ;;
    esac

    # Save to evidence file
    if [[ -n "$evidence_file" && -f "$evidence_file" && -n "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR/evidence/"
        cp "$evidence_file" "$OUTPUT_DIR/evidence/"
    fi
}

# Phase definitions for progress tracking
PHASE_NAMES=(
    "WAF Detection & CDN Fingerprinting"
    "Reconnaissance (DNS, SSL, Subdomains)"
    "Port & Service Scanning"
    "Web Enumeration (dirs, APIs, forms)"
    "2FA Bypass Check"
    "Bug Bounty Testing (takeover, dorking, OAuth)"
    "Vulnerability Checks (SQLi, XSS, etc.)"
    "Port Exploitation"
    "Tool Integration (sqlmap, nikto, etc.)"
    "Report Generation"
)

# Progress preview dashboard
show_progress() {
    local current="$1"
    local status="${2:-in_progress}"
    local elapsed=$(get_elapsed)
    local -i completed=0

    echo ""
    echo -e "${B}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${B}║${NC} ${W}Scan Progress Dashboard${NC}                                  ${B}║${NC}"
    echo -e "${B}║${NC} Elapsed: ${C}$elapsed${NC}  |  Target: ${W}$TARGET_DOMAIN${NC}                    ${B}║${NC}"
    echo -e "${B}╠═══════════════════════════════════════════════════════════════╣${NC}"

    for ((i=0; i<${#PHASE_NAMES[@]}; i++)); do
        local num=$((i+1))
        local name="${PHASE_NAMES[$i]}"
        local icon=""
        local color=""

        if [[ "$num" -lt "$current" ]]; then
            icon="✔"
            color="${G}"
            completed+=1
        elif [[ "$num" -eq "$current" ]]; then
            if [[ "$status" == "completed" ]]; then
                icon="✔"
                color="${G}"
                completed+=1
            elif [[ "$status" == "skipped" ]]; then
                icon="→"
                color="${D}"
            else
                icon="◉"
                color="${C}"
            fi
        else
            icon="·"
            color="${D}"
        fi

        printf "  ${B}║${NC} ${color}%s %-40s${NC}" "$icon" "$name"
        if [[ "$num" -eq "$current" && "$status" == "in_progress" ]]; then
            echo -e "${C} ◄── RUNNING${NC}"
        else
            echo ""
        fi
    done

    local -i pct=$((completed * 100 / ${#PHASE_NAMES[@]}))
    local -i bar_width=30
    local -i filled=$((pct * bar_width / 100))
    local -i empty=$((bar_width - filled))

    echo -e "  ${B}║${NC}                                                    "
    printf "  ${B}║${NC} Progress: ${W}[${NC}"
    for ((f=0; f<filled; f++)); do printf "${G}#${NC}"; done
    for ((e=0; e<empty; e++)); do printf "${D}·${NC}"; done
    echo -e "${W}]${NC} ${B}${pct}%${NC}  (${completed}/${#PHASE_NAMES[@]} phases)"

    # Findings summary
    echo -e "  ${B}║${NC} Findings: ${R}CRIT:${CRIT_COUNT:-0}${NC}  ${Y}HIGH:${HIGH_COUNT:-0}${NC}  ${Y}MED:${MED_COUNT:-0}${NC}  ${D}LOW:${LOW_COUNT:-0}${NC}  ${D}INFO:${INFO_COUNT:-0}${NC}"
    echo -e "  ${B}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Checkpoint system
save_checkpoint() {
    local phase="$1"
    local checkpoint_file="$OUTPUT_DIR/.checkpoint"
    cat > "$checkpoint_file" << EOF
PHASE=$phase
TIMESTAMP=$TIMESTAMP
TARGET=$TARGET
TARGET_DOMAIN=$TARGET_DOMAIN
TARGET_URL=$TARGET_URL
SCAN_LEVEL=$SCAN_LEVEL
CRIT_COUNT=$CRIT_COUNT
HIGH_COUNT=$HIGH_COUNT
MED_COUNT=$MED_COUNT
LOW_COUNT=$LOW_COUNT
INFO_COUNT=$INFO_COUNT
EOF
}

load_checkpoint() {
    local checkpoint_file="$OUTPUT_DIR/.checkpoint"
    if [[ -f "$checkpoint_file" ]]; then
        source "$checkpoint_file"
        log_info "Resuming from phase $PHASE"
        return 0
    fi
    return 1
}

# Dependency checking
check_deps() {
    local -a required_tools=("curl" "dig" "nmap" "whatweb" "whois")
    local -a missing=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing required tools: ${missing[*]}"
        echo -en "${Y}[?] Install missing tools? [Y/n]${NC} "
        read -r answer
        if [[ -z "$answer" || "$answer" =~ ^[Yy] ]]; then
            sudo apt update -qq
            sudo apt install -y "${missing[@]}"
            log_ok "Missing tools installed."
        else
            log_error "Cannot proceed without required tools."
            exit 1
        fi
    fi
}

check_optional_dep() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        log_warn "Optional tool '$tool' not found."
        echo -en "${Y}[?] Install $tool? [Y/n]${NC} "
        read -r answer
        if [[ -z "$answer" || "$answer" =~ ^[Yy] ]]; then
            sudo apt install -y "$tool" 2>/dev/null || pip3 install "$tool" 2>/dev/null
            if command -v "$tool" &>/dev/null; then
                log_ok "$tool installed."
                return 0
            else
                log_warn "Failed to install $tool. Skipping related checks."
                return 1
            fi
        else
            return 1
        fi
    fi
    return 0
}

# HTTP request helper
http_request() {
    local url="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    local content_type="${4:-}"

    local curl_args=(
        -s
        -k
        -L
        --max-time "$TIMEOUT"
        --retry "$MAX_RETRIES"
        --retry-delay 1
    )

    # User-Agent rotation
    if [[ "$USER_AGENT_ROTATION" == "true" ]]; then
        local ua_list=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/125.0.6422.113 Mobile Safari/537.36"
        )
        local rand_idx=$((RANDOM % ${#ua_list[@]}))
        curl_args+=(-H "User-Agent: ${ua_list[$rand_idx]}")
    else
        curl_args+=(-H "User-Agent: $USER_AGENT")
    fi

    curl_args+=(-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    curl_args+=(-H "Accept-Language: en-US,en;q=0.5")

    if [[ "$method" == "POST" ]]; then
        curl_args+=(-X POST)
        if [[ -n "$data" ]]; then
            curl_args+=(--data "$data")
        fi
        if [[ -n "$content_type" ]]; then
            curl_args+=(-H "Content-Type: $content_type")
        fi
    elif [[ "$method" == "PUT" ]]; then
        curl_args+=(-X PUT)
        if [[ -n "$data" ]]; then
            curl_args+=(--data "$data")
        fi
    fi

    curl "${curl_args[@]}" "$url" 2>/dev/null || echo ""
}

# Timing helper
start_timer() {
    START_TIME=$(date +%s)
}

get_elapsed() {
    local now=$(date +%s)
    local elapsed=$((now - START_TIME))
    printf "%02d:%02d" $((elapsed / 60)) $((elapsed % 60))
}

# Check if a phase should be skipped (matches --skip list by name or number)
is_phase_skipped() {
    local phase_name="$1"
    local phase_num="$2"
    local p
    for p in "${SKIP_PHASES[@]}"; do
        [[ "$p" == "$phase_name" || "$p" == "$phase_num" ]] && return 0
    done
    return 1
}

# Phase header
start_phase() {
    local phase_name="$1"
    CURRENT_PHASE="$phase_name"
    echo ""
    echo -e "${B}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${B}║${NC} Phase $PHASE_NUM/$TOTAL_PHASES: ${W}$phase_name${NC}${B}                     ║${NC}"
    echo -e "${B}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    start_timer
    save_checkpoint "$phase_name"
}

end_phase() {
    local elapsed=$(get_elapsed)
    log_ok "Phase completed in ${elapsed}"
    # Show progress dashboard after each phase
    show_progress "$PHASE_NUM" "completed"
}

# Validate target is reachable
validate_target() {
    log_step "Checking target reachability..."
    local response=$(http_request "$TARGET_URL" "GET")
    local http_code=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "$TARGET_URL" 2>/dev/null)
    
    if [[ -z "$response" ]]; then
        log_error "Target $TARGET_URL is not reachable!"
        exit 1
    fi
    
    if [[ "$http_code" == "000" ]]; then
        log_error "Connection refused or timeout for $TARGET_URL"
        exit 1
    fi
    
    log_ok "Target is reachable (HTTP $http_code)"
    echo "$http_code" > "$OUTPUT_DIR/http_code.txt"
    echo "$TARGET" > "$OUTPUT_DIR/target.txt"
    return 0
}

# Initialize everything
init() {
    load_config
    show_banner
    parse_args "$@"
    validate_target
    check_deps
    mkdir -p "$OUTPUT_DIR/evidence"
    log_info "Target: $TARGET_URL"
    log_info "Output: $OUTPUT_DIR"
    log_info "Level:  $SCAN_LEVEL"
    echo ""
}
