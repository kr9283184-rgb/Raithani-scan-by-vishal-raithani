#!/bin/bash
# =============================================================================
# Raithani-Scan v1.2
# Advanced Vulnerability Scanner for Kali Linux
# Scans all possible vulnerabilities in a target URL using multiple techniques
# with WAF bypass, custom payloads, and integrated Kali tools.
# Now with Port Exploitation (--exploit) and Bug Bounty modules (--bugbounty)
#
# Usage: ./raithani-scan.sh -t <target-url> [options]
# =============================================================================

# Source library files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for lib in "$SCRIPT_DIR"/lib/*.sh; do
    [[ -f "$lib" ]] && source "$lib"
done

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
    # Initialize (parses args, validates target, checks deps)
    init "$@"
    
    # Create output structure
    mkdir -p "$OUTPUT_DIR/evidence"
    mkdir -p "$OUTPUT_DIR/vuln_checks"
    mkdir -p "$OUTPUT_DIR/exploitation"
    mkdir -p "$OUTPUT_DIR/2fa_bypass"
    
    # ============ PHASE 1: WAF Detection ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "waf" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: WAF Detection — SKIPPED (--skip)"
    elif [[ "$WAF_DETECTION_ENABLED" == "true" ]]; then
        detect_waf "$TARGET_URL"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: WAF Detection — SKIPPED"
    fi
    
    # ============ PHASE 2: Reconnaissance ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "recon" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Reconnaissance — SKIPPED (--skip)"
    else
        run_recon "$TARGET_URL" "$TARGET_DOMAIN" "$OUTPUT_DIR"
    fi
    
    # ============ PHASE 3: Port & Service Scanning ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "port-scan" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Port & Service Scanning — SKIPPED (--skip)"
    elif [[ "$SCAN_LEVEL" -ge 1 ]]; then
        run_port_scan "$TARGET_DOMAIN" "$OUTPUT_DIR"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Port & Service Scanning — SKIPPED (level 0)"
    fi
    
    # ============ PHASE 4: Web Enumeration ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "web-enum" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Web Enumeration — SKIPPED (--skip)"
    elif [[ "$SCAN_LEVEL" -ge 1 ]]; then
        run_web_enum "$TARGET_URL" "$OUTPUT_DIR"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Web Enumeration — SKIPPED (level 0)"
    fi
    
    # ============ PHASE 5: 2FA Bypass Check ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "2fa" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: 2FA Bypass — SKIPPED (--skip)"
    elif [[ "$TWOFA_BYPASS_ENABLED" == "true" ]]; then
        run_2fa_bypass "$TARGET_URL" "$OUTPUT_DIR"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: 2FA Bypass — SKIPPED"
    fi
    
    # ============ PHASE 6: Bug Bounty Testing ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "bugbounty" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Bug Bounty — SKIPPED (--skip)"
    elif [[ "$BUG_BOUNTY_ENABLED" == "true" ]]; then
        run_bugbounty_checks "$TARGET_URL" "$TARGET_DOMAIN" "$OUTPUT_DIR"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Bug Bounty — SKIPPED"
    fi
    
    # ============ PHASE 7: Vulnerability Checks ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "vuln" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Vulnerability Checks — SKIPPED (--skip)"
    else
        run_vuln_checks "$TARGET_URL" "$OUTPUT_DIR"
    fi
    
    # ============ PHASE 8: Port Exploitation ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "exploit" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Port Exploitation — SKIPPED (--skip)"
    elif [[ "$PORT_EXPLOIT_ENABLED" == "true" ]]; then
        run_port_exploitation "$TARGET_DOMAIN" "$OUTPUT_DIR"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Port Exploitation — SKIPPED"
    fi
    
    # ============ PHASE 9: Tool Integration ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "tools" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Tool Integration — SKIPPED (--skip)"
    elif [[ "$TOOL_INTEGRATION_ENABLED" != "false" ]] && [[ "$SCAN_LEVEL" -ge 1 ]]; then
        run_tool_integration "$TARGET_URL" "$OUTPUT_DIR"
    else
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Tool Integration — SKIPPED"
    fi
    
    # ============ PHASE 10: Report Generation ============
    PHASE_NUM=$((PHASE_NUM + 1))
    if is_phase_skipped "report" "$PHASE_NUM"; then
        log_info "Phase $PHASE_NUM/$TOTAL_PHASES: Report Generation — SKIPPED (--skip)"
    else
        generate_reports "$TARGET_URL" "$TARGET_DOMAIN" "$OUTPUT_DIR"
    fi
    
    # Cleanup checkpoint
    rm -f "$OUTPUT_DIR/.checkpoint"
    
    log_ok "Raithani-Scan completed successfully!"
}

# Trap for cleanup on interrupt
cleanup() {
    echo ""
    log_warn "Scan interrupted by user"
    log_info "You can resume with --resume flag"
    save_checkpoint "$CURRENT_PHASE"
    exit 1
}

trap cleanup SIGINT SIGTERM

# Run main if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
