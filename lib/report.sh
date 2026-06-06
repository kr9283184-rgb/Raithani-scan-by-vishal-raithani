#!/bin/bash
# =============================================================================
# Raithani-Scan - Report Generation
# Terminal summary, HTML report, JSON output, CSV export
# =============================================================================

generate_reports() {
    start_phase "Report Generation"
    
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    local findings=("${FINDINGS[@]}")
    
    # Terminal summary
    generate_terminal_summary "$target_url" "$target_domain" "$output"
    
    # HTML report
    if [[ "$REPORT_HTML" == "true" ]]; then
        generate_html_report "$target_url" "$target_domain" "$output"
    fi
    
    # JSON report
    if [[ "$REPORT_JSON" == "true" ]]; then
        generate_json_report "$target_url" "$target_domain" "$output"
    fi
    
    # CSV report
    if [[ "$REPORT_CSV" == "true" ]]; then
        generate_csv_report "$target_url" "$target_domain" "$output"
    fi
    
    # Save findings array to file
    local findings_file="$output/findings.txt"
    printf '%s\n' "${findings[@]}" > "$findings_file"
    
    end_phase
}

generate_terminal_summary() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    
    echo ""
    echo -e "${M}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${M}║${NC}                    ${W}SCAN SUMMARY${NC}                        ${M}║${NC}"
    echo -e "${M}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${W}Target:${NC}      $target_url"
    echo -e "${W}Domain:${NC}      $target_domain"
    echo -e "${W}Scan Level:${NC}  $SCAN_LEVEL"
    echo -e "${W}Timestamp:${NC}   $(date)"
    echo -e "${W}Output Dir:${NC}  $output"
    echo ""
    
    if [[ "$WAF_DETECTED" == "true" ]]; then
        echo -e "${Y}WAF Detected:${NC} ${WAF_TYPE:-Yes}"
    else
        echo -e "${G}WAF:${NC} Not detected"
    fi
    
    echo ""
    echo -e "${R}  CRITICAL: ${CRIT_COUNT}${NC}"
    echo -e "${Y}  HIGH:     ${HIGH_COUNT}${NC}"
    echo -e "${Y}  MEDIUM:   ${MED_COUNT}${NC}"
    echo -e "${D}  LOW:      ${LOW_COUNT}${NC}"
    echo -e "${D}  INFO:     ${INFO_COUNT}${NC}"
    echo ""
    echo -e "${W}Total Findings: $((CRIT_COUNT + HIGH_COUNT + MED_COUNT + LOW_COUNT + INFO_COUNT))${NC}"
    echo ""
    
    # Print all findings grouped by severity
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
        echo -e "${M}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${M}│${NC}                  ${W}FINDINGS DETAILS${NC}                        ${M}│${NC}"
        echo -e "${M}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        # CRITICAL first
        for finding in "${FINDINGS[@]}"; do
            local severity="${finding%%|*}"
            if [[ "$severity" == "CRITICAL" ]]; then
                local rest="${finding#*|}"
                local title="${rest%%|*}"
                echo -e "${R}[CRITICAL]${NC} ${W}$title${NC}"
            fi
        done
        
        # HIGH
        for finding in "${FINDINGS[@]}"; do
            local severity="${finding%%|*}"
            if [[ "$severity" == "HIGH" ]]; then
                local rest="${finding#*|}"
                local title="${rest%%|*}"
                echo -e "${Y}[HIGH]${NC} ${W}$title${NC}"
            fi
        done
        
        # MEDIUM
        for finding in "${FINDINGS[@]}"; do
            local severity="${finding%%|*}"
            if [[ "$severity" == "MEDIUM" ]]; then
                local rest="${finding#*|}"
                local title="${rest%%|*}"
                echo -e "${Y}[MEDIUM]${NC} $title"
            fi
        done
        
        # LOW and INFO
        for finding in "${FINDINGS[@]}"; do
            local severity="${finding%%|*}"
            if [[ "$severity" == "LOW" || "$severity" == "INFO" ]]; then
                local rest="${finding#*|}"
                local title="${rest%%|*}"
                echo -e "${D}[$severity]${NC} $title"
            fi
        done
    fi
    
    echo ""
    echo -e "${G}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${G}│${NC} ${W}SCAN COMPLETE${NC}                                              ${G}│${NC}"
    echo -e "${G}│${NC} Reports saved to: ${C}$output${NC}                 ${G}│${NC}"
    echo -e "${G}│${NC}  - report.html (HTML report)                           ${G}│${NC}"
    echo -e "${G}│${NC}  - report.json (JSON data)                             ${G}│${NC}"
    echo -e "${G}│${NC}  - report.csv  (CSV summary)                           ${G}│${NC}"
    echo -e "${G}│${NC}  - findings.txt (Raw findings)                         ${G}│${NC}"
    echo -e "${G}│${NC}  - evidence/    (Evidence files)                       ${G}│${NC}"
    echo -e "${G}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

generate_html_report() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    local html_file="$output/report.html"
    
    log_step "Generating HTML report..."
    
    local total=$((CRIT_COUNT + HIGH_COUNT + MED_COUNT + LOW_COUNT + INFO_COUNT))
    
    # Build severity breakdown HTML
    local severity_html=""
    if [[ "$CRIT_COUNT" -gt 0 ]]; then
        severity_html+="<span style='color:#dc3545;font-weight:bold;margin-right:15px;'>CRITICAL: $CRIT_COUNT</span>"
    fi
    if [[ "$HIGH_COUNT" -gt 0 ]]; then
        severity_html+="<span style='color:#fd7e14;font-weight:bold;margin-right:15px;'>HIGH: $HIGH_COUNT</span>"
    fi
    if [[ "$MED_COUNT" -gt 0 ]]; then
        severity_html+="<span style='color:#ffc107;font-weight:bold;margin-right:15px;'>MEDIUM: $MED_COUNT</span>"
    fi
    if [[ "$LOW_COUNT" -gt 0 ]]; then
        severity_html+="<span style='color:#6c757d;font-weight:bold;margin-right:15px;'>LOW: $LOW_COUNT</span>"
    fi
    if [[ "$INFO_COUNT" -gt 0 ]]; then
        severity_html+="<span style='color:#17a2b8;font-weight:bold;margin-right:15px;'>INFO: $INFO_COUNT</span>"
    fi
    
    # Build findings HTML
    local findings_html=""
    local counter=1
    
    for finding in "${FINDINGS[@]}"; do
        local severity="${finding%%|*}"
        local rest="${finding#*|}"
        local title="${rest%%|*}"
        rest="${rest#*|}"
        local detail="${rest%%|*}"
        rest="${rest#*|}"
        local remediation="${rest%%|*}"
        
        local severity_color="#6c757d"
        case "$severity" in
            CRITICAL) severity_color="#dc3545" ;;
            HIGH)     severity_color="#fd7e14" ;;
            MEDIUM)   severity_color="#ffc107" ;;
            LOW)      severity_color="#6c757d" ;;
            INFO)     severity_color="#17a2b8" ;;
        esac
        
        findings_html+="
        <tr>
            <td style='padding:10px;border-bottom:1px solid #ddd;'>$counter</td>
            <td style='padding:10px;border-bottom:1px solid #ddd;'><span style='background:$severity_color;color:white;padding:3px 8px;border-radius:3px;font-size:12px;'>$severity</span></td>
            <td style='padding:10px;border-bottom:1px solid #ddd;font-weight:bold;'>$title</td>
            <td style='padding:10px;border-bottom:1px solid #ddd;color:#666;font-size:13px;'>$detail</td>
            <td style='padding:10px;border-bottom:1px solid #ddd;color:#28a745;font-size:13px;'>$remediation</td>
        </tr>"
        counter+=1
    done
    
    local waf_status="Not Detected"
    local waf_color="#28a745"
    if [[ "$WAF_DETECTED" == "true" ]]; then
        waf_status="${WAF_TYPE:-Detected}"
        waf_color="#dc3545"
    fi
    
    # Readme / additional info
    local scan_duration=$(get_elapsed)
    
    cat > "$html_file" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raithani-Scan Report - $target_domain</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Segoe UI',Arial,sans-serif; background:#f5f5f5; color:#333; line-height:1.6; }
        .container { max-width:1200px; margin:0 auto; padding:20px; }
        .header { background:linear-gradient(135deg,#1a1a2e,#16213e); color:white; padding:30px; border-radius:10px 10px 0 0; }
        .header h1 { font-size:24px; margin-bottom:5px; }
        .header p { color:#aaa; font-size:14px; }
        .stats { display:flex; gap:20px; padding:20px 30px; background:white; border:1px solid #ddd; border-top:0; }
        .stat-box { flex:1; text-align:center; padding:15px; background:#f8f9fa; border-radius:8px; }
        .stat-box .num { font-size:32px; font-weight:bold; }
        .stat-box .label { font-size:12px; color:#666; text-transform:uppercase; }
        .summary { padding:20px 30px; background:white; border:1px solid #ddd; border-top:0; }
        .summary h2 { margin-bottom:15px; font-size:18px; }
        .summary-grid { display:grid; grid-template-columns:1fr 1fr; gap:15px; }
        .summary-item { padding:10px; background:#f8f9fa; border-radius:5px; }
        .summary-item strong { display:inline-block; width:120px; }
        .findings { background:white; border:1px solid #ddd; border-top:0; border-radius:0 0 10px 10px; padding:20px 30px; }
        .findings h2 { margin-bottom:15px; font-size:18px; }
        table { width:100%; border-collapse:collapse; }
        th { text-align:left; padding:10px; background:#f8f9fa; border-bottom:2px solid #ddd; font-size:13px; text-transform:uppercase; }
        td { padding:10px; border-bottom:1px solid #eee; font-size:14px; }
        .waf-badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:12px; font-weight:bold; color:white; background:$waf_color; }
        .footer { text-align:center; padding:20px; color:#999; font-size:12px; }
        @media (max-width:768px) {
            .stats { flex-direction:column; }
            .summary-grid { grid-template-columns:1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Raithani-Scan Report</h1>
            <p>Vulnerability Assessment for <strong>$target_url</strong></p>
            <p style="margin-top:10px;font-size:13px;">Generated: $(date) | Scan Level: $SCAN_LEVEL | Duration: ${scan_duration}</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="num">$total</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-box" style="background:#fff3f3;">
                <div class="num" style="color:#dc3545;">$CRIT_COUNT</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-box" style="background:#fff8f0;">
                <div class="num" style="color:#fd7e14;">$HIGH_COUNT</div>
                <div class="label">High</div>
            </div>
            <div class="stat-box" style="background:#fffef0;">
                <div class="num" style="color:#ffc107;">$MED_COUNT</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-box" style="background:#f8f9fa;">
                <div class="num" style="color:#6c757d;">$LOW_COUNT</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-box" style="background:#f0f9ff;">
                <div class="num" style="color:#17a2b8;">$INFO_COUNT</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <div class="summary">
            <h2>📋 Scan Information</h2>
            <div class="summary-grid">
                <div class="summary-item"><strong>Target URL:</strong> $target_url</div>
                <div class="summary-item"><strong>Domain:</strong> $target_domain</div>
                <div class="summary-item"><strong>Scan Level:</strong> $SCAN_LEVEL</div>
                <div class="summary-item"><strong>WAF Status:</strong> <span class="waf-badge">$waf_status</span></div>
                <div class="summary-item"><strong>Timestamp:</strong> $(date)</div>
                <div class="summary-item"><strong>Output Directory:</strong> $output</div>
            </div>
            <div style="margin-top:15px;padding:10px;background:#f8f9fa;border-radius:5px;">
                <strong>Severity Distribution:</strong>
                <div style="margin-top:8px;">$severity_html</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>📝 Findings Details</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width:40px;">#</th>
                        <th style="width:100px;">Severity</th>
                        <th>Title</th>
                        <th>Details</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    $findings_html
                </tbody>
            </table>
            
            <div style="margin-top:30px;padding:15px;background:#fff3cd;border-radius:5px;border:1px solid #ffc107;">
                <strong>⚠️ Disclaimer:</strong> This report was generated by Raithani-Scan for security assessment purposes. 
                Findings should be verified manually before taking action. Only scan targets you own or have 
                explicit permission to test.
            </div>
        </div>
        
        <div class="footer">
            <p>Raithani-Scan v1.0 | Generated on $(date)</p>
        </div>
    </div>
</body>
</html>
HTMLEOF
    
    log_ok "HTML report generated: $html_file"
}

generate_json_report() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    local json_file="$output/report.json"
    
    log_step "Generating JSON report..."
    
    # Build findings JSON array
    local findings_json=""
    local first=true
    for finding in "${FINDINGS[@]}"; do
        local severity="${finding%%|*}"
        local rest="${finding#*|}"
        local title="${rest%%|*}"
        rest="${rest#*|}"
        local detail="${rest%%|*}"
        rest="${rest#*|}"
        local remediation="${rest%%|*}"
        rest="${rest#*|}"
        local evidence="${rest%%|*}"
        
        if [[ "$first" == "true" ]]; then
            first=false
        else
            findings_json+=","
        fi
        
        findings_json+="{\"severity\":\"$severity\",\"title\":$(echo "$title" | python3 -c "import sys,json;print(json.dumps(sys.stdin.read().strip()))" 2>/dev/null || echo "\"$title\""),\"detail\":$(echo "$detail" | python3 -c "import sys,json;print(json.dumps(sys.stdin.read().strip()))" 2>/dev/null || echo "\"$detail\""),\"remediation\":$(echo "$remediation" | python3 -c "import sys,json;print(json.dumps(sys.stdin.read().strip()))" 2>/dev/null || echo "\"$remediation\""),\"evidence\":\"$evidence\"}"
    done
    
    local waf_status="Not Detected"
    if [[ "$WAF_DETECTED" == "true" ]]; then
        waf_status="${WAF_TYPE:-Detected}"
    fi
    
    cat > "$json_file" << JSONEOF
{
    "tool": "Raithani-Scan",
    "version": "1.0",
    "target": {
        "url": "$target_url",
        "domain": "$target_domain",
        "scan_level": $SCAN_LEVEL,
        "timestamp": "$(date)"
    },
    "summary": {
        "total_findings": $((CRIT_COUNT + HIGH_COUNT + MED_COUNT + LOW_COUNT + INFO_COUNT)),
        "critical": $CRIT_COUNT,
        "high": $HIGH_COUNT,
        "medium": $MED_COUNT,
        "low": $LOW_COUNT,
        "info": $INFO_COUNT,
        "waf_detected": $([[ "$WAF_DETECTED" == "true" ]] && echo "true" || echo "false"),
        "waf_type": "$waf_status"
    },
    "findings": [$findings_json]
}
JSONEOF
    
    log_ok "JSON report generated: $json_file"
}

generate_csv_report() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    local csv_file="$output/report.csv"
    
    log_step "Generating CSV report..."
    
    echo "Severity,Title,Details,Remediation" > "$csv_file"
    
    for finding in "${FINDINGS[@]}"; do
        local severity="${finding%%|*}"
        local rest="${finding#*|}"
        local title="${rest%%|*}"
        rest="${rest#*|}"
        local detail="${rest%%|*}"
        rest="${rest#*|}"
        local remediation="${rest%%|*}"
        
        # Escape CSV fields
        local escaped_title=$(echo "$title" | sed 's/"/""/g')
        local escaped_detail=$(echo "$detail" | sed 's/"/""/g')
        local escaped_remediation=$(echo "$remediation" | sed 's/"/""/g')
        
        echo "\"$severity\",\"$escaped_title\",\"$escaped_detail\",\"$escaped_remediation\"" >> "$csv_file"
    done
    
    log_ok "CSV report generated: $csv_file"
}
