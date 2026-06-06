#!/bin/bash
# =============================================================================
# Raithani-Scan - External Tool Integration Phase
# sqlmap, nikto, searchsploit, nmap vuln scripts
# =============================================================================

run_tool_integration() {
    start_phase "Tool Integration"
    
    local target_url="$1"
    local output="$2"
    local tool_out="$output/tool_integration"
    mkdir -p "$tool_out"
    
    # 1. sqlmap (if SQLi enabled and tool available)
    if [[ "$SQLMAP_ENABLED" == "true" ]] && [[ "$SCAN_LEVEL" -ge 2 ]]; then
        run_sqlmap "$target_url" "$tool_out"
    fi
    
    # 2. nikto
    if [[ "$NIKTO_ENABLED" == "true" ]]; then
        run_nikto "$target_url" "$tool_out"
    fi
    
    # 3. searchsploit
    if [[ "$SEARCHSPLOIT_ENABLED" == "true" ]] && [[ "$SCAN_LEVEL" -ge 2 ]]; then
        run_searchsploit "$target_url" "$tool_out"
    fi
    
    # 4. nmap vulnerability scripts
    if [[ "$NMAP_VULN_SCRIPTS_ENABLED" == "true" ]] && [[ "$SCAN_LEVEL" -ge 2 ]]; then
        run_nmap_vuln_scripts "$target_url" "$tool_out"
    fi
    
    end_phase
}

run_sqlmap() {
    local target_url="$1"
    local output="$2"
    
    log_banner "sqlmap - Deep SQL Injection"
    
    if ! command -v sqlmap &>/dev/null; then
        log_warn "sqlmap not installed. Skipping."
        check_optional_dep "sqlmap" || return
    fi
    
    log_info "Running sqlmap for deep SQL injection analysis..."
    log_info "This may take a while..."
    
    local sqlmap_out="$output/sqlmap.txt"
    local sqlmap_cmd="sqlmap -u \"$target_url\" --batch --crawl=1 --time-sec=5 --random-agent --tamper=space2comment --level=3 --risk=2 --output-dir=\"$output/sqlmap_output\" 2>/dev/null"
    
    # Use safe mode: don't modify database
    sqlmap -u "$target_url" --batch --crawl=1 --time-sec=5 --random-agent --tamper=space2comment --level=2 --risk=1 --output-dir="$output/sqlmap_output" --flush-session 2>/dev/null | tee "$sqlmap_out" | while IFS= read -r line; do
        if echo "$line" | grep -qi "Parameter.*GET\|POST\|Cookie\|User-Agent\|Referer\|vulnerable\|injectable\|payload\|identified" 2>/dev/null; then
            log_high "$line"
            
            # Record finding from sqlmap
            record_finding "CRITICAL" "SQLi confirmed by sqlmap" "$line" "Use prepared statements and WAF rules." ""
        elif echo "$line" | grep -qi "testing\|checking\|trying" 2>/dev/null; then
            log_info "$line"
        fi
    done
    
    if [[ -f "$sqlmap_out" ]]; then
        log_ok "sqlmap scan complete. Check sqlmap_output/ for details."
    fi
}

run_nikto() {
    local target_url="$1"
    local output="$2"
    
    log_banner "nikto - Web Server Scanner"
    
    if ! command -v nikto &>/dev/null; then
        log_warn "nikto not installed. Skipping."
        check_optional_dep "nikto" || return
    fi
    
    log_info "Running nikto for web server vulnerability scanning..."
    
    local nikto_out="$output/nikto.txt"
    local nikto_html="$output/nikto.html"
    
    nikto -h "$target_url" -ssl -no404 -Format txt -output "$nikto_out" 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | grep -qi "\+.*OSVDB\|CVE\|vulnerability\|warning\|error\|interesting\|server\|cookie" 2>/dev/null; then
            log_high "$line"
            record_finding "MEDIUM" "nikto finding: $(echo "$line" | cut -c-60)" "$line" "Address identified vulnerability." ""
        elif echo "$line" | grep -qi "^\- " 2>/dev/null; then
            log_info "$line"
        fi
    done
    
    # Also generate HTML
    nikto -h "$target_url" -ssl -no404 -Format html -output "$nikto_html" 2>/dev/null
    
    log_ok "nikto scan complete. Results saved."
}

run_searchsploit() {
    local target_url="$1"
    local output="$2"
    
    log_banner "searchsploit - Vulnerability Lookup"
    
    if ! command -v searchsploit &>/dev/null; then
        log_warn "searchsploit not installed. Skipping."
        check_optional_dep "searchsploit" || return
    fi
    
    log_info "Searching exploit-db for relevant vulnerabilities..."
    
    local searchsploit_out="$output/searchsploit.txt"
    
    # Get services from port scan
    local service_file="$output/services.txt"
    local web_server=""
    
    if [[ -f "$output/../services.txt" ]]; then
        service_file="$output/../services.txt"
    fi
    
    if [[ -f "$service_file" ]]; then
        local servers=$(grep -iE "http|apache|nginx|tomcat|iis|lighttpd" "$service_file" 2>/dev/null | head -5)
        while IFS= read -r line; do
            local service_name=$(echo "$line" | awk '{print $NF}')
            if [[ -n "$service_name" ]]; then
                log_info "Searching exploits for: $service_name"
                searchsploit "$service_name" 2>/dev/null | head -20 >> "$searchsploit_out"
                echo "---" >> "$searchsploit_out"
            fi
        done <<< "$servers"
    fi
    
    # Also search for CMS-specific exploits
    local whatweb_out="$output/whatweb.txt"
    if [[ -f "$output/../whatweb.txt" ]]; then
        whatweb_out="$output/../whatweb.txt"
    fi
    if [[ -f "$whatweb_out" ]]; then
        local cms=$(grep -oiE "WordPress|Joomla|Drupal|Magento|Shopify|PrestaShop|Laravel|Symfony|CakePHP|Yii|Django|Rails|ASP\.NET" "$whatweb_out" 2>/dev/null | sort -u)
        while IFS= read -r cms_name; do
            if [[ -n "$cms_name" ]]; then
                log_info "Searching exploits for CMS: $cms_name"
                searchsploit "$cms_name" 2>/dev/null | head -15 >> "$searchsploit_out"
                echo "---" >> "$searchsploit_out"
            fi
        done <<< "$cms"
    fi
    
    if [[ -f "$searchsploit_out" ]]; then
        local exploit_count=$(grep -cE "^[0-9]+\|" "$searchsploit_out" 2>/dev/null)
        log_ok "searchsploit found $exploit_count potential exploits"
        
        if [[ "$exploit_count" -gt 0 ]]; then
            record_finding "INFO" "Potential exploits found ($exploit_count)" "Review searchsploit.txt for details." "Patch/upgrade software to latest versions." ""
        fi
    else
        log_info "No exploits found for identified services"
    fi
}

run_nmap_vuln_scripts() {
    local target_url="$1"
    local output="$2"
    
    log_banner "nmap Vulnerability Scripts"
    
    local target_domain=$(echo "$target_url" | sed -E 's|^https?://||' | sed 's|/.*$||')
    
    log_info "Running nmap vulnerability detection scripts..."
    
    local nmap_vuln_out="$output/nmap_vuln.txt"
    
    # Load open ports from port scan
    local port_file=""
    if [[ -f "$output/../ports.txt" ]]; then
        port_file="$output/../ports.txt"
    fi
    
    local ports="80,443"
    if [[ -f "$port_file" ]]; then
        ports=$(tr '\n' ',' < "$port_file" | sed 's/,$//')
    fi
    
    if command -v nmap &>/dev/null; then
        # Run NSE vulnerability scripts
        nmap -sV -p "$ports" --script "vuln and safe" -Pn -n "$target_domain" -oN "$nmap_vuln_out" 2>/dev/null | while IFS= read -r line; do
            if echo "$line" | grep -qi "CVE-\|vulnerable\|VULNERABLE\|CVSS\|risk\|warning\|exploit" 2>/dev/null; then
                log_high "$line"
                record_finding "HIGH" "nmap NSE: $(echo "$line" | cut -c-50)" "$line" "Apply relevant patches." ""
            fi
        done
    fi
    
    log_ok "nmap vulnerability scripts complete"
}
