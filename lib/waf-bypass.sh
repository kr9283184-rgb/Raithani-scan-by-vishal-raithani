#!/bin/bash
# =============================================================================
# Raithani-Scan - WAF Detection & Bypass Engine
# Detects WAF type and applies appropriate bypass techniques
# =============================================================================

detect_waf() {
    start_phase "WAF Detection"
    
    local target_url="$1"
    local waf_found=false
    
    log_step "Detecting Web Application Firewall..."
    
    # Method 1: wafw00f
    if command -v wafw00f &>/dev/null; then
        log_info "Running wafw00f..."
        local wafw00f_out="$OUTPUT_DIR/wafw00f.txt"
        wafw00f "$target_url" -a 2>/dev/null | tee "$wafw00f_out" | while IFS= read -r line; do
            log_info "$line"
        done
        
        if grep -qi "firewall\|waf\|blocked\|detected" "$wafw00f_out" 2>/dev/null; then
            waf_found=true
            WAF_TYPE=$(grep -i "firewall\|waf" "$wafw00f_out" | head -1 | sed 's/.*: //')
        fi
    fi
    
    # Method 2: nmap WAF fingerprint
    if command -v nmap &>/dev/null; then
        log_info "Running nmap WAF fingerprint..."
        local nmap_waf_out="$OUTPUT_DIR/nmap_waf.txt"
        nmap -p 443 --script http-waf-fingerprint "$TARGET_DOMAIN" 2>/dev/null | tee "$nmap_waf_out" | grep -v "^Starting\|^Nmap\|^Host\|^$" | while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                log_info "$line"
            fi
        done
        
        if grep -qi "firewall\|waf\|cloudflare\|mod_security\|barracuda\|f5\|imperva\|sucuri\|akamai" "$nmap_waf_out" 2>/dev/null; then
            waf_found=true
            WAF_TYPE=$(grep -i "firewall\|waf\|cloudflare\|mod_security" "$nmap_waf_out" | head -1)
        fi
    fi
    
    # Method 3: Custom WAF detection via headers
    log_info "Analyzing response headers for WAF signatures..."
    local headers_file="$OUTPUT_DIR/response_headers.txt"
    curl -s -k -I -L --max-time "$TIMEOUT" "$target_url" 2>/dev/null > "$headers_file"
    
    if grep -qi "cloudflare" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Cloudflare"
    elif grep -qi "server: cloudflare" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Cloudflare"
    elif grep -qi "__cfduid" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Cloudflare"
    elif grep -qi "mod_security\|ModSecurity" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="ModSecurity"
    elif grep -qi "F5\|BIG-IP" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="F5 BIG-IP"
    elif grep -qi "barracuda" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Barracuda"
    elif grep -qi "Akamai\|akamai" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Akamai"
    elif grep -qi "x-sucuri\|sucuri" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Sucuri"
    elif grep -qi "x-powered-by: AWS\|aws-waf\|x-amz" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="AWS WAF"
    elif grep -qi "imperva\|incapsula" "$headers_file" 2>/dev/null; then
        waf_found=true
        WAF_TYPE="Imperva/Incapsula"
    fi
    
    # Method 4: CDN fingerprinting
    log_info "CDN fingerprinting..."
    local cdn_identified=""
    local cdn_headers_file="$OUTPUT_DIR/response_headers.txt"
    
    # Check response headers for CDN signatures
    if grep -qi "x-cache:" "$cdn_headers_file" 2>/dev/null; then
        if grep -qi "x-cache:.*cloudflare" "$cdn_headers_file" 2>/dev/null; then
            cdn_identified="Cloudflare"
        elif grep -qi "x-cache:.*hit\|x-cache:.*miss" "$cdn_headers_file" 2>/dev/null; then
            cdn_identified="Generic CDN (x-cache header present)"
        fi
    fi
    if grep -qi "x-amz-cf-id\|x-amz-cf-pop\|cloudfront" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="AWS CloudFront"
    fi
    if grep -qi "x-akamai\|akamai" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Akamai"
    fi
    if grep -qi "x-sucuri-id\|x-sucuri-cache" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Sucuri"
    fi
    if grep -qi "fastly-debug\|x-fastly" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Fastly"
    fi
    if grep -qi "x-azure-ref\|x-azure" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Azure CDN"
    fi
    if grep -qi "x-cdn\|x-edge\|x-ec" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Edgecast / Verizon CDN"
    fi
    if grep -qi "x-iinfo\|x-request-id\|incapsula" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Imperva / Incapsula"
    fi
    if grep -qi "cf-ray\|__cfduid\|__cf_bm" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Cloudflare"
    fi
    if grep -qi "x-pingback\|x-powered-by:.*Plesk" "$cdn_headers_file" 2>/dev/null; then
        cdn_identified="Plesk (may be self-hosted)"
    fi
    
    if [[ -n "$cdn_identified" ]]; then
        log_info "  CDN: $cdn_identified"
        CDN_TYPE="$cdn_identified"
        record_finding "INFO" "CDN Detected: $cdn_identified" "Target uses $cdn_identified CDN." "" ""
        
        # Enhanced bypass headers for known CDNs
        case "${cdn_identified,,}" in
            *cloudflare*)
                log_info "    Cloudflare detected — adding origin bypass headers"
                ;;
            *cloudfront*)
                log_info "    CloudFront detected — checking for origin-override headers"
                ;;
            *akamai*)
                log_info "    Akamai detected — testing True-Client-IP bypass"
                ;;
        esac
    else
        log_info "  No CDN detected (may be direct origin or unknown CDN)"
    fi
    
    # Method 5: Probe with malicious payload to detect behavioral changes
    log_info "Probing with test payloads to detect WAF behavior..."
    local normal_response=$(curl -s -k -o /dev/null -w "%{size_download}" --max-time "$TIMEOUT" "$target_url" 2>/dev/null)
    local probe_response=$(curl -s -k -o /dev/null -w "%{size_download}" --max-time "$TIMEOUT" "${target_url}?test=' OR '1'='1" 2>/dev/null)
    
    if [[ "$normal_response" != "$probe_response" ]]; then
        log_warn "Response size differs when sending malicious payload (WAF may be active)"
        waf_found=true
        if [[ -z "$WAF_TYPE" ]]; then
            WAF_TYPE="Generic/Unknown"
        fi
    fi
    
    if [[ "$waf_found" == "true" ]]; then
        WAF_DETECTED=true
        log_high "WAF Detected: ${WAF_TYPE:-Unknown}"
        record_finding "INFO" "WAF Detected: ${WAF_TYPE:-Unknown}" "Target is protected by a Web Application Firewall. Bypass techniques will be applied." "Review WAF rules and test for bypasses." ""
        
        # Load bypass techniques
        load_bypass_techniques
    else
        log_ok "No WAF detected (or WAF is transparent)"
        WAF_DETECTED=false
    fi
    
    end_phase
}

load_bypass_techniques() {
    log_step "Loading WAF bypass techniques..."
    
    local bypass_dir="$SCRIPT_DIR/bypass"
    local bypass_file=""
    
    # Map WAF type to bypass file
    case "${WAF_TYPE,,}" in
        *cloudflare*)  bypass_file="$bypass_dir/cloudflare.txt" ;;
        *modsecurity*) bypass_file="$bypass_dir/modsec.txt" ;;
        *aws*)         bypass_file="$bypass_dir/aws-waf.txt" ;;
        *)             bypass_file="$bypass_dir/generic.txt" ;;
    esac
    
    if [[ -f "$bypass_file" ]]; then
        log_info "Loaded bypass techniques for ${WAF_TYPE:-Unknown}"
        while IFS='|' read -r tech_name tech_desc tech_impl; do
            if [[ -n "$tech_name" && ! "$tech_name" =~ ^# ]]; then
                log_info "  - $tech_name: $tech_desc"
            fi
        done < "$bypass_file"
    fi
}

# Apply bypass headers based on detected WAF
get_bypass_headers() {
    local bypass_headers=()
    
    case "${WAF_TYPE,,}" in
        *cloudflare*)
            bypass_headers+=("-H" "X-Forwarded-For: 127.0.0.1")
            bypass_headers+=("-H" "X-Real-IP: 127.0.0.1")
            bypass_headers+=("-H" "X-Originating-IP: 127.0.0.1")
            bypass_headers+=("-H" "CF-Connecting-IP: 127.0.0.1")
            ;;
        *modsecurity*)
            bypass_headers+=("-H" "X-Forwarded-For: 127.0.0.1")
            ;;
        *aws*)
            bypass_headers+=("-H" "X-Forwarded-For: 127.0.0.1")
            bypass_headers+=("-H" "X-Real-IP: 127.0.0.1")
            ;;
        *)
            if [[ "$WAF_DETECTED" == "true" ]]; then
                bypass_headers+=("-H" "X-Forwarded-For: 127.0.0.1")
                bypass_headers+=("-H" "X-Real-IP: 127.0.0.1")
            fi
            ;;
    esac
    
    echo "${bypass_headers[@]}"
}

# Generate bypass payload variants using Python generator
generate_payload_variants() {
    local vuln_type="$1"
    local base_payload="$2"
    local generator="$SCRIPT_DIR/payloads/generator.py"
    
    if [[ -f "$generator" ]]; then
        python3 "$generator" "$vuln_type" --base-payload "$base_payload" 2>/dev/null
    else
        echo "$base_payload"
    fi
}

# Generate ALL payload variants for a vulnerability type
generate_all_variants() {
    local vuln_type="$1"
    local generator="$SCRIPT_DIR/payloads/generator.py"
    local payload_file="$SCRIPT_DIR/payloads/${vuln_type}.txt"
    
    if [[ -f "$generator" ]]; then
        python3 "$generator" "$vuln_type" 2>/dev/null
    elif [[ -f "$payload_file" ]]; then
        grep -v '^#' "$payload_file" | grep -v '^$'
    fi
}

# Calculate adaptive delay based on WAF detection
get_request_delay() {
    if [[ "$WAF_DETECTED" == "true" ]]; then
        # Be more cautious when WAF is present
        local base_min=1.0
        local base_max=3.0
        python3 -c "import random; print(round(random.uniform($base_min, $base_max), 2))" 2>/dev/null || echo "1.5"
    else
        python3 -c "import random; print(round(random.uniform($REQUEST_DELAY_MIN, $REQUEST_DELAY_MAX), 2))" 2>/dev/null || echo "0.5"
    fi
}

# WAF-aware HTTP request
waf_request() {
    local url="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    local content_type="${4:-}"
    
    local curl_args=(-s -k -L --max-time "$TIMEOUT" --retry "$MAX_RETRIES" --retry-delay 2)
    
    # Add bypass headers if WAF detected
    if [[ "$WAF_DETECTED" == "true" ]]; then
        local bypass_headers=()
        IFS=' ' read -ra bypass_headers <<< "$(get_bypass_headers)"
        for h in "${bypass_headers[@]}"; do
            curl_args+=("$h")
        done
    fi
    
    # User-Agent rotation
    local ua_list=(
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Firefox/126.0"
    )
    local rand_idx=$((RANDOM % ${#ua_list[@]}))
    curl_args+=(-H "User-Agent: ${ua_list[$rand_idx]}")
    curl_args+=(-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    curl_args+=(-H "Accept-Language: en-US,en;q=0.5")
    
    # Add random delay to avoid rate limiting
    local delay=$(get_request_delay)
    sleep "$delay"
    
    if [[ "$method" == "POST" ]]; then
        curl_args+=(-X POST)
        [[ -n "$data" ]] && curl_args+=(--data "$data")
        [[ -n "$content_type" ]] && curl_args+=(-H "Content-Type: $content_type")
    fi
    
    curl "${curl_args[@]}" "$url" 2>/dev/null || echo ""
}
