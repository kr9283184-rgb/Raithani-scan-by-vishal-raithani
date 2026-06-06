#!/bin/bash
# =============================================================================
# Raithani-Scan - Vulnerability Scanning Engine
# Custom HTTP-based vulnerability checks using ALL payloads with WAF bypass
# =============================================================================

run_vuln_checks() {
    start_phase "Vulnerability Scanning Engine"
    
    local target_url="$1"
    local output="$2"
    local payload_dir="$SCRIPT_DIR/payloads"
    local vuln_output="$output/vuln_checks"
    mkdir -p "$vuln_output"
    
    log_info "Loading payloads and generating variants..."
    log_info "Target URL: $target_url"
    
    # Load discovered URLs and parameters from web enum phase
    local discovered_urls="$output/all_discovered_urls.txt"
    local param_urls="$output/web_enum/parameterized_urls.txt"
    
    # Build list of testable URLs
    local test_urls=("$target_url")
    if [[ -f "$discovered_urls" ]]; then
        while IFS= read -r url; do
            [[ -n "$url" ]] && test_urls+=("$url")
        done < "$discovered_urls"
    fi
    
    # If we have parameterized URLs, use those too
    local test_params=()
    if [[ -f "$param_urls" ]]; then
        while IFS= read -r url; do
            [[ -n "$url" ]] && test_urls+=("$url")
        done < "$param_urls"
    fi
    
    log_info "Testing ${#test_urls[@]} URLs for vulnerabilities..."
    
    # === SQL INJECTION ===
    if [[ "$SQLI_ENABLED" == "true" ]]; then
        check_sqli "$target_url" "$output" "$payload_dir/sqli.txt"
    fi
    
    # === XSS ===
    if [[ "$XSS_ENABLED" == "true" ]]; then
        check_xss "$target_url" "$output" "$payload_dir/xss.txt"
    fi
    
    # === LFI/RFI ===
    if [[ "$LFI_ENABLED" == "true" ]]; then
        check_lfi "$target_url" "$output" "$payload_dir/lfi.txt"
    fi
    
    # === COMMAND INJECTION ===
    if [[ "$CMDI_ENABLED" == "true" ]]; then
        check_cmdi "$target_url" "$output" "$payload_dir/cmdi.txt"
    fi
    
    # === SSRF ===
    if [[ "$SSRF_ENABLED" == "true" ]]; then
        check_ssrf "$target_url" "$output" "$payload_dir/ssrf.txt"
    fi
    
    # === SSTI ===
    if [[ "$SSTI_ENABLED" == "true" ]]; then
        check_ssti "$target_url" "$output" "$payload_dir/ssti.txt"
    fi
    
    # === XXE ===
    if [[ "$XXE_ENABLED" == "true" ]]; then
        check_xxe "$target_url" "$output" "$payload_dir/xxe.txt"
    fi
    
    # === OPEN REDIRECT ===
    if [[ "$OPEN_REDIRECT_ENABLED" == "true" ]]; then
        check_open_redirect "$target_url" "$output" "$payload_dir/open-redirect.txt"
    fi
    
    # === SECURITY HEADERS & CONFIGURATION ===
    if [[ "$HEADER_CHECK_ENABLED" == "true" ]]; then
        check_security_headers "$target_url" "$output"
    fi
    
    # === CORS CHECK ===
    if [[ "$CORS_CHECK_ENABLED" == "true" ]]; then
        check_cors "$target_url" "$output"
    fi
    
    # === CSRF CHECK ===
    if [[ "$CSRF_ENABLED" == "true" ]]; then
        check_csrf "$target_url" "$output"
    fi

    # === IDOR CHECK ===
    if [[ "$IDOR_ENABLED" == "true" ]]; then
        check_idor "$target_url" "$output"
    fi

    # === JWT CHECK ===
    if [[ "$JWT_ENABLED" == "true" ]]; then
        check_jwt "$target_url" "$output"
    fi

    # === GRAPHQL CHECK ===
    if [[ "$GRAPHQL_ENABLED" == "true" ]]; then
        check_graphql "$target_url" "$output"
    fi

    end_phase
}

# =============================================================================
# SQL INJECTION CHECK
# =============================================================================
check_sqli() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "SQL Injection Testing (${#test_urls[@]} URLs)"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base SQLi payloads"
    
    # Define test parameters
    local sqli_params=("id" "page" "pid" "cat" "category" "product" "products" "item" "items" "article" "news" "blog" "post" "view" "read" "show" "detail" "file" "name" "user" "username" "search" "q" "query" "s" "sort" "order" "table" "field" "type" "option" "param" "value")
    
    # Build test URLs for each parameter
    local sqli_test_urls=()
    
    # Test on root URL with various params
    for param in "${sqli_params[@]}"; do
        sqli_test_urls+=("${target_url}?${param}=PAYLOAD")
    done
    
    # Add discovered URLs
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            # If URL already has params, add a SQLi param
            if [[ "$url" == *"?"* ]]; then
                sqli_test_urls+=("${url}&sqli=PAYLOAD")
            else
                for param in "${sqli_params[@]:0:5}"; do
                    sqli_test_urls+=("${url}?${param}=PAYLOAD")
                done
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    local test_count=0
    local sqli_findings=0
    
    # Test loop - try each payload on each URL
    for base_url_info in "${sqli_test_urls[@]}"; do
        local final_url=""
        local url_base="${base_url_info/PAYLOAD/__PAYLOAD__}"
        
        for payload in "${payloads[@]}"; do
            [[ -z "$payload" ]] && continue
            [[ "$payload" =~ ^# ]] && continue
            
            # Skip destructive payloads in safe mode
            if [[ "$DANGER_MODE" != "true" ]]; then
                if [[ "$payload" =~ DROP|DELETE|TRUNCATE|INTO\ OUTFILE|INTO\ DUMPFILE|xp_|exec ]]; then
                    continue
                fi
            fi
            
            # Generate WAF bypass variants
            local variants=()
            variants+=("$payload")
            
            # Add URL encoded variant
            local encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null)
            [[ -n "$encoded" ]] && variants+=("$encoded")
            
            # Add comment injection variant for SQL keywords
            if [[ "$payload" == *"UNION"* || "$payload" == *"SELECT"* ]]; then
                variants+=("$(python3 -c "
payload = '$payload'
import random
keywords = ['UNION', 'SELECT', 'OR', 'AND', 'FROM', 'WHERE']
for kw in sorted(keywords, key=len, reverse=True):
    if kw in payload or kw.lower() in payload.lower():
        idx = payload.lower().index(kw.lower())
        variant = payload[:idx] + '/**/' + payload[idx:] + '/**/'
        print(variant)
        break
" 2>/dev/null)")
            fi
            
            for variant in "${variants[@]}"; do
                [[ -z "$variant" ]] && continue
                
                # Prepare request
                if [[ "$url_base" == *"__PAYLOAD__"* ]]; then
                    final_url="${url_base/__PAYLOAD__/$variant}"
                else
                    final_url="$url_base$variant"
                fi
                
                # Add random delay for WAF bypass
                local delay=$(get_request_delay)
                sleep "$delay"
                
                # Make request with WAF bypass headers
                local response=$(waf_request "$final_url" "GET")
                local response_size=$(echo "$response" | wc -c)
                local response_time=0
                
                # Time-based detection
                if [[ "$payload" == *"SLEEP"* || "$payload" == *"WAITFOR"* || "$payload" == *"BENCHMARK"* ]]; then
                    local start_t=$(date +%s%N)
                    local time_resp=$(waf_request "$final_url" "GET")
                    local end_t=$(date +%s%N)
                    response_time=$(( (end_t - start_t) / 1000000 ))
                fi
                
                # === Detection Logic ===
                local detected=false
                local evidence=""
                
                # 1. Error-based detection
                if echo "$response" | grep -qi "SQL syntax\|MySQL\|MariaDB\|PostgreSQL\|Oracle\|ODBC\|SQLite\| sql \|driver.*error\|Warning.*mysql\|unclosed quotation\|quoted string\|Division by zero\|Unknown column\|Table.*doesn't exist\|You have an error" 2>/dev/null; then
                    detected=true
                    evidence="SQL error in response"
                fi
                
                # 2. Boolean-based detection
                if [[ "$payload" == *" AND "*"1=1"* || "$payload" == *" AND "*"1=2"* ]]; then
                    if [[ -n "$response" ]]; then
                        # Compare with normal response
                        local normal_resp=$(http_request "${final_url/ AND */}" 2>/dev/null)
                        if [[ "$response" != "$normal_resp" ]]; then
                            detected=true
                            evidence="Response differs between boolean conditions"
                        fi
                    fi
                fi
                
                # 3. Time-based detection
                if [[ "$response_time" -gt 4000 ]]; then
                    detected=true
                    evidence="Time delay detected: ${response_time}ms (expected <1000ms)"
                fi
                
                # 4. Union-based detection (check for numeric output)
                if [[ "$payload" == *"UNION"* || "$payload" == *"UNION ALL"* ]]; then
                    if echo "$response" | grep -qP '[0-9]+[,\s]+[0-9]+[,\s]+[0-9]+' 2>/dev/null; then
                        detected=true
                        evidence="UNION SELECT output detected (numbers in response)"
                    fi
                fi
                
                if [[ "$detected" == "true" ]]; then
                    sqli_findings+=1

                    local severity="HIGH"
                    if [[ "$response_time" -gt 4000 || "$payload" == *"UNION"* ]]; then
                        severity="CRITICAL"
                    fi

                    local evidence_file=""
                    if [[ "$severity" == "CRITICAL" ]]; then
                        evidence_file="$vuln_output/sqli_evidence_${sqli_findings}.txt"
                        {
                            echo "URL: $final_url"
                            echo "Payload: $variant"
                            echo "Evidence: $evidence"
                            echo "Response size: $response_size"
                            echo "Response time: ${response_time}ms"
                            echo ""
                            echo "--- Manual Verification Steps ---"
                            echo "1. Open terminal and run:"
                            echo "   curl -k \"$final_url\""
                            echo "2. Check the response for SQL error messages:"
                            echo "   - 'SQL syntax', 'MySQL', 'MariaDB', 'PostgreSQL'"
                            echo "   - 'Unclosed quotation mark', 'Division by zero'"
                            echo "   - 'Unknown column', 'Table.*doesn't exist'"
                            echo "3. If you see database error messages, the parameter is vulnerable."
                            echo ""
                            echo "--- Response (first 500 chars) ---"
                            echo "$response" | head -c 500
                        } > "$evidence_file"
                    fi

                    record_finding "$severity" \
                        "SQL Injection in $(echo "$final_url" | sed 's/?.*/?.../')" \
                        "Parameter: $(echo "$final_url" | grep -oP '\K[^?&?]+(?==)' | head -1) | Payload: $(echo "$variant" | cut -c1-50) | $evidence" \
                        "Use prepared statements / parameterized queries. Implement WAF rules." \
                        "$evidence_file"

                    if [[ "$severity" == "CRITICAL" ]]; then
                        break 2
                    fi
                    break
                fi
            done
            test_count+=1
        done
    done
    
    if [[ "$sqli_findings" -eq 0 ]]; then
        log_ok "No SQL injection vulnerabilities detected with ${#payloads[@]} payloads across ${#sqli_test_urls[@]} URLs"
    fi
}

# =============================================================================
# XSS CHECK
# =============================================================================
check_xss() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "XSS Testing"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base XSS payloads"
    
    local xss_params=("q" "s" "search" "query" "name" "user" "comment" "text" "msg" "message" "content" "title" "subject" "email" "url" "redirect" "return" "next" "page" "id" "view" "feedback" "input" "keyword" "term" "searchword" "searchtext")
    local xss_test_urls=()
    
    for param in "${xss_params[@]}"; do
        xss_test_urls+=("${target_url}?${param}=PAYLOAD")
    done
    
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if [[ "$url" == *"?"* ]]; then
                xss_test_urls+=("${url}&xss=PAYLOAD")
            else
                for param in "${xss_params[@]:0:5}"; do
                    xss_test_urls+=("${url}?${param}=PAYLOAD")
                done
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    local xss_findings=0
    local alert_variants=("alert(1)" "prompt(1)" "confirm(1)" "alert(document.cookie)")
    
    for base_url_info in "${xss_test_urls[@]}"; do
        local url_base="${base_url_info/PAYLOAD/__PAYLOAD__}"
        
        for payload in "${payloads[@]}"; do
            [[ -z "$payload" ]] && continue
            [[ "$payload" =~ ^# ]] && continue
            
            # Generate variants
            local variants=()
            variants+=("$payload")
            
            # Encoded variants for WAF bypass
            local encoded_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload''', safe=''))" 2>/dev/null)
            [[ -n "$encoded_payload" ]] && variants+=("$encoded_payload")
            
            # HTML entity encoded for certain contexts
            if [[ "$payload" == *"<"* || "$payload" == *">"* ]]; then
                local html_ent=$(python3 -c "
p = '''$payload'''
import random
result = ''
for c in p:
    if c == '<': result += '&#x3c;'
    elif c == '>': result += '&#x3e;'
    elif c == '\"': result += '&#x22;'
    elif c == \"'\": result += '&#x27;'
    else: result += c
print(result)
" 2>/dev/null)
                [[ -n "$html_ent" ]] && variants+=("$html_ent")
            fi
            
            # Add unicode variants
            if [[ "$payload" == *"alert"* || "$payload" == *"script"* ]]; then
                local unicode_var=$(python3 -c "
p = '''$payload'''
import random
# Randomly substitute with full-width chars
result = ''
fullwidth = {'a':'ａ','b':'ｂ','c':'ｃ','e':'ｅ','l':'ｌ','p':'ｐ','r':'ｒ','s':'ｓ','t':'ｔ'}
for c in p:
    if c.lower() in fullwidth and random.random() > 0.7:
        result += fullwidth[c.lower()]
    else:
        result += c
print(result)
" 2>/dev/null)
                [[ -n "$unicode_var" ]] && variants+=("$unicode_var")
            fi
            
            for variant in "${variants[@]}"; do
                [[ -z "$variant" ]] && continue
                
                # Prepare URL
                if [[ "$url_base" == *"__PAYLOAD__"* ]]; then
                    local final_url="${url_base/__PAYLOAD__/$variant}"
                else
                    local final_url="$url_base$variant"
                fi
                
                # XSS detection
                local delay=$(get_request_delay)
                sleep "$delay"
                
                local response=$(waf_request "$final_url" "GET")
                
                local detected=false
                local evidence=""
                
                # Check if payload is reflected in response (unescaped)
                if echo "$response" | grep -qF "$variant" 2>/dev/null; then
                    detected=true
                    evidence="Payload reflected unescaped in response"
                # Check for unescaped angle brackets
                elif echo "$response" | grep -qiP '<script[^>]*>[^<]*alert\(' 2>/dev/null; then
                    detected=true
                    evidence="Script tag with alert() reflected"
                elif echo "$response" | grep -qiP 'onerror\s*=\s*alert' 2>/dev/null; then
                    detected=true
                    evidence="Event handler with alert() reflected"
                elif echo "$response" | grep -qiP 'onload\s*=\s*alert' 2>/dev/null; then
                    detected=true
                    evidence="onload handler with alert() reflected"
                elif echo "$response" | grep -qiP 'javascript:.*alert\(' 2>/dev/null; then
                    detected=true
                    evidence="javascript: URI with alert() reflected"
                elif [[ "$variant" == *"<img"* ]] && echo "$response" | grep -qiP '<img[^>]*src\s*=\s*["'\'']?\s*x' 2>/dev/null; then
                    detected=true
                    evidence="Image tag with broken src reflected"
                elif [[ "$variant" == *"<svg"* ]] && echo "$response" | grep -qiP '<svg[^>]*onload' 2>/dev/null; then
                    detected=true
                    evidence="SVG with onload reflected"
                fi
                
                if [[ "$detected" == "true" ]]; then
                    xss_findings+=1
                    local evidence_file="$vuln_output/xss_evidence_${xss_findings}.txt"
                    echo "URL: $final_url" > "$evidence_file"
                    echo "Payload: $variant" >> "$evidence_file"
                    echo "Evidence: $evidence" >> "$evidence_file"
                    echo "--- Response (first 300 chars) ---" >> "$evidence_file"
                    echo "$response" | head -c 300 >> "$evidence_file"
                    
                    # Extract reflected payload context
                    local reflected=$(echo "$response" | grep -oP ".{0,50}$(echo "$variant" | sed 's/[\/]/\\&/g').{0,50}" 2>/dev/null | head -3)
                    echo "--- Context ---" >> "$evidence_file"
                    echo "$reflected" >> "$evidence_file"
                    
                    record_finding "HIGH" "XSS in $(echo "$final_url" | sed 's/?.*/?.../')" "Type: Reflected | Payload: $(echo "$variant" | cut -c1-60) | $evidence" "Properly encode output based on context. Use Content-Security-Policy header." "$evidence_file"
                    break
                fi
            done
        done
    done
    
    if [[ "$xss_findings" -eq 0 ]]; then
        log_ok "No XSS vulnerabilities detected with ${#payloads[@]} payloads"
    fi
}

# =============================================================================
# LFI/RFI CHECK
# =============================================================================
check_lfi() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "LFI/RFI Testing"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base LFI/RFI payloads"
    
    local lfi_params=("file" "page" "include" "template" "dir" "path" "document" "folder" "root" "load" "read" "show" "view" "content" "data" "inc" "loc" "location" "open" "f" "pg" "p" "name" "cat" "cmd")
    
    local lfi_test_urls=()
    for param in "${lfi_params[@]}"; do
        lfi_test_urls+=("${target_url}?${param}=PAYLOAD")
    done
    
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if [[ "$url" == *"?"* ]]; then
                lfi_test_urls+=("${url}&lfi=PAYLOAD")
            else
                for param in "${lfi_params[@]:0:5}"; do
                    lfi_test_urls+=("${url}?${param}=PAYLOAD")
                done
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    local lfi_findings=0
    # Indicators that LFI was successful
    local lfi_indicators=("root:" "daemon:" "bin:" "sys:" "www-data:" "mysql:" "nobody:" "admin:" "ntp:" "messagebus:" "sshd:" "mail:" ":[0-9]+:[0-9]+:" "tcp" "udp" "127.0.0.1" "localhost" "nginx" "apache" "Listen " "DocumentRoot" "ServerName")
    
    # PHP wrapper indicators
    local base64_indicators=("PD9" "PDw" "PC8" "IDw" "Pz4" "aWQ" "d2hv" "bHMg")
    
    for base_url_info in "${lfi_test_urls[@]}"; do
        local url_base="${base_url_info/PAYLOAD/__PAYLOAD__}"
        
        for payload in "${payloads[@]}"; do
            [[ -z "$payload" ]] && continue
            [[ "$payload" =~ ^# ]] && continue
            
            # Try URL encoded variants
            local variants=("$payload")
            local encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null)
            [[ -n "$encoded" ]] && variants+=("$encoded")
            
            # Double URL encode
            local double_encoded=$(python3 -c "import urllib.parse; p=urllib.parse.quote('$payload', safe=''); print(urllib.parse.quote(p, safe=''))" 2>/dev/null)
            [[ -n "$double_encoded" ]] && variants+=("$double_encoded")
            
            for variant in "${variants[@]}"; do
                [[ -z "$variant" ]] && continue
                
                if [[ "$url_base" == *"__PAYLOAD__"* ]]; then
                    local final_url="${url_base/__PAYLOAD__/$variant}"
                else
                    local final_url="$url_base$variant"
                fi
                
                local delay=$(get_request_delay)
                sleep "$delay"
                
                local response=$(waf_request "$final_url" "GET")
                
                local detected=false
                local evidence=""
                
                # Check for file inclusion indicators
                for indicator in "${lfi_indicators[@]}"; do
                    if echo "$response" | grep -qiP "$indicator" 2>/dev/null; then
                        detected=true
                        evidence="File content indicator: '$indicator' found in response"
                        break
                    fi
                done
                
                # Check for base64 encoded output (PHP wrappers)
                if [[ "$detected" == "false" ]]; then
                    for b64_ind in "${base64_indicators[@]}"; do
                        if echo "$response" | grep -q "$b64_ind" 2>/dev/null; then
                            detected=true
                            evidence="Base64 encoded content detected (PHP wrapper output)"
                            break
                        fi
                    done
                fi
                
                # Check for RFI (remote content inclusion)
                if [[ "$detected" == "false" && "$payload" == *"http"* ]]; then
                    if echo "$response" | grep -qi "shell\|backdoor\|VULNERABLE\|RFI_SUCCESS" 2>/dev/null; then
                        detected=true
                        evidence="Remote file inclusion confirmed"
                    fi
                fi
                
                if [[ "$detected" == "true" ]]; then
                    lfi_findings+=1
                    local evidence_file="$vuln_output/lfi_evidence_${lfi_findings}.txt"
                    echo "URL: $final_url" > "$evidence_file"
                    echo "Payload: $variant" >> "$evidence_file"
                    echo "Evidence: $evidence" >> "$evidence_file"
                    echo "--- Response (first 500 chars) ---" >> "$evidence_file"
                    echo "$response" | head -c 500 >> "$evidence_file"
                    
                    record_finding "CRITICAL" "LFI/RFI in $(echo "$final_url" | sed 's/?.*/?.../')" "Payload: $(echo "$variant" | cut -c1-60) | $evidence" "Avoid passing user input to file inclusion functions. Use whitelist-based file inclusion." "$evidence_file"
                    break
                fi
            done
        done
    done
    
    if [[ "$lfi_findings" -eq 0 ]]; then
        log_ok "No LFI/RFI vulnerabilities detected with ${#payloads[@]} payloads"
    fi
}

# =============================================================================
# COMMAND INJECTION CHECK
# =============================================================================
check_cmdi() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "Command Injection Testing"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base command injection payloads"
    
    local cmdi_params=("cmd" "command" "exec" "run" "execute" "ping" "traceroute" "nslookup" "host" "dig" "whois" "cmd" "command" "system" "shell" "sh" "bash" "ps" "ls" "df" "du" "free" "uptime" "hostname" "uname" "id" "env" "printenv" "set" "pwd" "dir" "more" "cat" "tail" "head" "less" "echo" "out" "output" "input" "ip" "ifconfig" "netstat" "route" "arp" "iwconfig" "ipconfig" "tracert" "nslookup" "ping" "path" "folder" "f" "dir" "loc" "host")
    
    local cmdi_test_urls=()
    for param in "${cmdi_params[@]}"; do
        cmdi_test_urls+=("${target_url}?${param}=PAYLOAD")
    done
    
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if [[ "$url" == *"?"* ]]; then
                cmdi_test_urls+=("${url}&cmd=PAYLOAD")
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    local cmdi_findings=0
    local cmdi_indicators=("uid=" "gid=" "www-data" "root" "bin" "sbin" "Linux" "UNAME" "uname" "load average" "MemTotal" "SwapTotal" "CPU" "processor" "nodev" "proc" "VULNERABLE" "SEPARATOR")
    
    # Time-based detection commands
    local time_payloads=("; sleep 5" "| sleep 5" "& sleep 5" "&& sleep 5" "`sleep 5`" "$(sleep 5)")
    
    for base_url_info in "${cmdi_test_urls[@]}"; do
        local url_base="${base_url_info/PAYLOAD/__PAYLOAD__}"
        
        for payload in "${payloads[@]}"; do
            [[ -z "$payload" ]] && continue
            [[ "$payload" =~ ^# ]] && continue
            
            # Skip destructive commands in safe mode
            if [[ "$DANGER_MODE" != "true" ]]; then
                if [[ "$payload" =~ rm\ |dd\ |mkfs|fdisk|halt|reboot|poweroff|shutdown ]]; then
                    continue
                fi
            fi
            
            # Generate bypass variants
            local variants=("$payload")
            
            # URL encoded
            local encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null)
            [[ -n "$encoded" ]] && variants+=("$encoded")
            
            # Double URL encode
            local double_encoded=$(python3 -c "import urllib.parse; p=urllib.parse.quote('$payload', safe=''); print(urllib.parse.quote(p, safe=''))" 2>/dev/null)
            [[ -n "$double_encoded" ]] && variants+=("$double_encoded")
            
            # Newline encoded
            if [[ "$payload" != *%0a* ]]; then
                local newline_var="${payload/;/;%0a}"
                [[ "$newline_var" != "$payload" ]] && variants+=("$newline_var")
            fi
            
            for variant in "${variants[@]}"; do
                [[ -z "$variant" ]] && continue
                
                if [[ "$url_base" == *"__PAYLOAD__"* ]]; then
                    local final_url="${url_base/__PAYLOAD__/$variant}"
                else
                    local final_url="$url_base$variant"
                fi
                
                local delay=$(get_request_delay)
                sleep "$delay"
                
                # Time-based detection
                local is_time_based=false
                for tp in "${time_payloads[@]}"; do
                    if [[ "$variant" == *"$tp"* || "$variant" == *"sleep 5"* ]]; then
                        is_time_based=true
                        break
                    fi
                done
                
                local response=""
                local response_time=0
                
                if [[ "$is_time_based" == "true" ]]; then
                    local start_t=$(date +%s%N)
                    response=$(waf_request "$final_url" "GET")
                    local end_t=$(date +%s%N)
                    response_time=$(( (end_t - start_t) / 1000000 ))
                else
                    response=$(waf_request "$final_url" "GET")
                fi
                
                local detected=false
                local evidence=""
                
                # Content-based detection
                for indicator in "${cmdi_indicators[@]}"; do
                    if echo "$response" | grep -qiF "$indicator" 2>/dev/null; then
                        detected=true
                        evidence="Command output indicator: '$indicator'"
                        break
                    fi
                done
                
                # Time-based detection
                if [[ "$is_time_based" == "true" && "$response_time" -gt 4000 ]]; then
                    detected=true
                    evidence="Time delay detected: ${response_time}ms"
                fi
                
                # Error-based detection
                if echo "$response" | grep -qi "command not found\|not recognized\|sh:.*not found\|bash:.*not found\|syntax error\|unexpected token" 2>/dev/null; then
                    detected=true
                    evidence="Command execution attempted (error in output)"
                fi
                
                if [[ "$detected" == "true" ]]; then
                    cmdi_findings+=1
                    local evidence_file="$vuln_output/cmdi_evidence_${cmdi_findings}.txt"
                    echo "URL: $final_url" > "$evidence_file"
                    echo "Payload: $variant" >> "$evidence_file"
                    echo "Response time: ${response_time}ms" >> "$evidence_file"
                    echo "Evidence: $evidence" >> "$evidence_file"
                    echo "--- Response (first 500 chars) ---" >> "$evidence_file"
                    echo "$response" | head -c 500 >> "$evidence_file"
                    
                    local severity="HIGH"
                    if [[ "$evidence" == *"Time delay"* || "$response" == *"uid="* ]]; then
                        severity="CRITICAL"
                    fi
                    
                    record_finding "$severity" "Command Injection in $(echo "$final_url" | sed 's/?.*/?.../')" "Payload: $(echo "$variant" | cut -c1-60) | $evidence" "Avoid passing user input to system commands. Use language-native APIs instead." "$evidence_file"
                    break
                fi
            done
        done
    done
    
    if [[ "$cmdi_findings" -eq 0 ]]; then
        log_ok "No command injection vulnerabilities detected with ${#payloads[@]} payloads"
    fi
}

# =============================================================================
# SSRF CHECK
# =============================================================================
check_ssrf() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "SSRF Testing"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base SSRF payloads"
    
    local ssrf_params=("url" "uri" "link" "src" "href" "source" "file" "image" "img" "css" "js" "data" "target" "endpoint" "dest" "destination" "redirect" "proxy" "path" "location" "site" "html" "load" "read" "fetch" "domain" "host" "server" "remote" "feed" "upload" "download" "import")
    
    local ssrf_findings=0
    local ssrf_test_urls=()
    
    for param in "${ssrf_params[@]}"; do
        ssrf_test_urls+=("${target_url}?${param}=PAYLOAD")
    done
    
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if [[ "$url" == *"?"* ]]; then
                ssrf_test_urls+=("${url}&ssrf=PAYLOAD")
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    # Quick test - check for port knocking on localhost
    log_info "Testing for basic SSRF (localhost probe)..."
    
    for base_url_info in "${ssrf_test_urls[@]}"; do
        local url_base="${base_url_info/PAYLOAD/__PAYLOAD__}"
        
        # Test a few key payloads (127.0.0.1:22, 169.254.169.254, file:///etc/passwd)
        local test_payloads=(
            "http://127.0.0.1:22"
            "http://127.0.0.1:80"
            "http://169.254.169.254/latest/meta-data/"
            "file:///etc/passwd"
        )
        
        for payload in "${test_payloads[@]}"; do
            local encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null)
            
            for variant in "$payload" "$encoded"; do
                [[ -z "$variant" ]] && continue
                
                if [[ "$url_base" == *"__PAYLOAD__"* ]]; then
                    local final_url="${url_base/__PAYLOAD__/$variant}"
                else
                    local final_url="$url_base$variant"
                fi
                
                local response=$(waf_request "$final_url" "GET")
                
                local detected=false
                local evidence=""
                
                if [[ "$payload" == *"169.254"* ]] && echo "$response" | grep -qi "ami-id\|meta-data\|instance\|security-credentials\|role" 2>/dev/null; then
                    detected=true
                    evidence="Cloud metadata accessible via SSRF"
                elif [[ "$payload" == *"file:"* ]] && echo "$response" | grep -qi "root:\|daemon:\|www-data:" 2>/dev/null; then
                    detected=true
                    evidence="Local file read via SSRF (file://)"
                elif [[ "$payload" == *"127.0.0.1:"* ]] && [[ -n "$response" && ${#response} -gt 100 ]]; then
                    detected=true
                    evidence="Internal service accessible via SSRF on port $(echo "$payload" | grep -oP ':\K[0-9]+')"
                fi
                
                if [[ "$detected" == "true" ]]; then
                    ssrf_findings+=1
                    local evidence_file="$vuln_output/ssrf_evidence_${ssrf_findings}.txt"
                    echo "URL: $final_url" > "$evidence_file"
                    echo "Payload: $variant" >> "$evidence_file"
                    echo "Response size: $(echo "$response" | wc -c)" >> "$evidence_file"
                    echo "--- Response (first 300 chars) ---" >> "$evidence_file"
                    echo "$response" | head -c 300 >> "$evidence_file"
                    
                    record_finding "CRITICAL" "SSRF in $(echo "$final_url" | sed 's/?.*/?.../')" "Payload: $payload | $evidence" "Validate and restrict URLs to trusted domains. Block private IP ranges." "$evidence_file"
                    break 2
                fi
            done
        done
    done
    
    if [[ "$ssrf_findings" -eq 0 ]]; then
        log_ok "No obvious SSRF vulnerabilities detected"
    fi
}

# =============================================================================
# SSTI CHECK
# =============================================================================
check_ssti() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "SSTI Testing"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base SSTI payloads"
    
    local ssti_params=("name" "user" "username" "message" "template" "view" "page" "file" "include" "content" "title" "text" "body" "subject" "q" "search" "s" "data" "input" "form" "field" "param" "value")
    
    local ssti_findings=0
    local ssti_test_urls=()
    
    for param in "${ssti_params[@]}"; do
        ssti_test_urls+=("${target_url}?${param}=PAYLOAD")
    done
    
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if [[ "$url" == *"?"* ]]; then
                ssti_test_urls+=("${url}&ssti=PAYLOAD")
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    log_info "Testing for Template Injection..."
    
    # Quick test: check for basic math evaluation
    local math_payloads=("{{7*7}}" '${7*7}' '<%= 7*7 %>' "#{7*7}" "{{7*'7'}}")
    local math_results=("49" "49" "49" "49" "7777777")
    
    for base_url_info in "${ssti_test_urls[@]}"; do
        local url_base="${base_url_info/PAYLOAD/__PAYLOAD__}"
        
        for i in "${!math_payloads[@]}"; do
            local payload="${math_payloads[$i]}"
            local expected="${math_results[$i]}"
            
            if [[ "$url_base" == *"__PAYLOAD__"* ]]; then
                local final_url="${url_base/__PAYLOAD__/$payload}"
            else
                local final_url="$url_base$payload"
            fi
            
            local response=$(waf_request "$final_url" "GET")
            
            if echo "$response" | grep -qF "$expected" 2>/dev/null; then
                ssti_findings+=1
                local evidence_file="$vuln_output/ssti_evidence_${ssti_findings}.txt"
                echo "URL: $final_url" > "$evidence_file"
                echo "Payload: $payload (expected: $expected)" >> "$evidence_file"
                echo "--- Response (first 300 chars) ---" >> "$evidence_file"
                echo "$response" | head -c 300 >> "$evidence_file"
                
                record_finding "CRITICAL" "SSTI in $(echo "$final_url" | sed 's/?.*/?.../')" "Template engine evaluated: $payload -> $expected" "Disable template engine evaluation in user-facing inputs. Use sandboxed templates." "$evidence_file"
                break 2
            fi
        done
    done
    
    if [[ "$ssti_findings" -eq 0 ]]; then
        log_ok "No server-side template injection detected"
    fi
}

# =============================================================================
# XXE CHECK
# =============================================================================
check_xxe() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "XXE Testing"
    
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    
    log_info "Loaded ${#payloads[@]} base XXE payloads"
    
    local xxe_endpoints=("/api" "/api/upload" "/xml" "/soap" "/api/xml" "/ws" "/webservice" "/rest" "/api/v1" "/graphql" "/api/graphql" "${target_url%/}")
    
    local xxe_findings=0
    
    log_info "Testing for XML External Entity injection..."
    
    for endpoint in "${xxe_endpoints[@]}"; do
        local full_endpoint="${target_url}${endpoint}"
        
        for payload in "${payloads[@]}"; do
            [[ -z "$payload" ]] && continue
            [[ "$payload" =~ ^# ]] && continue
            
            local delay=$(get_request_delay)
            sleep "$delay"
            
            local response=$(waf_request "$full_endpoint" "POST" "$payload" "application/xml")
            if [[ -z "$response" ]]; then
                response=$(waf_request "$full_endpoint" "POST" "$payload" "text/xml")
            fi
            
            local detected=false
            local evidence=""
            
            # Check for file content in response
            if echo "$response" | grep -qi "root:\|daemon:\|www-data:\|nobody:\|\[.*inet\]\|127.0.0.1" 2>/dev/null; then
                detected=true
                evidence="File content read via XXE"
            # Check for SSRF indicators
            elif echo "$response" | grep -qi "ami-id\|meta-data\|security-credentials\|instance-id" 2>/dev/null; then
                detected=true
                evidence="Cloud metadata accessible via XXE"
            # Check for PHP wrapper output
            elif echo "$response" | grep -qiP "^[A-Za-z0-9+/=]{20,}" 2>/dev/null; then
                detected=true
                evidence="Base64 encoded content (PHP wrapper)"
            fi
            
            if [[ "$detected" == "true" ]]; then
                xxe_findings+=1
                local evidence_file="$vuln_output/xxe_evidence_${xxe_findings}.txt"
                echo "Endpoint: $full_endpoint" > "$evidence_file"
                echo "Payload: $(echo "$payload" | cut -c1-100)" >> "$evidence_file"
                echo "Evidence: $evidence" >> "$evidence_file"
                echo "--- Response (first 500 chars) ---" >> "$evidence_file"
                echo "$response" | head -c 500 >> "$evidence_file"
                
                record_finding "CRITICAL" "XXE in $endpoint" "Endpoint processes XML without disabling external entities | $evidence" "Disable external entity processing in XML parser. Use JSON where possible." "$evidence_file"
                break
            fi
        done
    done
    
    if [[ "$xxe_findings" -eq 0 ]]; then
        log_ok "No XXE vulnerabilities detected"
    fi
}

# =============================================================================
# OPEN REDIRECT CHECK
# =============================================================================
check_open_redirect() {
    local target_url="$1"
    local output="$2"
    local payload_file="$3"
    
    log_banner "Open Redirect Testing"
    
    local redirect_findings=0
    [[ -z "$vuln_output" ]] && local vuln_output="$output/vuln_checks" && mkdir -p "$vuln_output"
    
    # 1. Payload-based redirect testing
    local payloads=()
    if [[ -f "$payload_file" ]]; then
        mapfile -t payloads < <(grep -v '^#' "$payload_file" | grep -v '^$')
    fi
    log_info "Loaded ${#payloads[@]} open redirect payloads"
    log_info "Testing for open redirect vulnerabilities..."
    
    local test_domain=$(echo "$target_url" | sed -E 's|^https?://||' | cut -d/ -f1)
    local test_domain_escaped=$(printf '%s\n' "$test_domain" | sed 's/\./\\./g')
    
    for payload in "${payloads[@]}"; do
        [[ -z "$payload" ]] && continue
        [[ "$payload" =~ ^# ]] && continue
        
        local test_url="${target_url}$payload"
        local delay=$(get_request_delay)
        sleep "$delay"
        
        local final_url=$(curl -s -k -L -o /dev/null -w "%{url_effective}" --max-time "$TIMEOUT" "$test_url" 2>/dev/null)
        
        if [[ -n "$final_url" && "$final_url" != "$test_url" ]]; then
            local final_domain=$(echo "$final_url" | sed -E 's|^https?://([^/]+).*|\1|')
            
            if ! echo "$final_domain" | grep -qiE "^${test_domain_escaped}$"; then
                redirect_findings+=1
                local evidence_file="$vuln_output/redirect_evidence_${redirect_findings}.txt"
                echo "Test URL: $test_url" > "$evidence_file"
                echo "Redirect URL: $final_url" >> "$evidence_file"
                echo "Original Domain: $test_domain" >> "$evidence_file"
                echo "Redirect Domain: $final_domain" >> "$evidence_file"
                record_finding "MEDIUM" "Open Redirect in $(echo "$payload" | cut -c1-50)" "Redirects to: $final_domain | Payload: $payload" "Do not accept user-controlled URLs. Use whitelist-based redirects." "$evidence_file"
            fi
        fi
    done
    
    # 2. HTTP method-based redirect test (POST redirects)
    log_info "Testing POST-based redirects..."
    local post_payloads=(
        "?url=http://evil.com"
        "?redirect=http://evil.com"
        "?next=http://evil.com"
    )
    for pp in "${post_payloads[@]}"; do
        local test_url="${target_url}${pp}"
        local final_url=$(curl -s -k -L -o /dev/null -w "%{url_effective}" --max-time "$TIMEOUT" -X POST "$test_url" 2>/dev/null)
        if [[ -n "$final_url" && "$final_url" != "$test_url" ]]; then
            local final_domain=$(echo "$final_url" | sed -E 's|^https?://([^/]+).*|\1|')
            if ! echo "$final_domain" | grep -qiE "^${test_domain_escaped}$"; then
                redirect_findings+=1
                record_finding "MEDIUM" "Open Redirect via POST in $(echo "$pp" | cut -c1-40)" "Redirects to: $final_domain | Method: POST | Payload: $pp" "Do not accept user-controlled URLs in POST handlers." ""
            fi
        fi
    done
    
    # 3. Header-based redirect test (X-Forwarded-Host injection)
    log_info "Testing header-based redirects..."
    local header_redirect_payloads=(
        "?url=http://evil.com"
        "?dest=http://evil.com"
    )
    for hp in "${header_redirect_payloads[@]}"; do
        local test_url="${target_url}${hp}"
        local final_url=$(curl -s -k -L -o /dev/null -w "%{url_effective}" --max-time "$TIMEOUT" -H "X-Forwarded-Host: evil.com" "$test_url" 2>/dev/null)
        if [[ -n "$final_url" && "$final_url" != "$test_url" ]]; then
            local final_domain=$(echo "$final_url" | sed -E 's|^https?://([^/]+).*|\1|')
            if echo "$final_domain" | grep -qi "evil.com\|attacker"; then
                redirect_findings+=1
                record_finding "MEDIUM" "Open Redirect via Header Injection" "Redirects to: $final_domain | Header: X-Forwarded-Host: evil.com | Payload: $hp" "Validate all input and do not trust forwarded headers." ""
            fi
        fi
    done
    
    if [[ "$redirect_findings" -eq 0 ]]; then
        log_ok "No open redirect vulnerabilities detected"
    fi
}

# =============================================================================
# CSRF CHECK
# =============================================================================
check_csrf() {
    local target_url="$1"
    local output="$2"
    
    log_banner "Cross-Site Request Forgery (CSRF) Testing"
    
    [[ -z "$vuln_output" ]] && local vuln_output="$output/vuln_checks" && mkdir -p "$vuln_output"
    local csrf_output="$vuln_output/csrf_check.txt"
    local csrf_findings=0
    
    # 1. Check for anti-CSRF tokens in forms
    log_info "Checking for CSRF tokens in forms..."
    local index_content=$(waf_request "$target_url" "GET" "" "")
    
    # Extract all forms
    local forms=$(echo "$index_content" | grep -oiP '<form[^>]*>.*?</form>' 2>/dev/null || echo "")
    if [[ -z "$forms" ]]; then
        forms=$(echo "$index_content" | grep -oiP '<form[^>]*>' 2>/dev/null)
    fi
    
    local form_count=0
    local unprotected_forms=0
    
    if [[ -n "$forms" ]]; then
        while IFS= read -r form; do
            [[ -z "$form" ]] && continue
            form_count+=1
            
            local form_action=$(echo "$form" | grep -oiP 'action=["'\'']([^"'\'']*)["'\'']' | head -1 | sed 's/action=["'\'']//;s/["'\'']$//')
            local form_method=$(echo "$form" | grep -oiP 'method=["'\'']([^"'\'']*)["'\'']' | head -1 | sed 's/method=["'\'']//;s/["'\'']$//')
            local form_has_token=false
            
            # Check for common CSRF token patterns in form fields
            if echo "$form" | grep -qiP '(csrf|_token|_csrf|csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|xsrf|x-csrf|nonce|state)' 2>/dev/null; then
                form_has_token=true
            fi
            
            # Check for hidden fields that might be tokens
            local hidden_fields=$(echo "$form" | grep -oiP '<input[^>]*type=["'\'']hidden["'\''][^>]*>' 2>/dev/null)
            if [[ -n "$hidden_fields" ]]; then
                while IFS= read -r hidden; do
                    [[ -z "$hidden" ]] && continue
                    local hidden_name=$(echo "$hidden" | grep -oiP 'name=["'\'']([^"'\'']*)["'\'']' | head -1 | sed 's/name=["'\'']//;s/["'\'']$//')
                    local hidden_val=$(echo "$hidden" | grep -oiP 'value=["'\'']([^"'\'']*)["'\'']' | head -1 | sed 's/value=["'\'']//;s/["'\'']$//')
                    
                    # Token-like fields usually have opaque values
                    if [[ ${#hidden_val} -ge 20 ]] || echo "$hidden_name" | grep -qiP '(token|nonce|state|csrf)' 2>/dev/null; then
                        form_has_token=true
                    fi
                done <<< "$hidden_fields"
            fi
            
            if [[ "$form_has_token" == false ]]; then
                unprotected_forms+=1
                local form_info="Form #$form_count (action: ${form_action:-N/A}, method: ${form_method:-GET})"
                echo "$form_info" >> "$csrf_output"
                echo "$form" >> "$csrf_output"
                echo "---" >> "$csrf_output"
            fi
        done <<< "$forms"
    fi
    
    if [[ "$unprotected_forms" -gt 0 ]]; then
        log_medium "$unprotected_forms form(s) without CSRF protection"
        record_finding "MEDIUM" "CSRF: $unprotected_forms form(s) missing anti-CSRF tokens" "$unprotected_forms form(s) lack CSRF protection tokens. See $csrf_output for details." "Implement anti-CSRF tokens (e.g., CSRF token, SameSite cookies, or custom headers)." "$csrf_output"
    else
        log_ok "All forms appear to have CSRF protection ($form_count forms checked)"
    fi
    
    # 2. Test CSRF by removing/replacing known token parameters
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        log_info "Testing CSRF by tampering with token parameters..."
        local token_params=(
            "csrf_token=attacker_token"
            "csrfmiddlewaretoken=attacker_token"
            "_token=attacker_token"
            "authenticity_token=attacker_token"
            "__RequestVerificationToken=attacker_token"
            "xsrf_token=attacker_token"
        )
        
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local base_url=$(echo "$url" | sed 's/\?.*//')
            for tp in "${token_params[@]}"; do
                local tamper_url="${base_url}?${tp}"
                local tamper_response=$(waf_request "$tamper_url" "POST" "$tp" "application/x-www-form-urlencoded")
                local response_size=$(echo "$tamper_response" | wc -c)
                
                # Compare with baseline
                local baseline=$(waf_request "$base_url" "GET" "" "")
                local baseline_size=$(echo "$baseline" | wc -c)
                
                # If tampered request returns similar size to baseline, token might not be validated
                local size_diff=$((response_size - baseline_size))
                if [[ ${size_diff#-} -lt 100 ]]; then
                    csrf_findings+=1
                    record_finding "LOW" "CSRF: Token validation may be weak at $url" "Response with tampered token ($tp) is similar in size to baseline (diff: $size_diff bytes). Token may not be validated server-side." "Ensure CSRF tokens are properly validated on every state-changing request." ""
                    break
                fi
            done
        done < "$output/all_discovered_urls.txt"
    fi
    
    # 3. Check SameSite cookie attribute (already in check_security_headers but double-check)
    log_info "Re-checking Cookie SameSite attributes..."
    local headers=$(curl -s -k -I --max-time "$TIMEOUT" "$target_url" 2>/dev/null)
    local cookies=$(echo "$headers" | grep -i "Set-Cookie" 2>/dev/null)
    if [[ -n "$cookies" ]]; then
        while IFS= read -r cookie; do
            [[ -z "$cookie" ]] && continue
            if ! echo "$cookie" | grep -qi "SameSite"; then
                log_warn "Cookie missing SameSite attribute: $(echo "$cookie" | cut -d: -f2 | cut -c1-40)"
                record_finding "LOW" "CSRF: Cookie missing SameSite attribute" "Without SameSite, browsers may send this cookie on cross-origin requests, enabling CSRF." "Add SameSite=Lax or SameSite=Strict to all cookies." ""
            fi
        done <<< "$cookies"
    fi
    
    if [[ "$csrf_findings" -eq 0 ]]; then
        log_ok "No additional CSRF weaknesses detected"
    fi
}

# =============================================================================
# IDOR CHECK
# =============================================================================
check_idor() {
    local target_url="$1"
    local output="$2"
    
    log_banner "Insecure Direct Object Reference (IDOR) Testing"
    
    [[ -z "$vuln_output" ]] && local vuln_output="$output/vuln_checks" && mkdir -p "$vuln_output"
    local idor_output="$vuln_output/idor_check.txt"
    local idor_findings=0
    
    # Extract potential numeric IDs from URLs
    log_info "Analyzing URLs for sequential IDs..."
    
    local test_urls_file="$output/all_discovered_urls.txt"
    local urls_with_ids=()
    
    if [[ -f "$test_urls_file" ]]; then
        # Find URLs containing numeric IDs
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if echo "$url" | grep -qiP '(id|user|uid|pid|order|invoice|ticket|account|profile|document|file|page|article|post|product)=[0-9]+' 2>/dev/null; then
                urls_with_ids+=("$url")
            fi
        done < "$test_urls_file"
    fi
    
    # Also check main target for ID-like parameters
    local id_params=("id" "user_id" "uid" "pid" "order_id" "invoice" "ticket" "account" "profile_id" "document_id" "file_id" "page" "article" "post_id" "product_id" "cat_id")
    for param in "${id_params[@]}"; do
        urls_with_ids+=("${target_url}?${param}=1")
    done
    
    if [[ ${#urls_with_ids[@]} -eq 0 ]]; then
        log_info "No URLs with numeric IDs found to test"
        return
    fi
    
    log_info "Found ${#urls_with_ids[@]} URL(s) with potential IDs"
    
    # For each URL with an ID, try nearby IDs
    for orig_url in "${urls_with_ids[@]}"; do
        [[ -z "$orig_url" ]] && continue
        
        local base_url=$(echo "$orig_url" | sed -E 's/(id|user_id|uid|pid|order_id|invoice|ticket|account|profile_id|document_id|file_id|page|article|post_id|product_id|cat_id)=[0-9]+/\1=ID_PLACEHOLDER/')
        local param_name=$(echo "$orig_url" | grep -oiP '(id|user_id|uid|pid|order_id|invoice|ticket|account|profile_id|document_id|file_id|page|article|post_id|product_id|cat_id)=' | sed 's/=//')
        local orig_id=$(echo "$orig_url" | grep -oiP "${param_name}=[0-9]+" | sed "s/${param_name}=//")
        
        # Skip if no numeric ID found
        [[ -z "$orig_id" ]] && continue
        
        log_info "Testing IDOR on $param_name (original=$orig_id)..."
        
        # Get baseline response for original ID
        local delay=$(get_request_delay)
        sleep "$delay"
        local baseline_url=$(echo "$base_url" | sed "s/ID_PLACEHOLDER/$orig_id/")
        local baseline_response=$(waf_request "$baseline_url" "GET" "" "")
        local baseline_size=$(echo "$baseline_response" | wc -c)
        local baseline_title=$(echo "$baseline_response" | grep -oiP '<title>[^<]*</title>' 2>/dev/null | head -1)
        
        # Test nearby numeric IDs
        local test_ids=()
        [[ "$orig_id" -gt 1 ]] && test_ids+=($((orig_id - 1)))
        test_ids+=($((orig_id + 1)))
        test_ids+=($((orig_id + 100)))
        test_ids+=($((orig_id * 10)))
        
        local numeric_match_count=0
        local numeric_diff_count=0
        local match_details=""
        
        for test_id in "${test_ids[@]}"; do
            local test_url=$(echo "$base_url" | sed "s/ID_PLACEHOLDER/$test_id/")
            local delay2=$(get_request_delay)
            sleep "$delay2"
            local test_response=$(waf_request "$test_url" "GET" "" "")
            local test_size=$(echo "$test_response" | wc -c)
            local test_title=$(echo "$test_response" | grep -oiP '<title>[^<]*</title>' 2>/dev/null | head -1)
            local size_diff=$((test_size - baseline_size))
            
            if [[ ${size_diff#-} -lt 500 ]] && [[ "$test_title" == "$baseline_title" ]]; then
                numeric_match_count+=1
                match_details+="  $param_name=$test_id (diff: $size_diff bytes)\n"
            else
                numeric_diff_count+=1
            fi
        done
        
        # If all numeric IDs return the SAME content, the param is ignored → skip
        # If some return similar and some return different → param is processed → report
        if [[ "$numeric_match_count" -gt 0 ]] && [[ "$numeric_diff_count" -gt 0 ]] && [[ "$numeric_match_count" -ge 2 ]]; then
            idor_findings+=1
            local evidence_file="$vuln_output/idor_evidence_${idor_findings}.txt"
            {
                echo "Original URL: $orig_url (ID: $orig_id)"
                echo ""
                echo "IDs returning similar content to baseline:"
                printf "$match_details"
                echo ""
                echo "$numeric_diff_count ID(s) returned different content (param is actively processed)"
                echo "Baseline Size: $baseline_size bytes"
                echo "Baseline Title: $baseline_title"
            } > "$evidence_file"
            record_finding "HIGH" "Potential IDOR: $param_name at $(echo "$orig_url" | cut -c1-80)" "Numeric IDs ($numeric_match_count of $((numeric_match_count + numeric_diff_count))) return similar content. Parameter is actively processed by application." "Implement proper access controls. Do not rely on hidden or sequential IDs for authorization." "$evidence_file"
        elif [[ "$numeric_match_count" -eq "${#test_ids[@]}" ]]; then
            log_info "  All test IDs returned identical content for $param_name (parameter likely ignored by application)"
        fi
    done
    
    if [[ "$idor_findings" -eq 0 ]]; then
        log_ok "No IDOR vulnerabilities detected"
    fi
}

# =============================================================================
# JWT CHECK
# =============================================================================
check_jwt() {
    local target_url="$1"
    local output="$2"
    
    log_banner "JWT Security Testing"
    
    [[ -z "$vuln_output" ]] && local vuln_output="$output/vuln_checks" && mkdir -p "$vuln_output"
    local jwt_output="$vuln_output/jwt_check.txt"
    local jwt_findings=0
    
    # 1. Extract JWT tokens from cookies, headers, and response body
    log_info "Extracting JWT tokens..."
    local response=$(curl -s -k -I --max-time "$TIMEOUT" "$target_url" 2>/dev/null)
    local body=$(waf_request "$target_url" "GET" "" "")
    
    local all_jwts=()
    
    # Check Set-Cookie headers for JWT
    local cookies=$(echo "$response" | grep -i "Set-Cookie" 2>/dev/null)
    if [[ -n "$cookies" ]]; then
        while IFS= read -r cookie; do
            [[ -z "$cookie" ]] && continue
            # JWT pattern: base64.base64.base64
            local jwt=$(echo "$cookie" | grep -oiP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' 2>/dev/null)
            [[ -n "$jwt" ]] && all_jwts+=("$jwt")
        done <<< "$cookies"
    fi
    
    # Check Authorization header
    local auth_header=$(echo "$response" | grep -i "Authorization" 2>/dev/null)
    if [[ -n "$auth_header" ]]; then
        local jwt=$(echo "$auth_header" | grep -oiP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' 2>/dev/null)
        [[ -n "$jwt" ]] && all_jwts+=("$jwt")
    fi
    
    # Check response body for JWT in scripts or JSON
    local body_jwts=$(echo "$body" | grep -oiP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' 2>/dev/null)
    if [[ -n "$body_jwts" ]]; then
        while IFS= read -r j; do
            [[ -n "$j" ]] && all_jwts+=("$j")
        done <<< "$body_jwts"
    fi
    
    # Check for JWT in common locations like /api/auth endpoints
    local jwt_endpoints=(
        "${target_url}/api/auth"
        "${target_url}/api/login"
        "${target_url}/api/token"
        "${target_url}/auth"
        "${target_url}/login"
        "${target_url}/oauth/token"
    )
    for ep in "${jwt_endpoints[@]}"; do
        local ep_response=$(waf_request "$ep" "POST" "" "application/json" 2>/dev/null)
        local ep_jwt=$(echo "$ep_response" | grep -oiP 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' 2>/dev/null)
        [[ -n "$ep_jwt" ]] && all_jwts+=("$ep_jwt")
    done
    
    # Remove duplicates
    local unique_jwts=()
    if [[ ${#all_jwts[@]} -gt 0 ]]; then
        while IFS= read -r jwt; do
            [[ -n "$jwt" ]] && unique_jwts+=("$jwt")
        done < <(printf '%s\n' "${all_jwts[@]}" | sort -u)
    fi
    
    if [[ ${#unique_jwts[@]} -eq 0 ]]; then
        log_info "No JWT tokens found on the target"
        log_ok "JWT check complete (no tokens to test)"
        return
    fi
    
    log_info "Found ${#unique_jwts[@]} unique JWT token(s)"
    
    for jwt_token in "${unique_jwts[@]}"; do
        [[ -z "$jwt_token" ]] && continue
        
        local evidence_file="$vuln_output/jwt_analysis_${jwt_findings}.txt"
        {
            echo "=== JWT Token Analysis ==="
            echo "Token: $jwt_token"
            echo ""
        } > "$evidence_file"
        
        # 2. Decode JWT header
        log_info "Analyzing JWT token..."
        local header_b64=$(echo "$jwt_token" | cut -d. -f1)
        local payload_b64=$(echo "$jwt_token" | cut -d. -f2)
        
        # Base64 decode with padding
        local header_decode=$(echo "${header_b64}=" | sed 's/-/+/g; s/_/\//g' 2>/dev/null)
        local payload_decode=$(echo "${payload_b64}=" | sed 's/-/+/g; s/_/\//g' 2>/dev/null)
        
        local header_json=$(echo "$header_decode" | base64 -d 2>/dev/null || echo "decode_failed")
        local payload_json=$(echo "$payload_decode" | base64 -d 2>/dev/null || echo "decode_failed")
        
        {
            echo "--- Header (decoded) ---"
            echo "$header_json"
            echo ""
            echo "--- Payload (decoded) ---"
            echo "$payload_json"
            echo ""
        } >> "$evidence_file"
        
        # 3. Check algorithm
        local alg=$(echo "$header_json" | grep -oiP '"alg":\s*"[^"]*"' | head -1 | sed 's/"alg": *"//;s/"//')
        
        if [[ -n "$alg" ]]; then
            log_info "Token algorithm: $alg"
            
            # Test "none" algorithm bypass
            if echo "$alg" | grep -qiP '(none|null|None|nOnE|NONE)' 2>/dev/null; then
                jwt_findings+=1
                record_finding "CRITICAL" "JWT: 'none' algorithm allowed" "JWT token uses 'none' algorithm, allowing forged tokens without signature verification." "Configure JWT library to reject 'none' algorithm. Always verify signatures." "$evidence_file"
            fi
            
            # Check for weak HMAC algorithms
            if echo "$alg" | grep -qiP '(HS256|HS384|HS512)' 2>/dev/null; then
                log_info "Token uses symmetric HMAC algorithm: $alg"
                record_finding "INFO" "JWT: Symmetric algorithm used ($alg)" "JWT uses HMAC-based algorithm. If secret is weak, token forgery is possible." "Use asymmetric algorithms (RS256/ES256) for server-to-server tokens." ""
            fi
        fi
        
        # 4. Check for common weak secrets in payload
        if [[ "$payload_json" != "decode_failed" ]]; then
            local sub=$(echo "$payload_json" | grep -oiP '"sub":\s*"[^"]*"' | head -1)
            local role=$(echo "$payload_json" | grep -oiP '"role":\s*"[^"]*"' | head -1)
            local admin=$(echo "$payload_json" | grep -oiP '"admin":\s*(true|false)' | head -1)
            
            [[ -n "$sub" ]] && log_info "Subject: $sub"
            [[ -n "$role" ]] && log_info "Role: $role"
            [[ -n "$admin" ]] && log_info "Admin: $admin"
            
            {
                [[ -n "$sub" ]] && echo "Subject: $sub"
                [[ -n "$role" ]] && echo "Role: $role"
                [[ -n "$admin" ]] && echo "Admin: $admin"
            } >> "$evidence_file"
        fi
        
        # 5. Test JWT with kid injection (if kid exists in header)
        local kid=$(echo "$header_json" | grep -oiP '"kid":\s*"[^"]*"' 2>/dev/null | head -1)
        if [[ -n "$kid" ]]; then
            log_info "Token has kid header, testing KID injection..."
            log_warn "KID injection requires base64-encoded forged tokens - manual testing recommended"
            record_finding "MEDIUM" "JWT: kid header present (potential KID injection)" "JWT contains kid (Key ID) header. If not properly validated, attacker can inject path traversal or SQLi via kid." "Validate kid against a whitelist. Do not use kid in file system operations." ""
        fi
        
        # 6. Check for jwk/jku in header
        local jwk=$(echo "$header_json" | grep -oiP '"jwk"' 2>/dev/null)
        local jku=$(echo "$header_json" | grep -oiP '"jku"' 2>/dev/null)
        if [[ -n "$jwk" ]]; then
            jwt_findings+=1
            record_finding "CRITICAL" "JWT: Embedded JWK in header (JWK injection)" "JWT contains embedded JWK (JSON Web Key). Server may accept attacker-supplied public keys." "Disable embedded JWK. Use a trusted JWKS endpoint." "$evidence_file"
        fi
        if [[ -n "$jku" ]]; then
            jwt_findings+=1
            record_finding "CRITICAL" "JWT: JKU in header (JKU injection)" "JWT contains JKU (JWK Set URL) header. Server may fetch keys from attacker-controlled URL." "Validate JKU against a whitelist of trusted URLs." "$evidence_file"
        fi
    done
    
    if [[ "$jwt_findings" -eq 0 ]]; then
        log_ok "No JWT vulnerabilities detected"
    fi
}

# =============================================================================
# GRAPHQL CHECK
# =============================================================================
check_graphql() {
    local target_url="$1"
    local output="$2"
    
    log_banner "GraphQL Security Testing"
    
    [[ -z "$vuln_output" ]] && local vuln_output="$output/vuln_checks" && mkdir -p "$vuln_output"
    local graphql_output="$vuln_output/graphql_check.txt"
    local graphql_findings=0
    
    # 1. Discover GraphQL endpoints
    log_info "Discovering GraphQL endpoints..."
    
    local graphql_endpoints=()
    local common_endpoints=(
        "${target_url}/graphql"
        "${target_url}/graphql/v1"
        "${target_url}/graphql/v2"
        "${target_url}/api/graphql"
        "${target_url}/api/v1/graphql"
        "${target_url}/api/v2/graphql"
        "${target_url}/gql"
        "${target_url}/api/gql"
        "${target_url}/query"
        "${target_url}/api/query"
        "${target_url}/v1/graphql"
        "${target_url}/v2/graphql"
        "${target_url}/graph"
        "${target_url}/api/graph"
    )
    
    # Check from web enum results too
    if [[ -f "$output/all_discovered_urls.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            if echo "$url" | grep -qi "graphql\|gql\|graph\|query"; then
                graphql_endpoints+=("$url")
            fi
        done < "$output/all_discovered_urls.txt"
    fi
    
    for ep in "${common_endpoints[@]}"; do
        graphql_endpoints+=("$ep")
    done
    
    # Remove duplicates
    local unique_endpoints=()
    if [[ ${#graphql_endpoints[@]} -gt 0 ]]; then
        while IFS= read -r ep; do
            [[ -n "$ep" ]] && unique_endpoints+=("$ep")
        done < <(printf '%s\n' "${graphql_endpoints[@]}" | sort -u)
    fi
    
    log_info "Testing ${#unique_endpoints[@]} potential GraphQL endpoint(s)"
    
    for endpoint in "${unique_endpoints[@]}"; do
        [[ -z "$endpoint" ]] && continue
        
        # 2. Test introspection query
        log_info "Testing introspection on $endpoint..."
        
        local introspection_query='{"query":"query { __schema { types { name fields { name type { name kind } } } } }"}'
        local intro_response=$(curl -s -k --max-time "$TIMEOUT" -X POST \
            -H "Content-Type: application/json" \
            -d "$introspection_query" \
            "$endpoint" 2>/dev/null)
        
        if echo "$intro_response" | grep -qi '"data"' 2>/dev/null; then
            if echo "$intro_response" | grep -qi '"__schema"' 2>/dev/null; then
                graphql_findings+=1
                local evidence_file="$vuln_output/graphql_introspection_${graphql_findings}.txt"
                echo "Endpoint: $endpoint" > "$evidence_file"
                echo "Introspection enabled - full schema can be extracted" >> "$evidence_file"
                echo "$intro_response" | python3 -m json.tool 2>/dev/null >> "$evidence_file" || echo "$intro_response" >> "$evidence_file"
                record_finding "HIGH" "GraphQL Introspection Enabled at $(echo "$endpoint" | sed "s|$target_url||")" "GraphQL introspection query returns schema data. Attackers can enumerate all types, queries, and mutations." "Disable introspection in production. Use a whitelist of allowed queries." "$evidence_file"
            fi
        fi
        
        # 3. Test field-depth DoS (aliases-based batching)
        log_info "Testing alias-based batching on $endpoint..."
        
        # Build a query with many aliases to test depth limits
        local alias_query='{"query":"query { '
        for i in $(seq 1 50); do
            alias_query+="a${i}: __typename "
        done
        alias_query+=' }"}'
        
        local alias_response=$(curl -s -k --max-time "$TIMEOUT" -X POST \
            -H "Content-Type: application/json" \
            -d "$alias_query" \
            "$endpoint" 2>/dev/null)
        
        if echo "$alias_response" | grep -qiP '"a[0-9]+"' 2>/dev/null; then
            graphql_findings+=1
            record_finding "MEDIUM" "GraphQL: Alias-based batching allowed at $(echo "$endpoint" | sed "s|$target_url||")" "Server accepts batched queries with aliases. Potential for DoS or rate-limit bypass (up to 50 aliases accepted)." "Limit query depth and the number of aliases per request. Implement query cost analysis." ""
        fi
        
        # 4. Test mutation access
        log_info "Testing mutation discovery on $endpoint..."
        local mutation_query='{"query":"query { __schema { mutationType { name fields { name type { name kind } } } } }"}'
        local mutation_response=$(curl -s -k --max-time "$TIMEOUT" -X POST \
            -H "Content-Type: application/json" \
            -d "$mutation_query" \
            "$endpoint" 2>/dev/null)
        
        if echo "$mutation_response" | grep -qi '"fields"' 2>/dev/null && echo "$mutation_response" | grep -qi '"name"' 2>/dev/null; then
            local mutations=$(echo "$mutation_response" | python3 -c "import sys,json; d=json.load(sys.stdin); ms=[f['name'] for f in d.get('data',{}).get('__schema',{}).get('mutationType',{}).get('fields',[]) if 'name' in f]; print('\n'.join(ms))" 2>/dev/null)
            if [[ -n "$mutations" ]]; then
                graphql_findings+=1
                echo "Endpoint: $endpoint" > "$vuln_output/graphql_mutations.txt"
                echo "$mutations" >> "$vuln_output/graphql_mutations.txt"
                record_finding "MEDIUM" "GraphQL: Mutations exposed at $(echo "$endpoint" | sed "s|$target_url||")" "GraphQL mutations available: $(echo "$mutations" | tr '\n' ', ')" "Review all mutations for proper authorization. Disable unused mutations." "$vuln_output/graphql_mutations.txt"
            fi
        fi
        
        # 5. Test for error-based information disclosure
        log_info "Testing error-based information disclosure on $endpoint..."
        local error_query='{"query":"query { invalidFieldThatDoesNotExist }"}'
        local error_response=$(curl -s -k --max-time "$TIMEOUT" -X POST \
            -H "Content-Type: application/json" \
            -d "$error_query" \
            "$endpoint" 2>/dev/null)
        
        if echo "$error_response" | grep -qiP '"errors"' 2>/dev/null && echo "$error_response" | grep -qiP '(stack|trace|debug|internal|at |Error:)' 2>/dev/null; then
            graphql_findings+=1
            record_finding "MEDIUM" "GraphQL: Error-based information disclosure at $(echo "$endpoint" | sed "s|$target_url||")" "GraphQL errors reveal stack traces or internal details." "Disable debug mode and stack traces in production GraphQL environments." ""
        fi
    done
    
    if [[ "$graphql_findings" -eq 0 ]]; then
        log_ok "No GraphQL endpoints found or no vulnerabilities detected"
    fi
}

# =============================================================================
# SECURITY HEADERS CHECK
# =============================================================================
check_security_headers() {
    local target_url="$1"
    local output="$2"
    
    log_banner "Security Headers Audit"
    
    local headers_file="$output/headers_check.txt"
    curl -s -k -I -L --max-time "$TIMEOUT" "$target_url" 2>/dev/null > "$headers_file"
    
    log_info "Analyzing HTTP security headers..."
    
    local header_checks=(
        "Strict-Transport-Security:HSTS (Strict-Transport-Security):MEDIUM:Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'"
        "Content-Security-Policy:CSP (Content-Security-Policy):HIGH:Add Content-Security-Policy header to prevent XSS"
        "X-Frame-Options:X-Frame-Options:MEDIUM:Add 'X-Frame-Options: DENY' to prevent clickjacking"
        "X-Content-Type-Options:X-Content-Type-Options:LOW:Add 'X-Content-Type-Options: nosniff'"
        "Referrer-Policy:Referrer-Policy:LOW:Add Referrer-Policy header (e.g., strict-origin-when-cross-origin)"
        "Permissions-Policy:Permissions-Policy:LOW:Add Permissions-Policy header to restrict API access"
        "Cross-Origin-Embedder-Policy:COEP (Cross-Origin-Embedder-Policy):LOW:Add COEP header"
        "Cross-Origin-Opener-Policy:COOP (Cross-Origin-Opener-Policy):LOW:Add COOP header"
        "Cross-Origin-Resource-Policy:CORP (Cross-Origin-Resource-Policy):LOW:Add CORP header"
    )
    
    for check in "${header_checks[@]}"; do
        local header_name=$(echo "$check" | cut -d: -f1)
        local display_name=$(echo "$check" | cut -d: -f2)
        local severity=$(echo "$check" | cut -d: -f3)
        local remediation=$(echo "$check" | cut -d: -f4)
        
        if ! grep -qi "$header_name" "$headers_file" 2>/dev/null; then
            log_medium "Missing: $display_name"
            record_finding "$severity" "Missing Security Header: $display_name" "The $display_name header is not set in HTTP response." "$remediation" ""
        else
            local header_value=$(grep -i "$header_name" "$headers_file" 2>/dev/null | head -1)
            log_ok "Present: $display_name"
            log_info "  $header_value"
        fi
    done
    
    # Check for information disclosure headers
    log_info "Checking for information disclosure..."
    if grep -qi "X-Powered-By\|X-AspNet-Version\|X-AspNetMvc-Version\|X-Generator\|X-Drupal\|X-Joomla\|X-Magento\|X-Version\|X-Environment" "$headers_file" 2>/dev/null; then
        local disclosed=$(grep -i "X-Powered-By\|X-AspNet-Version\|X-AspNetMvc-Version\|X-Generator\|X-Drupal\|X-Joomla\|X-Magento\|X-Version" "$headers_file" 2>/dev/null | head -3)
        log_high "Information disclosure detected!"
        record_finding "LOW" "Information Disclosure via Headers" "$(echo "$disclosed" | tr '\n' ' ')" "Remove or obfuscate technology-specific headers." ""
    fi
    
    # Check for cookies
    if grep -qi "Set-Cookie" "$headers_file" 2>/dev/null; then
        log_info "Checking cookie security flags..."
        if grep -qi "Set-Cookie" "$headers_file" 2>/dev/null | head -5 | while IFS= read -r cookie; do
            if ! echo "$cookie" | grep -qi "HttpOnly"; then
                log_warn "Cookie missing HttpOnly flag: $cookie"
                record_finding "MEDIUM" "Cookie Missing HttpOnly Flag" "Cookie set without HttpOnly flag, accessible via JavaScript." "Add HttpOnly flag to cookies." ""
            fi
            if ! echo "$cookie" | grep -qi "Secure"; then
                log_warn "Cookie missing Secure flag: $cookie"
                record_finding "MEDIUM" "Cookie Missing Secure Flag" "Cookie set without Secure flag, may be sent over HTTP." "Add Secure flag to cookies sent over HTTPS." ""
            fi
            if ! echo "$cookie" | grep -qi "SameSite"; then
                log_warn "Cookie missing SameSite attribute: $cookie"
                record_finding "LOW" "Cookie Missing SameSite Attribute" "Cookie set without SameSite attribute." "Add SameSite=Lax or SameSite=Strict to cookies." ""
            fi
        done; then
            :
        fi
    fi
    
    log_ok "Security headers audit complete"
}

# =============================================================================
# CORS CHECK
# =============================================================================
check_cors() {
    local target_url="$1"
    local output="$2"
    
    log_banner "CORS Misconfiguration Testing"
    
    local cors_output="$vuln_output/cors_check.txt"
    
    log_info "Testing CORS configuration..."
    
    local evil_origins=(
        "https://evil.com"
        "https://evil.com:443"
        "null"
        "https://${TARGET_DOMAIN}.evil.com"
        "https://${TARGET_DOMAIN//./}.evil.com"
        "http://evil${TARGET_DOMAIN}"
        "https://evil${TARGET_DOMAIN}"
    )
    
    local cors_findings=0
    
    for origin in "${evil_origins[@]}"; do
        local response=$(curl -s -k -I --max-time "$TIMEOUT" -H "Origin: $origin" -H "Access-Control-Request-Method: GET" "$target_url" 2>/dev/null)
        local acao=$(echo "$response" | grep -i "Access-Control-Allow-Origin" | tr -d '\r')
        local acac=$(echo "$response" | grep -i "Access-Control-Allow-Credentials" | tr -d '\r')
        
        if [[ -n "$acao" ]]; then
            {
                echo "Tested origin: $origin"
                echo "$acao"
                echo "$acac"
                echo "---"
            } >> "$cors_output"
            
            if echo "$acao" | grep -qi "$(echo "$origin" | sed 's/[\/&]/\\&/g')" 2>/dev/null || echo "$acao" | grep -qi "\*" 2>/dev/null; then
                local is_credentialed=$(echo "$acac" | grep -qi "true" && echo "with credentials" || echo "without credentials")
                
                if echo "$acao" | grep -qi "\*" 2>/dev/null; then
                    cors_findings+=1
                    record_finding "HIGH" "CORS: Wildcard Origin (*)" "Access-Control-Allow-Origin: * allows any website to read responses | Tested: $origin" "Set specific allowed origins instead of wildcard." ""
                elif [[ -n "$acac" ]]; then
                    cors_findings+=1
                    record_finding "HIGH" "CORS: Origin Reflection with Credentials" "Origin '$origin' reflected in ACAO $is_credentialed | Data exfiltration possible" "Do not reflect Origin header. Use whitelist-based CORS." ""
                else
                    cors_findings+=1
                    record_finding "MEDIUM" "CORS: Origin Reflected" "Origin '$origin' reflected in Access-Control-Allow-Origin $is_credentialed" "Use whitelist-based CORS policy." ""
                fi
            fi
        fi
    done
    
    if [[ "$cors_findings" -eq 0 ]]; then
        log_ok "No CORS misconfiguration detected"
    fi
}
