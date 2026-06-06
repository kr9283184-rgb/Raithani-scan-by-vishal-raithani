#!/bin/bash
# =============================================================================
# Raithani-Scan - Web Enumeration Phase
# Directory brute-force, hidden file discovery, parameter discovery
# =============================================================================

run_web_enum() {
    start_phase "Web Enumeration"
    
    local target_url="$1"
    local output="$2"
    local dir_file="$SCRIPT_DIR/payloads/dirs.txt"
    local enum_output="$output/web_enum"
    mkdir -p "$enum_output"
    
    # 1. Directory brute-force with gobuster
    log_step "Directory brute-force (gobuster)..."
    if command -v gobuster &>/dev/null; then
        local gobuster_out="$enum_output/gobuster.txt"
        gobuster dir -u "$target_url" -w "$dir_file" -t "${GOBUSTER_THREADS:-20}" -q -o "$gobuster_out" 2>/dev/null
        
        local found_dirs=$(grep -E "^/" "$gobuster_out" 2>/dev/null | wc -l)
        log_ok "gobuster found $found_dirs directories/files"
        
        # Display and record findings
        grep -E "^/" "$gobuster_out" 2>/dev/null | while IFS= read -r line; do
            local status=$(echo "$line" | awk '{print $2}')
            local dir=$(echo "$line" | awk '{print $1}')
            
            if [[ "$status" =~ ^2 ]]; then
                log_ok "  $dir (HTTP $status)"
                
                # Record interesting finds
                case "$dir" in
                    */admin*|*/login*|*/wp-admin*|*/administrator*)
                        record_finding "HIGH" "Admin Panel Found: $dir" "Admin interface accessible at $dir (HTTP $status)" "Restrict admin access by IP or use VPN." ""
                        ;;
                    */backup*|*/bak*|*/.git*|*/.svn*|*/dump*)
                        record_finding "CRITICAL" "Sensitive Directory Exposed: $dir" "Potentially sensitive directory accessible at $dir" "Remove or protect this directory." ""
                        ;;
                    */phpmyadmin*|*/pma*|*/phpPgAdmin*)
                        record_finding "CRITICAL" "Database Admin Tool: $dir" "Database administration tool exposed at $dir" "Remove or restrict access to database admin tools." ""
                        ;;
                    */api*|*/v1/*|*/v2/*|*/graphql*|*/swagger*)
                        record_finding "MEDIUM" "API Endpoint: $dir" "API endpoint discovered at $dir" "Ensure API endpoints are properly authenticated." ""
                        ;;
                    */config*|*/configuration*|*/.env*|*/env*)
                        record_finding "CRITICAL" "Configuration File: $dir" "Configuration file/directory exposed at $dir" "Remove or protect configuration files." ""
                        ;;
                    */cgi-bin*)
                        record_finding "HIGH" "CGI-Bin Accessible: $dir" "CGI directory accessible at $dir. Potential for shellshock or command injection." "Disable CGI if not needed." ""
                        ;;
                    */upload*|*/uploads*|*/download*|*/downloads*)
                        record_finding "MEDIUM" "File Upload/Download Directory: $dir" "File upload/download directory found at $dir" "Ensure upload validation and directory listing is disabled." ""
                        ;;
                    */actuator*|*/health*|*/info*|*/metrics*)
                        record_finding "MEDIUM" "Spring Boot Actuator: $dir" "Spring Boot actuator endpoint exposed at $dir" "Restrict actuator endpoints or disable in production." ""
                        ;;
                esac
            elif [[ "$status" =~ ^3 ]]; then
                log_info "  $dir -> redirect (HTTP $status)"
            elif [[ "$status" =~ ^4 ]]; then
                log_info "  $dir (HTTP $status - interesting)"
            fi
        done
    else
        log_warn "gobuster not installed"
        check_optional_dep "gobuster" || true
    fi
    
    # 2. Try alternative dirb if gobuster not available
    if ! command -v gobuster &>/dev/null && command -v dirb &>/dev/null; then
        log_step "Directory brute-force (dirb)..."
        local dirb_out="$enum_output/dirb.txt"
        dirb "$target_url" "$dir_file" -o "$dirb_out" 2>/dev/null | tail -20
        
        local found_count=$(grep -c "CODE:200\|CODE:301\|CODE:302\|CODE:403" "$dirb_out" 2>/dev/null)
        log_ok "dirb found $found_count paths"
    fi
    
    # 3. Parameter discovery (basic fuzzing)
    log_step "Parameter fuzzing on known endpoints..."
    local params_list=("id" "page" "file" "url" "path" "name" "q" "s" "search" "query" "action" "cmd" "exec" "command" "view" "template" "include" "load" "read" "dir" "type" "cat" "folder" "document" "filepath" "file_name" "open" "src" "data" "param" "login" "user" "username" "pass" "password" "email" "redirect" "return" "next" "dest" "target" "callback")
    local discovered_params_file="$enum_output/params.txt"
    
    # Find pages with forms/parameters
    local index_content=$(http_request "$target_url")
    local found_forms=$(echo "$index_content" | grep -oP 'action=["'\'']?\K[^"'\'' >]+' 2>/dev/null | sort -u | head -20)
    
    if [[ -n "$found_forms" ]]; then
        echo "$found_forms" > "$discovered_params_file"
        log_ok "Found $(echo "$found_forms" | wc -l) form action endpoints"
        
        echo "$found_forms" | while IFS= read -r endp; do
            [[ -z "$endp" ]] && continue
            local full_url="${target_url}${endp}"
            log_info "  Form target: $endp"
            
            # Try common params on discovered endpoints
            for param in "id" "page" "file" "url" "cmd"; do
                local resp=$(http_request "${full_url}?${param}=test" 2>/dev/null)
                if [[ -n "$resp" ]]; then
                    echo "$full_url?$param=test" >> "$enum_output/parameterized_urls.txt"
                fi
            done
        done
        log_ok "Parameter discovery saved to parameterized_urls.txt"
    fi
    
    # 4. Spider for URL discovery
    log_step "Spidering for URL discovery..."
    local spider_out="$enum_output/spidered_urls.txt"
    
    # Extract all links from index page
    echo "$index_content" | grep -oP '(?:href|src|action)=["'\''"]?\K[^"'\''"> ]+' 2>/dev/null | sort -u > "$spider_out"
    
    # Filter for internal URLs
    local internal_urls=$(grep -E "^/|^$target_url|^\." "$spider_out" 2>/dev/null | head -100)
    local url_count=$(echo "$internal_urls" | grep -c .)
    
    if [[ "$url_count" -gt 0 ]]; then
        log_ok "Discovered $url_count internal URLs"
        echo "$internal_urls" > "$enum_output/internal_urls.txt"
    fi
    
    # 5. Check for common sensitive files directly
    log_step "Checking for common sensitive files..."
    local sensitive_files=(
        "/.git/config"
        "/.git/HEAD"
        "/.env"
        "/.DS_Store"
        "/Thumbs.db"
        "/crossdomain.xml"
        "/clientaccesspolicy.xml"
        "/Dockerfile"
        "/docker-compose.yml"
        "/sitemap.xml"
        "/robots.txt"
        "/server-status"
        "/server-info"
    )
    
    for sf in "${sensitive_files[@]}"; do
        local response=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "${target_url}${sf}" 2>/dev/null)
        if [[ "$response" == "200" ]]; then
            log_high "Sensitive file found: ${sf}"
            local file_content=$(http_request "${target_url}${sf}" 2>/dev/null)
            echo "=== $sf ===" >> "$output/sensitive_files.txt"
            echo "$file_content" >> "$output/sensitive_files.txt"
            echo "" >> "$output/sensitive_files.txt"
            record_finding "HIGH" "Sensitive File Exposed: $sf" "File accessible at $target_url$sf" "Remove or restrict access to sensitive files." "$output/sensitive_files.txt"
        fi
    done
    
    # 6. API fuzzing and discovery
    if [[ "$API_FUZZ_ENABLED" == "true" ]]; then
        log_step "API endpoint discovery and fuzzing..."
        
        # 6a. Discover REST/API endpoints via gobuster with API-specific wordlist
        local api_endpoints_file="$enum_output/api_endpoints.txt"
        local api_wordlist=(
            "/api" "/api/v1" "/api/v2" "/api/v3" "/rest" "/rest/v1" "/rest/v2"
            "/swagger" "/swagger.json" "/swagger-ui" "/swagger-ui.html"
            "/api-docs" "/openapi.json" "/openapi"
            "/v1" "/v2" "/v3"
            "/docs" "/api/docs"
            "/graphql" "/graphiql" "/gql"
            "/health" "/healthz" "/ready" "/status"
            "/metrics" "/prometheus"
            "/users" "/user" "/users/1" "/me" "/profile"
            "/login" "/logout" "/register" "/signup" "/auth" "/oauth" "/token" "/refresh"
            "/admin" "/admin/users" "/admin/settings" "/admin/api"
            "/config" "/configuration" "/settings" "/env"
            "/search" "/query" "/filter" "/sort"
            "/upload" "/uploads" "/download" "/downloads"
            "/webhook" "/webhooks" "/callback" "/hook"
            "/ws" "/websocket" "/socket" "/mqtt"
            "/rpc" "/jsonrpc" "/xmlrpc" "/soap"
            "/cron" "/job" "/task" "/queue"
            "/export" "/import" "/backup" "/restore"
            "/debug" "/trace" "/test" "/ping" "/info"
        )
        
        for api_ep in "${api_wordlist[@]}"; do
            local api_response=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "${target_url}${api_ep}" 2>/dev/null)
            if [[ "$api_response" =~ ^(200|201|202|204|301|302|401|403|405|500)$ ]]; then
                echo "$api_ep" >> "$api_endpoints_file"
                log_info "  API endpoint: $api_ep (HTTP $api_response)"
                
                # Record interesting findings
                if echo "$api_ep" | grep -qiP "(swagger|openapi|api-docs)"; then
                    record_finding "MEDIUM" "API Documentation: $api_ep" "API documentation accessible at $api_ep (HTTP $api_response). May expose endpoint details." "Restrict API documentation access in production." ""
                elif echo "$api_ep" | grep -qiP "(health|healthz|metrics|prometheus|debug|trace)"; then
                    record_finding "MEDIUM" "Monitoring Endpoint: $api_ep" "Monitoring/debug endpoint accessible at $api_ep (HTTP $api_response)." "Restrict monitoring endpoints to internal networks." ""
                elif echo "$api_ep" | grep -qiP "admin"; then
                    record_finding "HIGH" "Admin API: $api_ep" "Admin API endpoint accessible at $api_ep (HTTP $api_response)." "Restrict admin API access." ""
                elif echo "$api_ep" | grep -qiP "(backup|export|import|config|env|\.json)"; then
                    record_finding "HIGH" "Sensitive API: $api_ep" "Potentially sensitive API endpoint at $api_ep (HTTP $api_response)." "Ensure proper authentication on all API endpoints." ""
                fi
            fi
        done
        
        # 6b. Test HTTP methods on discovered API endpoints
        if [[ -f "$api_endpoints_file" ]]; then
            log_info "Testing HTTP methods on API endpoints..."
            local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS")
            while IFS= read -r api_ep; do
                [[ -z "$api_ep" ]] && continue
                local full_url="${target_url}${api_ep}"
                for method in "${methods[@]}"; do
                    local method_response=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" -X "$method" "${full_url}" 2>/dev/null)
                    if [[ "$method_response" =~ ^(200|201|204|403|405)$ ]]; then
                        echo "$method $full_url -> $method_response" >> "$enum_output/api_methods.txt"
                        log_info "  $method $api_ep -> HTTP $method_response"
                        
                        # If DELETE/PUT/PATCH return 200/204, that's interesting
                        if [[ "$method" =~ ^(DELETE|PUT|PATCH)$ ]] && [[ "$method_response" =~ ^(200|204)$ ]]; then
                            record_finding "HIGH" "API: Unrestricted $method on $api_ep" "HTTP $method on $api_ep returns $method_response. May allow data modification." "Implement proper HTTP method restrictions." ""
                        fi
                    fi
                done
            done < "$api_endpoints_file"
        fi
        
        # 6c. Rate limit testing
        log_info "Testing rate limiting on API endpoints..."
        local rate_test_endpoints=("${target_url}/api/v1" "${target_url}/api" "${target_url}/login" "${target_url}/graphql")
        for rate_ep in "${rate_test_endpoints[@]}"; do
            local fast_responses=0
            for i in 1 2 3 4 5; do
                local rate_response=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 3 "${rate_ep}" 2>/dev/null)
                if [[ "$rate_response" =~ ^(200|201|401|403)$ ]]; then
                    fast_responses+=1
                fi
                sleep 0.1
            done
            if [[ "$fast_responses" -eq 5 ]]; then
                log_medium "No rate limiting detected on $rate_ep"
                record_finding "MEDIUM" "Rate Limiting: No rate limiting on $rate_ep" "$rate_ep accepted $fast_responses/5 rapid requests without rate limiting." "Implement rate limiting (e.g., 100 requests/min per IP) for all API endpoints." ""
                break
            fi
        done
        
        log_ok "API fuzzing complete"
    fi
    
    # Combine all discovered URLs
    {
        cat "$enum_output/gobuster.txt" 2>/dev/null
        cat "$enum_output/internal_urls.txt" 2>/dev/null
        cat "$enum_output/parameterized_urls.txt" 2>/dev/null
        cat "$output/sensitive_files.txt" 2>/dev/null
    } | sort -u > "$output/all_discovered_urls.txt"
    
    local total_urls=$(wc -l < "$output/all_discovered_urls.txt")
    log_ok "Web enumeration complete. $total_urls total URLs discovered."
    
    end_phase
}
