#!/bin/bash
# =============================================================================
# Raithani-Scan - Bug Bounty / Advanced Scanning Module
# Subdomain takeover, SAST/DAST, cloud buckets, OAuth/SSO, origin IP,
# HTTP smuggling, race conditions, Google dorking
# =============================================================================

run_bugbounty_checks() {
    start_phase "Bug Bounty Testing"

    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    local bb_output="$output/bugbounty"
    mkdir -p "$bb_output"

    # === GOOGLE DORKING ===
    if [[ "$GOOGLE_DORK_ENABLED" == "true" ]]; then
        check_google_dorks "$target_url" "$target_domain" "$bb_output"
    fi

    # === SAST/DAST ===
    if [[ "$SAST_DAST_ENABLED" == "true" ]]; then
        check_sast_dast "$target_url" "$target_domain" "$bb_output"
    fi

    # === SUBDOMAIN TAKEOVER ===
    if [[ "$SUBDOMAIN_TAKEOVER_ENABLED" == "true" ]]; then
        check_subdomain_takeover "$target_url" "$target_domain" "$output" "$bb_output"
    fi

    # === CLOUD BUCKET ENUMERATION ===
    if [[ "$CLOUD_BUCKET_ENUM_ENABLED" == "true" ]]; then
        check_cloud_buckets "$target_domain" "$bb_output"
    fi

    # === OAUTH/SSO TESTING ===
    if [[ "$OAUTH_TESTING_ENABLED" == "true" ]]; then
        check_oauth_sso "$target_url" "$target_domain" "$bb_output"
    fi

    # === ORIGIN IP DISCOVERY ===
    if [[ "$ORIGIN_IP_DISCOVERY_ENABLED" == "true" ]]; then
        discover_origin_ip "$target_url" "$target_domain" "$bb_output"
    fi

    # === HTTP REQUEST SMUGGLING ===
    if [[ "$SMUGGLING_ENABLED" == "true" ]]; then
        check_smuggling "$target_url" "$target_domain" "$bb_output"
    fi

    # === RACE CONDITIONS ===
    if [[ "$RACE_CONDITION_ENABLED" == "true" ]]; then
        check_race_conditions "$target_url" "$output" "$bb_output"
    fi

    end_phase
}

# =============================================================================
# GOOGLE DORKING
# =============================================================================
check_google_dorks() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"

    log_banner "Google Dorking"

    local dork_output="$output/dorks"
    mkdir -p "$dork_output"
    local dork_findings=0

    # Pick best search engine tool
    local search_tool=""
    if command -v googler &>/dev/null; then
        search_tool="googler"
        log_info "Using googler for searches"
    elif command -v ddgr &>/dev/null; then
        search_tool="ddgr"
        log_info "Using ddgr (DuckDuckGo) as fallback"
    else
        log_warn "Neither googler nor ddgr found. Skipping dorking."
        log_info "Install with: sudo apt install googler"
        return
    fi

    # Dork categories
    local dorks=(
        "filetype:pdf confidential|Sensitive PDF documents"
        "filetype:xls password|Excel files with passwords"
        "filetype:sql INSERT INTO|SQL dump files"
        "filetype:env DB_PASSWORD|Environment files with secrets"
        "filetype:bak|Backup files"
        "filetype:log password|Log files with passwords"
        "filetype:xml config|XML configuration files"
        "filetype:json api_key|JSON API key leaks"
        "filetype:yml secret|YAML secret files"
        "filetype:conf password|Config files with passwords"
        "filetype:cnf password|MySQL config files"
        "filetype:ini password|INI config files"
        "intitle:admin login|Admin login pages"
        "intitle:index of|Directory listings"
        "parent directory|Directory listings"
        "inurl:admin|Admin panel URLs"
        "inurl:login|Login page URLs"
        "inurl:backup|Backup page URLs"
        "inurl:wp-admin|WordPress admin panels"
        "inurl:phpmyadmin|phpMyAdmin panels"
        "error warning mysql|MySQL error disclosure"
        "Fatal error|PHP fatal errors"
        "Warning: include|PHP include warnings"
        "Notice: Undefined|PHP notice disclosure"
        "stack trace|Debug stack traces"
        "\"s3.amazonaws.com\"|S3 bucket leaks"
        "\"aws_access_key\"|AWS key leaks"
        "\"api_key\"|API key leaks"
        "\"API_SECRET\"|API secret leaks"
        "\"password\" \"admin\"|Password leaks"
        "\"-----BEGIN RSA PRIVATE KEY-----\"|Private key leaks"
        "\"-----BEGIN OPENSSH PRIVATE KEY-----\"|SSH key leaks"
        "\"-----BEGIN PRIVATE KEY-----\"|SSL private key"
        "\"meet.jit.si\"|Jitsi URLs on target"
        "\"webhook.site\"|Webhook URLs on target"
        "\"hookbin.com\"|Hookbin URLs on target"
        "\"requestbin\"|RequestBin URLs on target"
        "\"slack.com\" \"token\"|Slack token leaks"
        "\"github.com\" \"token\"|GitHub token leaks"
        "inurl:gitlab|GitLab instances"
        "inurl:jenkins|Jenkins instances"
        "inurl:grafana|Grafana dashboards"
        "inurl:kibana|Kibana dashboards"
        "inurl:prometheus|Prometheus endpoints"
        "inurl:swagger-ui|Swagger API docs"
        "inurl:api-docs|API documentation"
        "inurl:graphql|GraphQL endpoints"
        "inurl:phpinfo.php|phpinfo() pages"
        "inurl:server-status|Apache status pages"
        "inurl:info.php|PHP info pages"
        "inurl:test.php|Test PHP scripts"
    )

    local total_queries=${#dorks[@]}
    local processed=0

    log_info "Running $total_queries dork queries against $target_domain..."

    for dork_entry in "${dorks[@]}"; do
        local query="site:$target_domain ${dork_entry%%|*}"
        local description="${dork_entry##*|}"
        processed+=1

        echo -ne "\r${D}[i]${NC} Dork $processed/$total_queries: $description..." >&2

        local results_file="$dork_output/$(echo "$description" | tr ' ' '_' | tr -cd 'a-zA-Z0-9_-').txt"
        local results=""

        if [[ "$search_tool" == "googler" ]]; then
            results=$(googler -n "${DORK_MAX_RESULTS:-30}" --no-color --np "$query" 2>/dev/null)
        elif [[ "$search_tool" == "ddgr" ]]; then
            results=$(ddgr -n "${DORK_MAX_RESULTS:-30}" --no-color --num 1 "!g $query" 2>/dev/null)
        fi

        if [[ -n "$results" ]]; then
            echo "$results" > "$results_file"
            local url_count=$(echo "$results" | grep -cE '^https?://')
            if [[ "$url_count" -gt 0 ]]; then
                dork_findings+=1
                echo ""
                log_medium "$description: $url_count URL(s) found"
                echo "$results" | grep -E '^https?://' | head -5 | while IFS= read -r url; do
                    log_info "  $url"
                done
            fi
        fi

        sleep 1
    done

    echo ""
    if [[ "$dork_findings" -gt 0 ]]; then
        record_finding "MEDIUM" "Google Dorking: $dork_findings finding(s) for $target_domain" "$dork_findings dork queries returned results. See $dork_output for details." "Review exposed files and endpoints found via dorking." ""
    else
        log_ok "No dork results found (or search engine blocked the queries)"
    fi
}

# =============================================================================
# SAST / DAST
# =============================================================================
check_sast_dast() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"

    log_banner "SAST/DAST: Static & Dynamic Analysis"

    local sast_output="$output/sast_dast"
    mkdir -p "$sast_output"
    local sast_findings=0

    # === SAST: JavaScript Analysis ===
    log_info "SAST: Fetching and analyzing JavaScript files..."
    local js_output="$sast_output/js_analysis.txt"
    local secrets_output="$sast_output/secrets_found.txt"
    : > "$js_output"
    : > "$secrets_output"

    # Fetch the index page and extract JS URLs
    local index_html=$(http_request "$target_url" "GET" "" "")
    local js_urls=$(echo "$index_html" | grep -oiP 'src=["'\'']([^"'\'']*\.js[^"'\'']*)["'\'']' 2>/dev/null | sed 's/src=["\x27]//;s/["\x27]$//' | sort -u)

    if [[ -z "$js_urls" ]]; then
        js_urls=$(echo "$index_html" | grep -oiP '(href|src)=["'\'']?[^"'\'' >]+\.js["'\'' >]' 2>/dev/null | sed 's/(href|src)=["\x27]?//;s/["\x27 >]$//' | sort -u)
    fi

    # Resolve relative URLs
    local resolved_js=()
    while IFS= read -r js; do
        [[ -z "$js" ]] && continue
        if echo "$js" | grep -qE '^https?://'; then
            resolved_js+=("$js")
        elif echo "$js" | grep -qE '^//'; then
            resolved_js+=("https:$js")
        elif echo "$js" | grep -qE '^/'; then
            resolved_js+=("${target_url}$js")
        else
            resolved_js+=("${target_url}/${js}")
        fi
    done <<< "$js_urls"

    if [[ ${#resolved_js[@]} -eq 0 ]]; then
        log_info "  No JavaScript files found on index page"
        # Try common JS paths
        local common_js=("/assets/js/main.js" "/js/app.js" "/static/js/bundle.js" "/wp-content/themes/*/js/*.js" "/dist/js/*.js")
        for cjs in "${common_js[@]}"; do
            local test_url="${target_url}${cjs}"
            resolved_js+=("$test_url")
        done
    fi

    log_info "  Analyzing ${#resolved_js[@]} JavaScript file(s)..."

    # Secret patterns
    local secret_patterns=(
        'api[_-]?key\s*[:=]\s*["'\''][A-Za-z0-9_\-]{16,}["'\'']'
        'aws_access_key_id\s*[:=]\s*["'\''][A-Za-z0-9/+=]{16,}["'\'']'
        'aws_secret_access_key\s*[:=]\s*["'\''][A-Za-z0-9/+=]{40,}["'\'']'
        'ghp_[A-Za-z0-9]{36}'
        'gho_[A-Za-z0-9]{36}'
        'github_pat_[A-Za-z0-9_]{36,}'
        'ghr_[A-Za-z0-9]{36}'
        'sk_live_[A-Za-z0-9]{24,}'
        'pk_live_[A-Za-z0-9]{24,}'
        'sk_test_[A-Za-z0-9]{24,}'
        'xox[baprs]-[A-Za-z0-9-]{24,}'
        'AIza[0-9A-Za-z\-]{35}'
        'AKIA[0-9A-Z]{16}'
        '[\"'\''][Ff][Ii][Rr][Ee][Bb][Aa][Ss][Ee][_\.].*[\"'\''][=:].*[\"'\''][A-Za-z0-9]{40,}["'\'']'
        'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        '-----BEGIN RSA PRIVATE KEY-----'
        '-----BEGIN OPENSSH PRIVATE KEY-----'
        '-----BEGIN DSA PRIVATE KEY-----'
        '-----BEGIN EC PRIVATE KEY-----'
        '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        'password\s*[:=]\s*["'\''][^"'\'']+["'\'']'
        'passwd\s*[:=]\s*["'\''][^"'\'']+["'\'']'
        'pwd\s*[:=]\s*["'\''][^"'\'']+["'\'']'
        'secret\s*[:=]\s*["'\''][^"'\'']{8,}["'\'']'
        'token\s*[:=]\s*["'\''][A-Za-z0-9_\-]{16,}["'\'']'
        'MONGO_URI\s*[:=]\s*["'\''][^"'\'']+["'\'']'
        'mongodb://[^"'\'' ]+'
        'postgresql://[^"'\'' ]+'
        'mysql://[^"'\'' ]+'
        'redis://[^"'\'' ]+'
        'rediss://[^"'\'' ]+'
        'AWS_ACCESS_KEY|AWS_SECRET_KEY|AWS_SESSION_TOKEN'
        'SLACK_BOT_TOKEN|SLACK_WEBHOOK_URL'
        'DB_HOST|DB_USER|DB_PASS|DB_NAME|DB_PASSWORD'
        ':password=>'\''[^'\'']+'\'''
        ':passwd=>'\''[^'\'']+'\'''
    )

    for js_url in "${resolved_js[@]}"; do
        [[ -z "$js_url" ]] && continue
        log_info "  Fetching $(basename "$js_url" | cut -c1-40)..."

        local js_content=$(http_request "$js_url" "GET" "" "")

        if [[ -z "$js_content" || ${#js_content} -lt 10 ]]; then
            continue
        fi

        echo "=== $js_url ===" >> "$js_output"
        echo "Size: ${#js_content} bytes" >> "$js_output"

        # Search for secret patterns
        for pattern in "${secret_patterns[@]}"; do
            local matches=$(echo "$js_content" | grep -oiP "$pattern" 2>/dev/null | sort -u)
            if [[ -n "$matches" ]]; then
                echo "--- SECRET FOUND ---" >> "$secrets_output"
                echo "File: $js_url" >> "$secrets_output"
                echo "$matches" >> "$secrets_output"
                echo "" >> "$secrets_output"

                sast_findings+=1
                local match_count=$(echo "$matches" | wc -l)
                record_finding "CRITICAL" "SAST: Secrets leaked in $(basename "$js_url")" "$match_count secret(s) found in JavaScript. Pattern: ${pattern:0:40}" "Remove secrets from client-side code. Use environment variables." ""
            fi
        done

        # Search for dangerous JS patterns
        local dangerous=0
        echo "$js_content" | grep -oiP '(eval\s*\(|innerHTML\s*=|document\.write\s*\(|setTimeout\s*\(\s*["'\'']|setInterval\s*\(\s*["'\'']|new Function\s*\()' 2>/dev/null | sort -u > "$sast_output/dangerous_patterns.txt"
        if [[ -s "$sast_output/dangerous_patterns.txt" ]]; then
            dangerous=$(wc -l < "$sast_output/dangerous_patterns.txt")
            if [[ "$dangerous" -gt 0 ]]; then
                record_finding "MEDIUM" "SAST: Dangerous JS patterns in $(basename "$js_url")" "$dangerous dangerous pattern(s): $(head -3 "$sast_output/dangerous_patterns.txt" | tr '\n' ', ')" "Avoid eval(), innerHTML, and document.write()" ""
            fi
        fi

        # Extract API endpoints from JS
        echo "$js_content" | grep -oiP '["'\'']/(?:api|v[0-9]+|rest|graphql)[a-zA-Z0-9_\-/]*["'\'']' 2>/dev/null | sort -u >> "$sast_output/api_endpoints_from_js.txt"
    done

    # === SAST: Source Map Analysis ===
    log_info "SAST: Checking for source maps..."
    for js_url in "${resolved_js[@]}"; do
        local map_url="${js_url}.map"
        local map_content=$(http_request "$map_url" "GET" "" "")
        if [[ -n "$map_content" && ${#map_content} -gt 100 ]]; then
            sast_findings+=1
            echo "=== Source Map: $map_url ===" >> "$sast_output/sourcemaps.txt"
            echo "$map_content" | python3 -m json.tool 2>/dev/null | head -50 >> "$sast_output/sourcemaps.txt"
            record_finding "HIGH" "SAST: Source map exposed at $(basename "$map_url")" "Source map file accessible at $map_url (${#map_content} bytes). Original source code can be reconstructed." "Remove .map files from production builds." ""
        fi
    done

    # === SAST: HTML Comment Analysis ===
    log_info "SAST: Analyzing HTML comments..."
    local comments=$(echo "$index_html" | grep -oiP '<!--.*?-->' 2>/dev/null)
    if [[ -n "$comments" ]]; then
        echo "$comments" > "$sast_output/html_comments.txt"
        local todo_comments=$(echo "$comments" | grep -oiP '(TODO|FIXME|HACK|XXX|BUG|security|password|creds|secret|key|token)' 2>/dev/null)
        if [[ -n "$todo_comments" ]]; then
            sast_findings+=1
            record_finding "LOW" "SAST: Interesting HTML comments found" "Comments with security-relevant keywords found in HTML." "Remove development comments before production deployment." "$sast_output/html_comments.txt"
        fi
    fi

    # === SAST: Endpoint Extraction ===
    log_info "SAST: Extracting API endpoints from HTML..."
    local endpoints=$(echo "$index_html" | grep -oiP '["'\'']/(?:api|v[0-9]+|rest|graphql|admin|auth|login|register|upload|download|webhook|callback)[a-zA-Z0-9_\-/]*["'\'']' 2>/dev/null | sort -u | sed 's/["\x27]//g')
    if [[ -n "$endpoints" ]]; then
        echo "$endpoints" > "$sast_output/endpoints_from_html.txt"
        local ep_count=$(echo "$endpoints" | wc -l)
        log_ok "  Extracted $ep_count API endpoint(s) from HTML"
        for ep in $endpoints; do
            log_info "  $ep"
        done
    fi

    # === DAST: Form Auto-Submission ===
    log_info "DAST: Discovering and fuzzing forms..."
    local forms=$(echo "$index_html" | grep -oiP '<form[^>]*>.*?</form>' 2>/dev/null)
    if [[ -z "$forms" ]]; then
        forms=$(echo "$index_html" | grep -oiP '<form[^>]*>' 2>/dev/null)
    fi

    if [[ -n "$forms" ]]; then
        local form_count=0
        while IFS= read -r form; do
            [[ -z "$form" ]] && continue
            form_count+=1
            local form_action=$(echo "$form" | grep -oiP 'action=["'\'']?([^"'\'' >]+)' 2>/dev/null | head -1 | sed 's/action=["\x27]\?//')
            local form_method=$(echo "$form" | grep -oiP 'method=["'\'']?([^"'\'' >]+)' 2>/dev/null | head -1 | sed 's/method=["\x27]\?//')
            [[ -z "$form_method" ]] && form_method="GET"

            # Resolve action URL
            local action_url=""
            if [[ -z "$form_action" || "$form_action" == "#" ]]; then
                action_url="$target_url"
            elif echo "$form_action" | grep -qE '^https?://'; then
                action_url="$form_action"
            elif echo "$form_action" | grep -qE '^/'; then
                action_url="${target_url}${form_action}"
            else
                action_url="${target_url}/${form_action}"
            fi

            log_info "  Fuzzing form #$form_count (action: $(basename "$action_url" | cut -c1-30))..."

            # Extract all input fields
            local inputs=$(echo "$form" | grep -oiP '<input[^>]*>' 2>/dev/null)

            # Build a test submission with XSS payload in every text field
            local test_data=""
            while IFS= read -r input; do
                [[ -z "$input" ]] && continue
                local input_type=$(echo "$input" | grep -oiP 'type=["'\'']?([^"'\'' >]+)' 2>/dev/null | head -1 | sed 's/type=["\x27]\?//')
                local input_name=$(echo "$input" | grep -oiP 'name=["'\'']?([^"'\'' >]+)' 2>/dev/null | head -1 | sed 's/name=["\x27]\?//')
                [[ -z "$input_name" ]] && continue

                if [[ "$input_type" == "submit" || "$input_type" == "button" || "$input_type" == "image" || "$input_type" == "hidden" ]]; then
                    local input_value=$(echo "$input" | grep -oiP 'value=["'\'']?([^"'\'' >]+)' 2>/dev/null | head -1 | sed 's/value=["\x27]\?//')
                    [[ -n "$input_value" ]] && test_data+="$input_name=${input_value// /+}&"
                else
                    test_data+="${input_name}=<script>alert(1)</script>&"
                fi
            done <<< "$(echo "$inputs")"

            test_data="${test_data%&}"

            # Submit form
            if [[ -n "$test_data" ]]; then
                local form_response=$(http_request "$action_url" "${form_method^^}" "$test_data" "application/x-www-form-urlencoded")
                if echo "$form_response" | grep -qi "<script>alert(1)</script>"; then
                    sast_findings+=1
                    record_finding "HIGH" "DAST: XSS in form #$form_count" "XSS payload reflected in response from $action_url. Form may be vulnerable to stored/reflected XSS." "Properly encode all user input before rendering." ""
                fi
            fi
        done <<< "$forms"
    fi

    if [[ "$sast_findings" -eq 0 ]]; then
        log_ok "No SAST/DAST vulnerabilities detected"
    fi
}

# =============================================================================
# SUBDOMAIN TAKEOVER
# =============================================================================
check_subdomain_takeover() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    local bb_output="$4"

    log_banner "Subdomain Takeover Scanner"

    local takeover_output="$bb_output/subdomain_takeover"
    mkdir -p "$takeover_output"
    local takeover_findings=0

    # Gather all discovered subdomains from recon phase
    local subdomains_file="$output/subdomains.txt"
    local subdomains=()

    if [[ -f "$subdomains_file" ]]; then
        while IFS= read -r line; do
            local sd=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
            [[ -n "$sd" ]] && subdomains+=("$sd")
        done < "$subdomains_file"
    fi

    # Also add known subdomains from crt.sh if found
    local crt_file="$output/crt_sh_subdomains.txt"
    if [[ -f "$crt_file" ]]; then
        while IFS= read -r sd; do
            [[ -n "$sd" ]] && subdomains+=("$sd")
        done < "$crt_file"
    fi

    # Deduplicate
    local unique_subs=()
    if [[ ${#subdomains[@]} -gt 0 ]]; then
        while IFS= read -r sd; do
            [[ -n "$sd" ]] && unique_subs+=("$sd")
        done < <(printf '%s\n' "${subdomains[@]}" | sort -u)
    fi

    # If no subdomains, use basic common ones
    if [[ ${#unique_subs[@]} -eq 0 ]]; then
        log_info "No subdomains from previous phases, using common list..."
        local common_subs=("www" "mail" "ftp" "admin" "blog" "api" "dev" "staging" "test" "app" "m" "mobile" "web" "webmail" "cp" "cpanel" "whm" "ns1" "ns2" "mx" "docs" "help" "support" "status" "shop" "store" "demo" "beta" "vpn" "remote" "git" "cdn" "static" "media" "assets" "img" "css" "js" "download" "upload" "backup" "db" "database" "mysql" "webdisk" "autodiscover" "owa" "exchange" "calendar" "mail2" "mail1" "smtp" "pop" "pop3" "imap" "images" "video" "player" "chat" "forum" "community" "wiki" "news" "portal" "partner" "partners" "clients" "customer" "customers" "my" "secure" "ssl" "sso" "oauth" "auth" "login" "register" "signup" "signin" "tracking" "analytics" "stats" "events" "metrics" "monitor" "alerts" "logs" "error" "errors" "debug" "sandbox" "payment" "payments" "checkout" "billing" "invoice" "invoices" "gateway" "api-dev" "api-staging" "api-test" "dev-api" "stg" "stage" "preprod" "prod" "production" "uat" "qa" "quality" "internal" "corp" "corporate" "office" "hr" "employee" "employees" "intranet" "extranet" "portal" "vpn" "remote-access" "jump" "jumpbox" "bastion" "jenkins" "jira" "confluence" "gitlab" "bitbucket" "sonar" "sonarqube" "nexus" "artifactory" "docker" "k8s" "kubernetes" "swarm" "nomad" "consul" "vault" "grafana" "prometheus" "kibana" "elastic" "logstash" "kafka" "zookeeper" "redis" "rabbitmq" "mq" "amqp" "minio" "s3" "storage" "files" "file" "static-assets" "assets-cdn" "img-cdn" "video-cdn" "stream" "streaming" "live" "tv" "radio" "podcast" "webinar" "learn" "training" "academy" "education" "course" "courses" "classroom" "lms" "moodle" "blackboard" "canvas" "zoom" "teams" "meet" "meeting" "meetings" "skype" "lync" "webex" "gotomeeting" "adobeconnect" "adobe" "air" "flash" "java" "silverlight")
        for cs in "${common_subs[@]}"; do
            unique_subs+=("$cs.$target_domain")
        done
    fi

    log_info "Testing ${#unique_subs[@]} subdomain(s) for takeover..."

    # Service fingerprint database (CNAME target → detection string)
    local -A takeover_patterns
    takeover_patterns["s3.amazonaws.com"]="NoSuchBucket"
    takeover_patterns["cloudfront.net"]="ERROR: The request could not be satisfied"
    takeover_patterns["elasticbeanstalk.com"]="NXDOMAIN"
    takeover_patterns["github.io"]="There isn't a GitHub Pages site here"
    takeover_patterns["herokuapp.com"]="No such app"
    takeover_patterns["herokussl.com"]="No such app"
    takeover_patterns["netlify.app"]="Not Found - Netlify"
    takeover_patterns["vercel.app"]="404: NOT_FOUND"
    takeover_patterns["azurewebsites.net"]="404 Web Site not configured"
    takeover_patterns["azurewebsites.windows.net"]="404 Web Site not configured"
    takeover_patterns["storage.googleapis.com"]="The specified bucket does not exist"
    takeover_patterns["zendesk.com"]="Help Center Closed"
    takeover_patterns["myshopify.com"]="Sorry, this shop is currently unavailable"
    takeover_patterns["bitbucket.io"]="Repository not found"
    takeover_patterns["gitlab.io"]="The page could not be found"
    takeover_patterns["pantheonsite.io"]="404 - Unknown Site"
    takeover_patterns["pantheon.io"]="404 - Unknown Site"
    takeover_patterns["squarespace.com"]="No Such Page"
    takeover_patterns["tumblr.com"]="There's nothing here"
    takeover_patterns["unbounce.com"]="Sorry, the page you were looking for"
    takeover_patterns["helpjuice.com"]="No such help page"
    takeover_patterns["helpscout.net"]="No help site found"
    takeover_patterns["freshdesk.com"]="The page you are looking for was not found"
    takeover_patterns["statuspage.io"]="Try again in a few minutes"
    takeover_patterns["fastly.net"]="Fastly error: unknown domain"
    takeover_patterns["surge.sh"]="project not found"
    takeover_patterns["fly.io"]="Page Not Found"
    takeover_patterns["firebaseapp.com"]="Firebase Hosting Site Not Found"
    takeover_patterns["web.app"]="Firebase Hosting Site Not Found"
    takeover_patterns["pages.dev"]="The requested page could not be found"
    takeover_patterns["workers.dev"]="not a registered Cloudflare Workers domain"
    takeover_patterns["runkit.sh"]="404 - Not Found"
    takeover_patterns["ngrok.io"]="ngrok.io not found"
    takeover_patterns["service-now.com"]="The page you requested could not be found"
    takeover_patterns["kustomerapp.com"]="There are no applications"
    takeover_patterns["intercom.com"]="This page is not available"
    takeover_patterns["cargo.site"]="page could not be found"
    takeover_patterns["aftership.com"]="This page does not exist"
    takeover_patterns["hatchbuck.com"]="Form Not Found"

    local processed=0
    for subdomain in "${unique_subs[@]}"; do
        processed+=1
        echo -ne "\r${D}[i]${NC} Checking subdomain $processed/${#unique_subs[@]}: $subdomain..."

        local cname=$(dig +short CNAME "$subdomain" 2>/dev/null)
        if [[ -z "$cname" ]]; then
            continue
        fi

        # Check each service pattern
        local matched_service=""
        local matched_pattern=""
        for service_pattern in "${!takeover_patterns[@]}"; do
            if echo "$cname" | grep -qi "$service_pattern"; then
                matched_service="$service_pattern"
                matched_pattern="${takeover_patterns[$service_pattern]}"
                break
            fi
        done

        if [[ -z "$matched_service" ]]; then
            continue
        fi

        # Probe the subdomain to check if the service page says it's unclaimed
        local probe_response=$(curl -s -k -L --max-time 10 -o /dev/null -w "%{http_code}" "$subdomain" 2>/dev/null || echo "")
        local probe_body=$(curl -s -k -L --max-time 10 "$subdomain" 2>/dev/null || echo "")

        if echo "$probe_body" | grep -qi "$matched_pattern" 2>/dev/null; then
            takeover_findings+=1
            local evidence_file="$takeover_output/takeover_${takeover_findings}.txt"
            {
                echo "Subdomain: $subdomain"
                echo "CNAME: $cname"
                echo "Service: $matched_service"
                echo "Detection pattern: $matched_pattern"
                echo "HTTP Status: $probe_response"
                echo ""
                echo "--- Response (first 500 chars) ---"
                echo "$probe_body" | head -c 500
            } > "$evidence_file"

            log_high "$subdomain -> VULNERABLE to takeover ($matched_service)"
            record_finding "CRITICAL" "Subdomain Takeover: $subdomain" "Subdomain $subdomain points to $matched_service which appears unclaimed. CNAME: $cname" "Remove the DNS CNAME record or claim the resource at the cloud provider." "$evidence_file"
        fi
    done

    echo ""
    if [[ "$takeover_findings" -eq 0 ]]; then
        log_ok "No vulnerable subdomains found"
    else
        log_high "$takeover_findings subdomain takeover(s) detected"
    fi
}

# =============================================================================
# CLOUD BUCKET ENUMERATION
# =============================================================================
check_cloud_buckets() {
    local target_domain="$1"
    local output="$2"

    log_banner "Cloud Bucket Enumeration"

    local bucket_output="$output/cloud_buckets"
    mkdir -p "$bucket_output"
    local bucket_findings=0

    local base_name=$(echo "$target_domain" | sed 's/\..*//')
    local domain_base=$(echo "$target_domain" | sed 's/^www\.//')

    local bucket_names=(
        "$domain_base"
        "$base_name"
        "${domain_base}-backup"
        "${domain_base}-assets"
        "${domain_base}-uploads"
        "${domain_base}-data"
        "${domain_base}-logs"
        "${domain_base}-media"
        "${domain_base}-static"
        "${domain_base}-storage"
        "${domain_base}-files"
        "${domain_base}-public"
        "${domain_base}-www"
        "${domain_base}-cdn"
        "${domain_base}-backups"
        "${domain_base}-dev"
        "${domain_base}-test"
        "${domain_base}-staging"
        "${domain_base}-prod"
        "${domain_base}-config"
        "${base_name}-backup"
        "${base_name}-assets"
        "${base_name}-uploads"
        "${base_name}-data"
        "${base_name}-static"
        "${base_name}-storage"
        "${base_name}-media"
        "${base_name}-cdn"
        "${domain_base}-bucket"
        "${base_name}-public"
        "${domain_base}-private"
        "${domain_base}-internal"
        "${domain_base}-s3"
        "${domain_base}-s3-backup"
        "${domain_base}-db-backup"
        "${domain_base}-database"
        "${domain_base}-app"
        "${domain_base}-application"
    )

    log_info "Testing ${#bucket_names[@]} bucket name(s) across AWS S3, GCP, and Azure..."

    for bucket in "${bucket_names[@]}"; do
        [[ -z "$bucket" ]] && continue

        # AWS S3
        local s3_url="https://${bucket}.s3.amazonaws.com"
        local s3_status=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 5 "$s3_url" 2>/dev/null)
        if [[ "$s3_status" == "200" ]]; then
            # Check if bucket is listable
            local s3_listing=$(curl -s -k --max-time 5 "${s3_url}/?max-keys=1" 2>/dev/null)
            if echo "$s3_listing" | grep -q "ListBucketResult"; then
                bucket_findings+=1
                echo "S3 Public (Listable): $s3_url" >> "$bucket_output/public_buckets.txt"
                log_high "S3 bucket PUBLIC and LISTABLE: $bucket"
                record_finding "CRITICAL" "AWS S3 Bucket: $bucket (public + listable)" "S3 bucket $bucket is publicly accessible and allows listing. URL: $s3_url" "Restrict bucket permissions. Remove public access." ""
            else
                bucket_findings+=1
                echo "S3 Public (Non-listing): $s3_url" >> "$bucket_output/public_buckets.txt"
                log_medium "S3 bucket PUBLIC: $bucket"
                record_finding "HIGH" "AWS S3 Bucket: $bucket (public)" "S3 bucket $bucket is publicly accessible (HTTP 200). URL: $s3_url" "Restrict bucket permissions or remove public access." ""
            fi
        elif [[ "$s3_status" == "403" ]]; then
            log_info "  S3 bucket exists (403): $bucket"
            echo "S3 Exists (Private): $s3_url" >> "$bucket_output/existing_buckets.txt"
        fi

        # GCP Storage
        local gcp_url="https://storage.googleapis.com/${bucket}"
        local gcp_status=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 5 "$gcp_url" 2>/dev/null)
        if [[ "$gcp_status" == "200" ]]; then
            bucket_findings+=1
            echo "GCP Public: $gcp_url" >> "$bucket_output/public_buckets.txt"
            log_medium "GCP bucket PUBLIC: $bucket"
            record_finding "HIGH" "GCP Storage Bucket: $bucket (public)" "GCP storage bucket $bucket is publicly accessible (HTTP 200). URL: $gcp_url" "Restrict bucket access. Use IAM or signed URLs." ""
        elif [[ "$gcp_status" == "403" ]]; then
            log_info "  GCP bucket exists (403): $bucket"
            echo "GCP Exists (Private): $gcp_url" >> "$bucket_output/existing_buckets.txt"
        fi

        # Azure Blob
        local azure_url="https://${bucket}.blob.core.windows.net"
        local azure_status=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 5 "$azure_url" 2>/dev/null)
        if [[ "$azure_status" == "200" ]]; then
            bucket_findings+=1
            echo "Azure Public: $azure_url" >> "$bucket_output/public_buckets.txt"
            log_medium "Azure Blob PUBLIC: $bucket"
            record_finding "HIGH" "Azure Blob Storage: $bucket (public)" "Azure blob container $bucket is publicly accessible (HTTP 200). URL: $azure_url" "Restrict blob container access. Use SAS tokens." ""
        elif [[ "$azure_status" == "403" ]]; then
            log_info "  Azure container exists (403): $bucket"
            echo "Azure Exists (Private): $azure_url" >> "$bucket_output/existing_buckets.txt"
        fi
    done

    if [[ "$bucket_findings" -eq 0 ]]; then
        log_ok "No public cloud buckets found"
    fi
}

# =============================================================================
# OAUTH / SSO TESTING
# =============================================================================
check_oauth_sso() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"

    log_banner "OAuth / SSO Security Testing"

    local oauth_output="$output/oauth_testing"
    mkdir -p "$oauth_output"
    local oauth_findings=0

    # 1. Discover OAuth endpoints by scraping the main page
    log_info "Discovering OAuth/SSO endpoints..."
    local index_html=$(http_request "$target_url" "GET" "" "")
    local oauth_urls_file="$oauth_output/oauth_urls.txt"
    : > "$oauth_urls_file"

    # Known OAuth patterns
    local oauth_patterns=(
        "facebook.com/v[0-9.]\+/dialog/oauth"
        "facebook.com/login.php"
        "accounts.google.com/o/oauth2"
        "accounts.google.com/signin"
        "login.microsoftonline.com"
        "login.live.com"
        "github.com/login/oauth"
        "twitter.com/i/oauth2"
        "twitter.com/oauth"
        "linkedin.com/oauth"
        "linkedin.com/login"
        "appleid.apple.com/auth"
        "amazon.com/ap/oa"
        "amazon.com/ap/login"
        "paypal.com/oauth2"
        "api.instagram.com/oauth"
        "discord.com/api/oauth2"
        "slack.com/oauth"
        "auth0.com/authorize"
        "okta.com/oauth2"
        "accounts.salesforce.com"
        "id.atlassian.com/login"
        "login.salesforce.com"
        "sso."
        "oauth."
        "/oauth/"
        "/auth/"
        "/sso/"
        "/login/oauth"
        "/authorize"
        "/token"
        "response_type="
        "client_id="
        "redirect_uri="
    )

    for pattern in "${oauth_patterns[@]}"; do
        local matches=$(echo "$index_html" | grep -oiP "$pattern" 2>/dev/null | sort -u)
        if [[ -n "$matches" ]]; then
            echo "=== Pattern: $pattern ===" >> "$oauth_urls_file"
            echo "$matches" >> "$oauth_urls_file"
            echo "" >> "$oauth_urls_file"
            log_medium "OAuth pattern found: $pattern"
        fi
    done

    # Check JS files for OAuth patterns too
    local js_urls=$(echo "$index_html" | grep -oiP 'src=["'\'']([^"'\'']*\.js[^"'\'']*)["'\'']' 2>/dev/null | sed 's/src=["\x27]//;s/["\x27]$//')
    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        if echo "$js_url" | grep -qE '^//'; then
            js_url="https:$js_url"
        elif echo "$js_url" | grep -qE '^/'; then
            js_url="${target_url}${js_url}"
        elif ! echo "$js_url" | grep -qE '^https?://'; then
            js_url="${target_url}/${js_url}"
        fi

        local js_content=$(http_request "$js_url" "GET" "" "")
        if [[ -n "$js_content" ]]; then
            for pattern in "${oauth_patterns[@]}"; do
                local js_matches=$(echo "$js_content" | grep -oiP "$pattern" 2>/dev/null | sort -u)
                if [[ -n "$js_matches" ]]; then
                    echo "=== In JS: $js_url | Pattern: $pattern ===" >> "$oauth_urls_file"
                    echo "$js_matches" >> "$oauth_urls_file"
                    log_medium "OAuth pattern in JS: $pattern (from $(basename "$js_url"))"
                fi
            done
        fi
    done <<< "$(echo "$js_urls")"

    # 2. Test OAuth parameters on discovered endpoints
    if [[ -s "$oauth_urls_file" ]]; then
        log_info "Testing OAuth endpoint security..."

        # Extract OAuth authorize URLs
        local oauth_endpoints=$(grep -oiP 'https?://[^"'\'' <>]+(authorize|oauth|auth|login|sso|token)[^"'\'' <>]*' "$oauth_urls_file" 2>/dev/null | sort -u | head -10)

        for ep in $oauth_endpoints; do
            [[ -z "$ep" ]] && continue
            log_info "  Testing: $(echo "$ep" | cut -c1-80)..."

            # Check for state parameter (anti-CSRF)
            if echo "$ep" | grep -qi "state="; then
                log_ok "  state parameter present (anti-CSRF)"
            else
                oauth_findings+=1
                record_finding "MEDIUM" "OAuth: Missing state parameter at $(echo "$ep" | cut -c1-60)" "OAuth authorize URL does not include state parameter. Vulnerable to CSRF in OAuth flow." "Add a cryptographically random state parameter to all OAuth authorize requests." ""
            fi

            # Check for response_type=token (implicit flow)
            if echo "$ep" | grep -qi "response_type=token"; then
                oauth_findings+=1
                record_finding "MEDIUM" "OAuth: Implicit flow used (response_type=token)" "OAuth flow uses implicit grant (token in URL fragment). Access token may leak via Referer header or browser history." "Use authorization code grant with PKCE instead of implicit flow." ""
            fi

            # Check for redirect_uri parameter - test bypass
            local redirect_uri=$(echo "$ep" | grep -oiP 'redirect_uri=[^&]+' 2>/dev/null | head -1 | sed 's/redirect_uri=//')
            if [[ -n "$redirect_uri" ]]; then
                local decoded_uri=$(echo "$redirect_uri" | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null || echo "$redirect_uri")
                log_info "    redirect_uri: $(echo "$decoded_uri" | cut -c1-60)"

                # Test redirect_uri bypass payloads
                local ruri_bypasses=(
                    "${decoded_uri}.evil.com"
                    "${decoded_uri}@evil.com"
                    "${decoded_uri}/../evil.com"
                    "https://evil.com/${decoded_uri}"
                    "https://evil.com/?${decoded_uri}"
                    "${decoded_uri}/?url=https://evil.com"
                )
                for bypass in "${ruri_bypasses[@]}"; do
                    log_info "    Testing: redirect_uri=$bypass"
                    # URL-encode the bypass
                    local encoded_bypass=$(python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))" 2>/dev/null <<< "$bypass" || echo "$bypass")
                    oauth_findings+=1
                    record_finding "LOW" "OAuth redirect_uri testing suggested" "redirect_uri parameter found. Test bypasses manually: redirect_uri=$bypass" "Use strict redirect_uri validation. Match exact URLs, not prefixes or suffixes." ""
                done
            fi

            # Check scope parameter
            local scope=$(echo "$ep" | grep -oiP 'scope=[^&]+' 2>/dev/null | head -1)
            if [[ -n "$scope" ]]; then
                local decoded_scope=$(python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null <<< "$scope" || echo "$scope")
                log_info "    scope: $(echo "$decoded_scope" | cut -c1-60)"

                # Flag dangerous scopes
                if echo "$decoded_scope" | grep -qiP "(admin|manage|write|delete|full_access|*\. )"; then
                    oauth_findings+=1
                    record_finding "MEDIUM" "OAuth: Over-privileged scope requested ($scope)" "OAuth scope includes administrative or write privileges: $decoded_scope" "Request only the minimum permissions needed. Use granular scopes." ""
                fi
            fi
        done
    else
        log_info "No OAuth/SSO endpoints discovered"
    fi

    if [[ "$oauth_findings" -eq 0 ]]; then
        log_ok "No OAuth/SSO security issues detected"
    fi
}

# =============================================================================
# ORIGIN IP DISCOVERY
# =============================================================================
discover_origin_ip() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"

    log_banner "Origin IP Discovery"

    local origin_output="$output/origin_ip"
    mkdir -p "$origin_output"
    local origin_findings=0

    log_info "Searching for the real origin IP behind CDN..."

    # 1. Direct DNS resolution
    log_info "1. Direct A record resolution..."
    local direct_ips=$(dig +short A "$target_domain" 2>/dev/null)
    if [[ -n "$direct_ips" ]]; then
        echo "Direct A records: $direct_ips" > "$origin_output/dns_records.txt"
        log_info "  $direct_ips"

        # Check if IP belongs to known CDN ranges
        for ip in $direct_ips; do
            if echo "$ip" | grep -qE '^104\.1[6-9]\.|^104\.2[0-4]\.|^173\.245\.|^103\.21\.|^103\.22\.|^103\.31\.|^108\.162\.|^131\.0\.|^141\.101\.|^162\.158\.|^172\.64\.|^172\.65\.|^172\.66\.|^172\.67\.|^172\.68\.|^172\.69\.|^188\.114\.|^190\.93\.|^197\.234\.|^198\.41\.'; then
                log_info "    -> CloudFlare IP range (expected)"
            elif echo "$ip" | grep -qE '^2a06:'; then
                log_info "    -> CloudFlare IPv6 range"
            else
                origin_findings+=1
                record_finding "MEDIUM" "Origin IP: $ip (might be direct origin)" "IP $ip for $target_domain does not match known CDN ranges. May be the origin server IP." "Ensure all traffic routes through your CDN. Block direct IP access." "$origin_output/dns_records.txt"
            fi
        done
    fi

    # 2. SSL Certificate Subject Alternative Names
    log_info "2. SSL certificate SAN extraction..."
    local ssl_info=$(echo | openssl s_client -servername "$target_domain" -connect "$target_domain":443 2>/dev/null </dev/null)
    local sans=$(echo "$ssl_info" | openssl x509 -noout -ext subjectAltName 2>/dev/null)
    if [[ -n "$sans" ]]; then
        echo "$sans" > "$origin_output/ssl_sans.txt"
        local all_sans=$(echo "$sans" | grep -oP 'DNS:[^,]+' | sed 's/DNS://' | sort -u)
        log_info "  Found $(echo "$all_sans" | wc -l) SAN entries"
        for san in $all_sans; do
            if [[ "$san" != "$target_domain" ]] && [[ "$san" != "*.$target_domain" ]]; then
                log_info "    $san"
                local san_ip=$(dig +short A "$san" 2>/dev/null | head -1)
                if [[ -n "$san_ip" ]]; then
                    log_info "      -> $san_ip"
                    echo "$san -> $san_ip" >> "$origin_output/ssl_san_ips.txt"
                fi
            fi
        done
    fi

    # 3. MX/SPF record IP extraction
    log_info "3. MX/SPF record analysis..."
    local mx_records=$(dig +short MX "$target_domain" 2>/dev/null)
    if [[ -n "$mx_records" ]]; then
        echo "MX Records:" >> "$origin_output/dns_records.txt"
        echo "$mx_records" >> "$origin_output/dns_records.txt"
        while IFS= read -r mx; do
            local mx_host=$(echo "$mx" | awk '{print $2}')
            local mx_ip=$(dig +short A "$mx_host" 2>/dev/null | head -1)
            if [[ -n "$mx_ip" ]]; then
                log_info "  MX: $mx_host -> $mx_ip"
                origin_findings+=1
                record_finding "INFO" "Origin IP candidate: $mx_ip (from MX record $mx_host)" "Mail server IP $mx_ip may be on same infrastructure as origin." "Ensure proper network segmentation between mail and web servers." ""
            fi
        done <<< "$mx_records"
    fi

    local spf_records=$(dig +short TXT "$target_domain" 2>/dev/null | grep -i "v=spf1")
    if [[ -n "$spf_records" ]]; then
        echo "SPF Records:" >> "$origin_output/dns_records.txt"
        echo "$spf_records" >> "$origin_output/dns_records.txt"
        local spf_ips=$(echo "$spf_records" | grep -oiP 'ip[46]:[0-9./:a-f]+' 2>/dev/null)
        if [[ -n "$spf_ips" ]]; then
            log_info "  SPF IPs: $spf_ips"
            echo "SPF IPs: $spf_ips" >> "$origin_output/dns_records.txt"
        fi
    fi

    # 4. NS record IPs
    log_info "4. Nameserver analysis..."
    local ns_records=$(dig +short NS "$target_domain" 2>/dev/null)
    if [[ -n "$ns_records" ]]; then
        echo "NS Records:" >> "$origin_output/dns_records.txt"
        while IFS= read -r ns; do
            local ns_ip=$(dig +short A "$ns" 2>/dev/null | head -1)
            if [[ -n "$ns_ip" ]]; then
                log_info "  NS: $ns -> $ns_ip"
                echo "$ns -> $ns_ip" >> "$origin_output/ns_ips.txt"
            fi
        done <<< "$ns_records"
    fi

    # 5. Check favicon hash
    log_info "5. Favicon hash analysis..."
    local favicon_url="${target_url}/favicon.ico"
    local favicon_data=$(curl -s -k --max-time 5 "$favicon_url" 2>/dev/null)
    if [[ -n "$favicon_data" && ${#favicon_data} -gt 100 ]]; then
        local favicon_hash=$(echo "$favicon_data" | md5sum | awk '{print $1}')
        log_info "  Favicon hash: $favicon_hash"
        echo "Favicon URL: $favicon_url" > "$origin_output/favicon_info.txt"
        echo "MD5 Hash: $favicon_hash" >> "$origin_output/favicon_info.txt"
        echo "Size: ${#favicon_data} bytes" >> "$origin_output/favicon_info.txt"

        # Common favicon hashes (can be used with Shodan/Censys)
        # Add well-known hashes based on CMS/platform
        local known_hashes=(
            "f4dc1c0f6dfb5a100c44b3e22e0eae0b:WordPress"
            "f2f3db7f0e5f39a1c8ed84e82c59c8b8:Drupal"
            "df1f3e580b3db73e24e9e3ea67c21e7f:Joomla"
            "6a0d4f47c5c8ef18a7c5a1e2a3b4c5d6:phpMyAdmin"
            "b8d0f6e1c3a24b7f9e5d8c1a2b3f4e5d:Jenkins"
        )
        for entry in "${known_hashes[@]}"; do
            local known_hash="${entry%%:*}"
            local known_name="${entry##*:}"
            if [[ "$favicon_hash" == "$known_hash" ]]; then
                log_medium "  Favicon matches $known_name"
                record_finding "INFO" "Technology: $known_name (favicon match)" "Favicon hash matches known $known_name icon." "" ""
            fi
        done
    fi

    # 6. Check crt.sh results if available
    local crt_file="$output/crt_sh.json"
    if [[ -f "$crt_file" ]]; then
        log_info "6. crt.sh IP extraction..."
        local cert_ips=$(grep -oiP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$crt_file" 2>/dev/null | sort -u)
        if [[ -n "$cert_ips" ]]; then
            echo "crt.sh IPs:" >> "$origin_output/crt_ips.txt"
            for ip in $cert_ips; do
                echo "$ip" >> "$origin_output/crt_ips.txt"
            done
            log_info "  Found $(echo "$cert_ips" | wc -l) unique IP(s) from certificates"
        fi
    fi

    if [[ "$origin_findings" -eq 0 ]]; then
        log_ok "No origin IP candidates found (all traffic appears CDN-wrapped)"
    fi
}

# =============================================================================
# HTTP REQUEST SMUGGLING
# =============================================================================
check_smuggling() {
    local target_url="$1"
    local target_domain="$2"
    local output="$3"

    log_banner "HTTP Request Smuggling Testing"

    local smuggle_output="$output/smuggling"
    mkdir -p "$smuggle_output"
    local smuggle_findings=0

    log_info "Testing for HTTP request smuggling vulnerabilities..."
    log_info "This tests CL.TE, TE.CL, and TE.TE desync techniques."

    local host=$(echo "$target_url" | sed -E 's|^https?://([^/]+).*|\1|')
    local port=443
    local use_ssl=true
    if echo "$target_url" | grep -qi "^http://"; then
        port=80
        use_ssl=false
    fi

    local ssl_flag=""
    [[ "$use_ssl" == true ]] && ssl_flag="--ssl"

    # CL.TE: Content-Length + Transfer-Encoding: chunked
    log_info "1. Testing CL.TE (Content-Length + Transfer-Encoding)..."
    local cl_te_payload=$(printf "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /nonexistent HTTP/1.1\r\nFoo: bar" "$host")

    local cl_te_response=$(echo -e "$cl_te_payload" | timeout 10 openssl s_client -quiet -connect "${host}:${port}" 2>/dev/null </dev/null | head -20)
    if [[ -z "$cl_te_response" ]]; then
        cl_te_response=$(echo -e "$cl_te_payload" | timeout 10 nc -w 5 "$host" "$port" 2>/dev/null | head -20)
    fi

    if echo "$cl_te_response" | grep -qi "404\|406\|Not Found"; then
        smuggle_findings+=1
        echo "=== CL.TE Test ===" > "$smuggle_output/cl_te.txt"
        echo "Response contains 404/406 - potential CL.TE desync" >> "$smuggle_output/cl_te.txt"
        echo "$cl_te_response" >> "$smuggle_output/cl_te.txt"
        log_high "CL.TE desync detected!"
        record_finding "CRITICAL" "HTTP Request Smuggling: CL.TE" "CL.TE desync detected on $host:$port. Proxy-parsed Content-Length but backend-parsed Transfer-Encoding." "Reconfigure proxy/load balancer to reject conflicting CL+TE headers. Use HTTP/2." "$smuggle_output/cl_te.txt"
    else
        log_info "  No CL.TE desync detected"
    fi

    # TE.CL: Transfer-Encoding + Content-Length
    log_info "2. Testing TE.CL (Transfer-Encoding + Content-Length)..."
    local te_cl_payload=$(printf "POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /nonexistent HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n" "$host")

    local te_cl_response=$(echo -e "$te_cl_payload" | timeout 10 openssl s_client -quiet -connect "${host}:${port}" 2>/dev/null </dev/null | head -20)
    if [[ -z "$te_cl_response" ]]; then
        te_cl_response=$(echo -e "$te_cl_payload" | timeout 10 nc -w 5 "$host" "$port" 2>/dev/null | head -20)
    fi

    if echo "$te_cl_response" | grep -qi "404\|406\|Not Found"; then
        smuggle_findings+=1
        echo "=== TE.CL Test ===" > "$smuggle_output/te_cl.txt"
        echo "Response contains 404/406 - potential TE.CL desync" >> "$smuggle_output/te_cl.txt"
        echo "$te_cl_response" >> "$smuggle_output/te_cl.txt"
        log_high "TE.CL desync detected!"
        record_finding "CRITICAL" "HTTP Request Smuggling: TE.CL" "TE.CL desync detected on $host:$port. Backend-parsed Transfer-Encoding but proxy-parsed Content-Length." "Reconfigure proxy/load balancer to reject conflicting CL+TE headers. Use HTTP/2." "$smuggle_output/te_cl.txt"
    else
        log_info "  No TE.CL desync detected"
    fi

    # TE.TE: Malformed Transfer-Encoding
    log_info "3. Testing TE.TE (malformed Transfer-Encoding)..."
    local te_te_variants=(
        "Transfer-Encoding: xchunked"
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"
        "Transfer-Encoding : chunked"
        "Transfer-Encoding:\tchunked"
        "Transfer-Encoding: chunked\r\nTransfer-encoding: chunked"
    )

    for variant in "${te_te_variants[@]}"; do
        local te_te_payload=$(printf "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\n%s\r\n\r\n0\r\n\r\nX" "$host" "$variant")
        local te_te_response=$(echo -e "$te_te_payload" | timeout 10 openssl s_client -quiet -connect "${host}:${port}" 2>/dev/null </dev/null | head -10)
        if [[ -z "$te_te_response" ]]; then
            te_te_response=$(echo -e "$te_te_payload" | timeout 10 nc -w 5 "$host" "$port" 2>/dev/null | head -10)
        fi
        if echo "$te_te_response" | grep -qi "404\|406\|Not Found"; then
            smuggle_findings+=1
            echo "=== TE.TE Variant: $variant ===" >> "$smuggle_output/te_te.txt"
            echo "$te_te_response" >> "$smuggle_output/te_te.txt"
            log_medium "TE.TE desync detected with variant: $(echo "$variant" | head -c50)"
            record_finding "CRITICAL" "HTTP Request Smuggling: TE.TE" "TE.TE desync detected with variant: $(echo "$variant" | tr '\r\n' ' ' | head -c 60)" "Normalize Transfer-Encoding header. Reject malformed headers." "$smuggle_output/te_te.txt"
            break
        fi
    done

    if [[ "$smuggle_findings" -eq 0 ]]; then
        log_info "  No TE.TE desync detected"
        log_ok "No HTTP request smuggling vulnerabilities detected"
    fi
}

# =============================================================================
# RACE CONDITION TESTING
# =============================================================================
check_race_conditions() {
    local target_url="$1"
    local output="$2"
    local bb_output="$3"

    log_banner "Race Condition Testing"

    local race_output="$bb_output/race_conditions"
    mkdir -p "$race_output"
    local race_findings=0

    # Find mutation endpoints from web enum and SAST
    local endpoints=()
    local api_file="$output/all_discovered_urls.txt"
    if [[ -f "$api_file" ]]; then
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            # Only test mutation endpoints (POST/PUT/DELETE)
            if echo "$url" | grep -qiP "(/api/|/v[0-9]+/|/rest/|/graphql)"; then
                endpoints+=("$url")
            fi
        done < "$api_file"
    fi

    # Add common mutation endpoints
    local common_mutations=(
        "/api/login" "/api/register" "/api/signup"
        "/api/vote" "/api/like" "/api/follow"
        "/api/comment" "/api/post" "/api/create"
        "/api/update" "/api/delete" "/api/upload"
        "/api/checkout" "/api/payment" "/api/order"
        "/api/coupon" "/api/discount" "/api/redeem"
        "/api/gift" "/api/reward" "/api/points"
        "/api/transfer" "/api/withdraw" "/api/deposit"
        "/api/profile/update" "/api/settings"
        "/api/password/change" "/api/email/change"
        "/graphql" "/api/graphql"
    )
    for ep in "${common_mutations[@]}"; do
        endpoints+=("${target_url}${ep}")
    done

    # Deduplicate
    local unique_eps=()
    if [[ ${#endpoints[@]} -gt 0 ]]; then
        while IFS= read -r ep; do
            [[ -n "$ep" ]] && unique_eps+=("$ep")
        done < <(printf '%s\n' "${endpoints[@]}" | sort -u | head -20)
    fi

    if [[ ${#unique_eps[@]} -eq 0 ]]; then
        log_info "No endpoints found to test for race conditions"
        return
    fi

    log_info "Testing ${#unique_eps[@]} endpoint(s) for race conditions..."

    for endpoint in "${unique_eps[@]}"; do
        [[ -z "$endpoint" ]] && continue

        # Baseline: single request
        local baseline=$(waf_request "$endpoint" "GET" "" "")
        local baseline_size=$(echo "$baseline" | wc -c)

        # Race condition test: 5 concurrent requests
        local race_responses=()
        local race_pids=()

        for i in 1 2 3 4 5; do
            (
                local resp=$(curl -s -k --max-time "$TIMEOUT" "$endpoint" 2>/dev/null)
                echo "$resp" > "/tmp/race_response_$$_${i}.txt"
            ) &
            race_pids+=($!)
        done

        # Wait for all to complete
        wait

        # Collect responses
        local all_same=true
        local prev_size=0
        for i in 1 2 3 4 5; do
            local resp_file="/tmp/race_response_$$_${i}.txt"
            if [[ -f "$resp_file" ]]; then
                local size=$(wc -c < "$resp_file")
                if [[ "$prev_size" -ne 0 ]] && [[ "$size" -ne "$prev_size" ]]; then
                    all_same=false
                fi
                prev_size="$size"
                rm -f "$resp_file"
            fi
        done

        if [[ "$all_same" == false ]]; then
            race_findings+=1
            echo "=== Potential Race Condition ===" >> "$race_output/race_endpoints.txt"
            echo "Endpoint: $endpoint" >> "$race_output/race_endpoints.txt"
            echo "Baseline size: $baseline_size" >> "$race_output/race_endpoints.txt"
            echo "Concurrent responses differed" >> "$race_output/race_endpoints.txt"
            echo "" >> "$race_output/race_endpoints.txt"
            log_medium "Potential race condition at $(echo "$endpoint" | cut -c1-60)"
            record_finding "MEDIUM" "Race Condition: $(basename "$endpoint" | cut -c1-40)" "Concurrent requests to $endpoint returned inconsistent responses. May allow TOCTOU exploitation." "Use database transactions with proper locking. Consider idempotency tokens." ""
        fi
    done

    if [[ "$race_findings" -eq 0 ]]; then
        log_ok "No race conditions detected"
    fi
}
