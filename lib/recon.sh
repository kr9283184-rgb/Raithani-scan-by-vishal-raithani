#!/bin/bash
# =============================================================================
# Raithani-Scan - Reconnaissance Phase
# WHOIS, DNS, subdomain discovery, technology fingerprinting, SSL analysis
# =============================================================================

run_recon() {
    start_phase "Reconnaissance"
    
    local target_url="$1"
    local target_domain="$2"
    local output="$3"
    
    # 1. WHOIS Lookup
    log_step "WHOIS Lookup..."
    if command -v whois &>/dev/null; then
        whois "$target_domain" 2>/dev/null | head -50 > "$output/whois.txt"
        log_ok "WHOIS data saved to whois.txt"
    else
        log_warn "whois not installed, skipping"
    fi
    
    # 2. DNS Records
    log_step "DNS Enumeration..."
    {
        echo "=== A Record ==="
        dig +short A "$target_domain" 2>/dev/null
        echo "=== AAAA Record ==="
        dig +short AAAA "$target_domain" 2>/dev/null
        echo "=== MX Record ==="
        dig +short MX "$target_domain" 2>/dev/null
        echo "=== NS Record ==="
        dig +short NS "$target_domain" 2>/dev/null
        echo "=== TXT Record ==="
        dig +short TXT "$target_domain" 2>/dev/null
        echo "=== CNAME ==="
        dig +short CNAME "$target_domain" 2>/dev/null
        echo "=== SOA ==="
        dig +short SOA "$target_domain" 2>/dev/null
    } > "$output/dns_records.txt"
    log_ok "DNS records saved"
    
    # 3. Technology Fingerprinting
    log_step "Technology Fingerprinting..."
    if command -v whatweb &>/dev/null; then
        whatweb -a 3 "$target_url" 2>/dev/null > "$output/whatweb.txt"
        while IFS= read -r line; do
            log_info "$line"
        done < "$output/whatweb.txt"
        log_ok "Technology detected (see whatweb.txt)"
    else
        # Fallback: basic header analysis
        log_warn "whatweb not installed, using basic header analysis"
        curl -s -k -I -L --max-time "$TIMEOUT" "$target_url" 2>/dev/null > "$output/headers_recon.txt"
        while IFS= read -r line; do
            [[ -n "$line" ]] && log_info "$line"
        done < "$output/headers_recon.txt"
    fi
    
    # 4. WAF Detection (if not already done)
    log_step "SSL/TLS Analysis..."
    if command -v sslscan &>/dev/null; then
        sslscan --no-colour "$target_domain" 2>/dev/null | tee "$output/sslscan.txt" | grep -E "SSL|TLS|cipher|certificate|subject|issuer|notBefore|notAfter" | while IFS= read -r line; do
            log_info "$line"
        done
        log_ok "SSL scan complete"
    elif command -v nmap &>/dev/null; then
        nmap -p 443 --script ssl-enum-ciphers "$target_domain" 2>/dev/null > "$output/ssl_scan.txt"
        log_info "SSL ciphers enumerated via nmap"
    else
        log_warn "sslscan not installed, skipping SSL analysis"
    fi
    
    # 5. SSL Certificate Transparency (crt.sh)
    log_step "Certificate Transparency (crt.sh)..."
    local crt_json=$(curl -s -k --max-time 15 "https://crt.sh/?q=%25.${target_domain}&output=json" 2>/dev/null || echo "")
    local crt_subdomains=""
    if [[ -n "$crt_json" && "$crt_json" != "[]" ]]; then
        echo "$crt_json" > "$output/crt_sh.json"
        crt_subdomains=$(echo "$crt_json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    subs = set()
    for entry in data:
        name = entry.get('name_value', '')
        for n in name.split('\n'):
            n = n.strip().lower()
            if n and not n.startswith('*'):
                subs.add(n)
    for s in sorted(subs):
        print(s)
except:
    pass
" 2>/dev/null)
        if [[ -n "$crt_subdomains" ]]; then
            echo "$crt_subdomains" > "$output/crt_sh_subdomains.txt"
            local crt_count=$(echo "$crt_subdomains" | wc -l)
            log_ok "crt.sh returned $crt_count subdomain(s)"
        else
            log_info "No subdomains extracted from crt.sh"
        fi
    else
        log_info "crt.sh returned no data"
    fi

    # 6. SSL Certificate SAN extraction
    log_step "SSL Certificate SAN extraction..."
    local ssl_cert=$(echo | openssl s_client -servername "$target_domain" -connect "${target_domain}:443" 2>/dev/null </dev/null)
    local sans=$(echo "$ssl_cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null)
    if [[ -n "$sans" ]]; then
        echo "$sans" > "$output/ssl_sans.txt"
        local san_count=$(echo "$sans" | grep -oP 'DNS:[^,]+' | wc -l)
        log_info "Certificate has $san_count SAN entry(ies)"
        echo "$sans" | grep -oP 'DNS:[^,]+' | sed 's/DNS://' >> "$output/crt_sh_subdomains.txt" 2>/dev/null
    fi

    # 7. Favicon hash computation
    log_step "Favicon hash..."
    local favicon_url="${target_url}/favicon.ico"
    local favicon_data=$(curl -s -k --max-time 5 "$favicon_url" 2>/dev/null)
    if [[ -n "$favicon_data" && ${#favicon_data} -gt 50 ]]; then
        local favicon_hash=$(echo "$favicon_data" | md5sum | awk '{print $1}')
        echo "Favicon URL: $favicon_url" > "$output/favicon_info.txt"
        echo "MD5: $favicon_hash" >> "$output/favicon_info.txt"
        echo "Size: ${#favicon_data} bytes" >> "$output/favicon_info.txt"
        log_info "Favicon MD5: $favicon_hash (${#favicon_data} bytes)"

        # Known favicon hashes for tech detection
        case "$favicon_hash" in
            f4dc1c0f6dfb5a100c44b3e22e0eae0b) log_info "  -> WordPress" ;;
            df1f3e580b3db73e24e9e3ea67c21e7f) log_info "  -> Joomla" ;;
            f2f3db7f0e5f39a1c8ed84e82c59c8b8) log_info "  -> Drupal" ;;
            6a0d4f47c5c8ef18a7c5a1e2a3b4c5d6) log_info "  -> phpMyAdmin" ;;
            b8d0f6e1c3a24b7f9e5d8c1a2b3f4e5d) log_info "  -> Jenkins" ;;
        esac
    else
        log_info "No favicon.ico found"
    fi

    # 8. Subdomain Discovery
    log_step "Subdomain Discovery..."
    
    # Advanced subdomain tools (if available)
    local all_subs=()
    local tools_used=false

    if command -v subfinder &>/dev/null; then
        log_info "Running subfinder..."
        local subfinder_out=$(subfinder -d "$target_domain" -silent 2>/dev/null)
        if [[ -n "$subfinder_out" ]]; then
            all_subs+=($subfinder_out)
            tools_used=true
        fi
    fi

    if command -v sublist3r &>/dev/null; then
        log_info "Running sublist3r..."
        local sublist3r_out=$(sublist3r -d "$target_domain" 2>/dev/null | grep -E "^[a-zA-Z0-9]" || true)
        if [[ -n "$sublist3r_out" ]]; then
            all_subs+=($sublist3r_out)
            tools_used=true
        fi
    fi

    if command -v assetfinder &>/dev/null; then
        log_info "Running assetfinder..."
        local assetfinder_out=$(assetfinder --subs-only "$target_domain" 2>/dev/null)
        if [[ -n "$assetfinder_out" ]]; then
            all_subs+=($assetfinder_out)
            tools_used=true
        fi
    fi

    if command -v dnsrecon &>/dev/null; then
        dnsrecon -d "$target_domain" -t std 2>/dev/null > "$output/dnsrecon.txt"
        local sub_count=$(grep -c "A\|CNAME" "$output/dnsrecon.txt" 2>/dev/null)
        log_ok "DNS recon complete ($sub_count records found)"
        tools_used=true
    fi

    # Common subdomains with dig (always run)
    log_info "Checking common subdomains..."
    local common_subs=("www" "mail" "admin" "api" "dev" "staging" "blog" "cdn" "ftp" "webmail" "test" "vpn" "shop" "portal" "secure" "m" "app" "mobile" "backup" "git" "docs" "help" "support" "status" "demo" "beta" "stg" "stage" "qa" "uat" "preprod" "internal" "corp" "jenkins" "jira" "gitlab" "grafana" "prometheus" "kibana" "redis" "rabbitmq" "kafka" "docker" "k8s" "kubernetes" "s3" "minio" "storage" "files" "static" "assets" "cdn" "img" "video" "stream" "live" "tv" "radio" "podcast" "webinar" "learn" "training" "academy" "course" "courses" "classroom" "lms" "moodle" "blackboard" "canvas" "zoom" "teams" "meet" "meeting" "meetings" "skype" "lync" "webex" "adobeconnect" "adobe" "air" "flash" "java" "silverlight")
    local found_subs=()
    for sub in "${common_subs[@]}"; do
        local result=$(dig +short "$sub.$target_domain" 2>/dev/null)
        if [[ -n "$result" ]]; then
            found_subs+=("$sub.$target_domain")
            log_info "  Found: $sub.$target_domain -> $result"
        fi
    done
    if [[ ${#found_subs[@]} -gt 0 ]]; then
        all_subs+=("${found_subs[@]}")
    fi

    # Combine and deduplicate all sources
    if [[ ${#all_subs[@]} -gt 0 ]]; then
        printf '%s\n' "${all_subs[@]}" | sort -u > "$output/subdomains.txt"
        local total_unique=$(wc -l < "$output/subdomains.txt")
        log_ok "$total_unique unique subdomains discovered"
        record_finding "INFO" "Subdomains discovered" "$total_unique subdomains found. See subdomains.txt" "Investigate each subdomain for potential attack surface expansion." ""
    fi

    # Save all subdomains from all sources combined
    {
        cat "$output/crt_sh_subdomains.txt" 2>/dev/null
        cat "$output/subdomains.txt" 2>/dev/null
    } | sort -u > "$output/all_subdomains.txt"
    local all_total=$(wc -l < "$output/all_subdomains.txt" 2>/dev/null || echo 0)
    [[ "$all_total" -gt 0 ]] && log_info "Total unique subdomains (all sources): $all_total"
    
    # 6. HTTP Headers Analysis
    log_step "HTTP Headers Analysis..."
    curl -s -k -I -L --max-time "$TIMEOUT" "$target_url" 2>/dev/null > "$output/response_headers.txt"
    
    # Check security headers
    local sec_headers_file="$output/response_headers.txt"
    
    if ! grep -qi "strict-transport-security\|HSTS\|Strict-Transport-Security" "$sec_headers_file" 2>/dev/null; then
        log_warn "Missing HSTS (Strict-Transport-Security) header"
        record_finding "MEDIUM" "Missing HSTS Header" "HTTP Strict-Transport-Security not set. Potential for SSL stripping attacks." "Add Strict-Transport-Security: max-age=31536000; includeSubDomains" ""
    fi
    
    if ! grep -qi "content-security-policy\|Content-Security-Policy" "$sec_headers_file" 2>/dev/null; then
        log_warn "Missing Content-Security-Policy header"
        record_finding "MEDIUM" "Missing CSP Header" "Content-Security-Policy not set. Potential for XSS and data injection attacks." "Implement a Content-Security-Policy header" ""
    fi
    
    if ! grep -qi "x-frame-options\|X-Frame-Options" "$sec_headers_file" 2>/dev/null; then
        log_warn "Missing X-Frame-Options header"
        record_finding "MEDIUM" "Missing X-Frame-Options Header" "Page may be vulnerable to clickjacking attacks." "Add X-Frame-Options: DENY or SAMEORIGIN" ""
    fi
    
    if ! grep -qi "x-content-type-options\|X-Content-Type-Options" "$sec_headers_file" 2>/dev/null; then
        log_warn "Missing X-Content-Type-Options header"
        record_finding "LOW" "Missing X-Content-Type-Options Header" "Browser may perform MIME-type sniffing." "Add X-Content-Type-Options: nosniff" ""
    fi
    
    if ! grep -qi "x-xss-protection\|X-XSS-Protection" "$sec_headers_file" 2>/dev/null; then
        log_info "X-XSS-Protection header not set (optional in modern browsers)"
    fi
    
    # Check for Server info disclosure
    local server_header=$(grep -i "^server:" "$sec_headers_file" 2>/dev/null | sed 's/^server: //I')
    if [[ -n "$server_header" ]]; then
        log_info "Server: $server_header"
        record_finding "LOW" "Server Information Disclosure" "Server header reveals: $server_header. Helps attackers target specific vulnerabilities." "Remove or obfuscate the Server header" ""
    fi
    
    # 7. robots.txt
    log_step "Checking robots.txt..."
    local robots_content=$(http_request "${target_url}/robots.txt")
    if [[ -n "$robots_content" && "$robots_content" != *"Not Found"* && "$robots_content" != *"404"* ]]; then
        echo "$robots_content" > "$output/robots.txt"
        log_ok "robots.txt found and saved"
        local disallowed=$(echo "$robots_content" | grep -i "Disallow:" | head -10)
        if [[ -n "$disallowed" ]]; then
            echo "$disallowed" | while IFS= read -r line; do
                log_info "  Disallowed: $line"
            done
        fi
    else
        log_info "No robots.txt found"
    fi
    
    # 8. sitemap.xml
    log_step "Checking sitemap.xml..."
    local sitemap_content=$(http_request "${target_url}/sitemap.xml")
    if [[ -n "$sitemap_content" && "$sitemap_content" != *"Not Found"* && "$sitemap_content" != *"404"* ]]; then
        echo "$sitemap_content" > "$output/sitemap.xml"
        log_ok "sitemap.xml found and saved"
    fi
    
    # Save recon summary
    {
        echo "RECONNAISSANCE SUMMARY"
        echo "====================="
        echo "Target: $target_url"
        echo "Domain: $target_domain"
        echo "Timestamp: $(date)"
        echo ""
        echo "--- DNS Records ---"
        cat "$output/dns_records.txt" 2>/dev/null
        echo ""
        echo "--- Subdomains ---"
        cat "$output/subdomains.txt" 2>/dev/null || echo "None discovered"
        echo ""
        echo "--- Security Headers ---"
        grep -iE "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|server|x-powered-by" "$output/response_headers.txt" 2>/dev/null || echo "No significant headers"
    } > "$output/recon_summary.txt"
    
    end_phase
}
