#!/bin/bash
# =============================================================================
# Raithani-Scan - Port & Service Scanning
# Uses nmap for port discovery, service version detection, and OS fingerprinting
# =============================================================================

run_port_scan() {
    start_phase "Port & Service Scanning"
    
    local target_domain="$1"
    local output="$2"
    local port_file="$output/ports.txt"
    local service_file="$output/services.txt"
    
    log_step "Performing port scan on $target_domain..."
    
    # Determine if we need sudo for SYN scan
    local sudo_prefix=""
    if [[ "$PORT_SCAN_TYPE" == "sS" ]]; then
        sudo_prefix="sudo"
        log_info "SYN stealth scan selected (requires elevated privileges)"
    fi
    
    if ! command -v nmap &>/dev/null; then
        log_error "nmap not found. Installing..."
        sudo apt install -y nmap 2>/dev/null
    fi
    
    # Phase 1: Quick port discovery
    log_step "Phase 1: Port discovery (top 1000 ports)..."
    local quick_scan_cmd
    quick_scan_cmd=($sudo_prefix nmap "-${PORT_SCAN_TYPE:-sS}" --top-ports 1000 $NMAP_TIMING -T4 --open -Pn -n "$target_domain" -oN "$output/nmap_quick.txt")
    "${quick_scan_cmd[@]}" 2>/dev/null
    
    local open_ports=$(grep -E "^[0-9]+/tcp" "$output/nmap_quick.txt" 2>/dev/null | wc -l)
    log_ok "Discovered $open_ports open ports"
    
    if [[ "$open_ports" -eq 0 ]]; then
        log_warn "No open ports found on standard ports. Trying broader scan..."
        local broader_cmd
        broader_cmd=($sudo_prefix nmap "-${PORT_SCAN_TYPE:-sS}" -p 1-10000 $NMAP_TIMING -T4 --open -Pn -n "$target_domain" -oN "$output/nmap_broad.txt")
        "${broader_cmd[@]}" 2>/dev/null
        open_ports=$(grep -E "^[0-9]+/tcp" "$output/nmap_broad.txt" 2>/dev/null | wc -l)
        log_ok "Discovered $open_ports open ports (1-10000)"
    fi
    
    # Extract open ports list
    grep -E "^[0-9]+/tcp" "$output/nmap_quick.txt" "$output/nmap_broad.txt" 2>/dev/null | cut -d'/' -f1 | sort -un > "$port_file"
    local ports=$(tr '\n' ',' < "$port_file" | sed 's/,$//')
    
    if [[ -z "$ports" ]]; then
        # Try common ports
        ports="80,443,8080,8443"
        log_info "Using default common ports: $ports"
    fi
    
    # Phase 2: Service version detection
    log_step "Phase 2: Service version detection..."
    local version_cmd
    version_cmd=($sudo_prefix nmap "-${PORT_SCAN_TYPE:-sS}" -sV --version-intensity 7 -p "$ports" $NMAP_TIMING --open -Pn -n "$target_domain" -oN "$service_file")
    "${version_cmd[@]}" 2>/dev/null
    
    # Phase 3: OS detection (level 2+)
    if [[ "$SCAN_LEVEL" -ge 2 ]]; then
        log_step "Phase 3: OS Detection..."
        local os_cmd
        os_cmd=($sudo_prefix nmap -O --osscan-guess -p "$ports" $NMAP_TIMING --open -Pn -n "$target_domain" -oN "$output/nmap_os.txt")
        "${os_cmd[@]}" 2>/dev/null
        
        local os_detected=$(grep -i "OS details\|Aggressive OS" "$output/nmap_os.txt" 2>/dev/null | head -5)
        if [[ -n "$os_detected" ]]; then
            log_ok "OS detected: $os_detected"
        fi
    fi
    
    # Phase 4: NSE default scripts (level 2+)
    if [[ "$SCAN_LEVEL" -ge 2 ]]; then
        log_step "Phase 4: Running NSE default scripts..."
        local nse_cmd
        nse_cmd=($sudo_prefix nmap -sV -p "$ports" --script "default,safe" $NMAP_TIMING --open -Pn -n "$target_domain" -oN "$output/nmap_nse.txt")
        "${nse_cmd[@]}" 2>/dev/null
    fi
    
    # Parse results
    log_step "Analyzing scan results..."
    
    # Extract service info
    if [[ -f "$service_file" ]]; then
        echo "PORT    STATE SERVICE VERSION" > "$output/parsed_services.txt"
        grep -E "^[0-9]+/tcp" "$service_file" >> "$output/parsed_services.txt"
        
        log_separator
        log_info "Open ports and services:"
        grep -E "^[0-9]+/tcp" "$service_file" 2>/dev/null | while IFS= read -r line; do
            log_info "  $line"
        done
        log_separator
        
        # Check for interesting services
        if grep -qi "ssh\|22/tcp" "$service_file" 2>/dev/null; then
            record_finding "INFO" "SSH Service" "SSH service detected on port 22. Version: $(grep "22/tcp" "$service_file" | sed 's/.*//')" "Ensure SSH uses key-based auth and is not exposed unnecessarily." ""
        fi
        
        if grep -qi "mysql\|3306/tcp\|postgresql\|5432/tcp\|mssql\|1433/tcp\|oracle\|1521/tcp" "$service_file" 2>/dev/null; then
            record_finding "HIGH" "Database Service Exposed" "A database service is exposed to the network. This is a significant security risk." "Restrict database access to trusted IPs only or move to private network." ""
        fi
        
        if grep -qi "redis\|6379/tcp\|mongodb\|27017/tcp\|elastic\|9200/tcp" "$service_file" 2>/dev/null; then
            record_finding "HIGH" "In-Memory Data Store Exposed" "An in-memory data store is exposed. Often these lack authentication." "Bind to localhost or require authentication." ""
        fi
        
        # Check for outdated software versions
        if grep -qi "Apache/2\.[0-4]\|nginx/1\.[0-9]\|PHP/5\." "$service_file" 2>/dev/null; then
            record_finding "HIGH" "Outdated Software Detected" "End-of-life software version found in service scan." "Upgrade to a supported version." ""
        fi
    fi
    
    # Summary
    local http_services=$(grep -cE "http|https|web" "$service_file" 2>/dev/null)
    log_ok "Port scan complete. $open_ports open ports, $http_services HTTP/HTTPS services."
    
    end_phase
}
