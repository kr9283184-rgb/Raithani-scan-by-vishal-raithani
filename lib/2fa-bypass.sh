#!/bin/bash
# =============================================================================
# Raithani-Scan - 2FA Bypass Check Phase
# Tests for two-factor authentication bypass vulnerabilities
# =============================================================================

run_2fa_bypass() {
    start_phase "2FA Bypass Check"

    local target_url="$1"
    local output="$2"
    local bypass_output="$output/2fa_bypass"
    mkdir -p "$bypass_output"

    local intensity="${TWOFA_BYPASS_INTENSITY:-medium}"
    local otp_attempts="${TWOFA_OTP_ATTEMPTS:-10}"
    local findings_before=${#FINDINGS[@]}

    # 1. Discover 2FA endpoints
    log_step "Discovering 2FA endpoints..."
    local endpoints=()
    local auth_paths=(
        "/login" "/signin" "/auth" "/2fa" "/mfa" "/verify"
        "/otp" "/totp" "/two-factor" "/authenticate"
        "/login/2fa" "/auth/verify" "/api/2fa" "/api/verify-otp"
    )
    local found_endpoints=0
    for path in "${auth_paths[@]}"; do
        local resp=$(http_request "${target_url}${path}" "GET" "" "text/html")
        if [[ -n "$resp" ]]; then
            local http_code=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "${target_url}${path}" 2>/dev/null)
            if [[ "$http_code" != "404" ]] && [[ "$http_code" != "000" ]]; then
                endpoints+=("${target_url}${path}")
                log_ok "Found 2FA endpoint: ${path} (HTTP $http_code)"
                ((found_endpoints++))
            fi
        fi
    done

    if [[ ${#endpoints[@]} -eq 0 ]]; then
        log_info "No 2FA endpoints discovered"
        end_phase
        return 0
    fi
    echo "$found_endpoints" > "$bypass_output/endpoints.txt"

    # 2. Detect 2FA type on each endpoint
    log_step "Identifying 2FA mechanisms..."
    for ep in "${endpoints[@]}"; do
        detect_2fa_type "$ep" "$bypass_output"
    done

    # 3. OTP bypass tests
    log_step "Testing OTP bypass techniques..."
    for ep in "${endpoints[@]}"; do
        test_otp_bypass "$ep" "$bypass_output" "$otp_attempts"
    done

    # 4. Rate limiting tests
    if [[ "$TWOFA_RATE_LIMIT_CHECK" == "true" ]] || [[ -z "$TWOFA_RATE_LIMIT_CHECK" ]]; then
        log_step "Testing rate limiting on 2FA endpoints..."
        for ep in "${endpoints[@]}"; do
            test_rate_limiting "$ep" "$bypass_output" "$otp_attempts"
        done
    fi

    # 5. Response manipulation tests
    if [[ "$intensity" == "high" ]]; then
        log_step "Testing response manipulation bypasses..."
        for ep in "${endpoints[@]}"; do
            test_response_manipulation "$ep" "$bypass_output"
        done
    fi

    # 6. Session/Cookie based bypass
    log_step "Testing session-based 2FA bypass..."
    test_session_bypass "$target_url" "$bypass_output"

    local new_findings=$(( ${#FINDINGS[@]} - findings_before ))
    log_ok "2FA bypass checks complete ($new_findings findings)"
    end_phase
}

detect_2fa_type() {
    local endpoint="$1"
    local output="$2"

    local resp=$(http_request "$endpoint" "GET")
    if [[ -z "$resp" ]]; then
        return
    fi

    local detection_file="$output/detected_2fa.txt"

    if echo "$resp" | grep -qi "google-authenticator\|totp\|time-based\|authenticator app" 2>/dev/null; then
        echo "TOTP|$endpoint" >> "$detection_file"
        log_ok "TOTP-based 2FA detected at $endpoint"
    fi

    if echo "$resp" | grep -qi "sms\|phone\|text message\|\+[0-9]" 2>/dev/null; then
        echo "SMS|$endpoint" >> "$detection_file"
        log_ok "SMS-based 2FA detected at $endpoint"
    fi

    if echo "$resp" | grep -qi "email.*code\|email.*otp\|check.*email" 2>/dev/null; then
        echo "EMAIL|$endpoint" >> "$detection_file"
        log_ok "Email-based 2FA detected at $endpoint"
    fi

    if echo "$resp" | grep -qi "security question\|secret question\|backup code\|recovery code" 2>/dev/null; then
        echo "BACKUP|$endpoint" >> "$detection_file"
        log_ok "Backup/recovery code based 2FA detected at $endpoint"
    fi

    if ! [[ -s "$detection_file" ]]; then
        echo "UNKNOWN|$endpoint" >> "$detection_file"
        log_info "2FA mechanism at $endpoint could not be identified"
    fi
}

test_otp_bypass() {
    local endpoint="$1"
    local output="$2"
    local attempts="${3:-10}"

    local bypass_file="$output/otp_bypass.txt"

    local bypass_payloads=(
        "otp=" "code=" "token=" "2fa_code="
        "otp=000000" "code=000000" "code=0" "otp=null"
        "otp[]=" "code[]=" "token[]="
        "otp=999999" "code=999999"
    )

    for payload in "${bypass_payloads[@]}"; do
        local resp=$(http_request "$endpoint" "POST" "$payload" "application/x-www-form-urlencoded")
        local http_code=$(curl -s -k -o /dev/null -w "%{http_code}" -X POST --data "$payload" -H "Content-Type: application/x-www-form-urlencoded" --max-time "$TIMEOUT" "$endpoint" 2>/dev/null)

        if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]] || [[ "$http_code" == "301" ]]; then
            local body_check=$(curl -s -k -X POST --data "$payload" -H "Content-Type: application/x-www-form-urlencoded" --max-time "$TIMEOUT" "$endpoint" 2>/dev/null)
            if ! echo "$body_check" | grep -qi "invalid code\|wrong code\|incorrect\|invalid otp\|expired\|error" 2>/dev/null; then
                echo "POTENTIAL_BYPASS|$payload|HTTP $http_code" >> "$bypass_file"
                log_warn "Potential OTP bypass with payload: $payload (HTTP $http_code)"
                record_finding "HIGH" "2FA OTP Bypass" \
                    "2FA endpoint $endpoint may be bypassable using payload: $payload (HTTP $http_code)" \
                    "Ensure OTP validation is performed server-side. Validate all input. Implement strict rate limiting."
            fi
        fi
    done

    local null_bytes=("%00" "%0d%0a" "null" "undefined" "NaN")
    for nb in "${null_bytes[@]}"; do
        local payload="otp=$nb"
        local resp=$(http_request "$endpoint" "POST" "$payload" "application/x-www-form-urlencoded")
        local http_code=$(curl -s -k -o /dev/null -w "%{http_code}" -X POST --data "$payload" -H "Content-Type: application/x-www-form-urlencoded" --max-time "$TIMEOUT" "$endpoint" 2>/dev/null)

        if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
            local body_check=$(curl -s -k -X POST --data "$payload" -H "Content-Type: application/x-www-form-urlencoded" --max-time "$TIMEOUT" "$endpoint" 2>/dev/null)
            if ! echo "$body_check" | grep -qi "invalid\|wrong\|incorrect\|error" 2>/dev/null; then
                echo "NULL_BYPASS|$nb|HTTP $http_code" >> "$bypass_file"
                log_warn "Potential null value OTP bypass: $nb"
                record_finding "HIGH" "2FA Null/Empty OTP Bypass" \
                    "2FA endpoint $endpoint accepts null/empty OTP value: $nb" \
                    "Reject null and empty values for OTP fields. Validate server-side."
            fi
        fi
    done
}

test_rate_limiting() {
    local endpoint="$1"
    local output="$2"
    local attempts="${3:-10}"

    local rate_file="$output/rate_limiting.txt"
    local start_time=$(date +%s)
    local success_count=0
    local status_codes=()

    for ((i=0; i<attempts; i++)); do
        local data="otp=$((RANDOM % 1000000))"
        local http_code=$(curl -s -k -o /dev/null -w "%{http_code}" -X POST --data "$data" -H "Content-Type: application/x-www-form-urlencoded" --max-time 3 "$endpoint" 2>/dev/null)
        status_codes+=("$http_code")
        if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
            ((success_count++))
        fi
        sleep 0.1
    done
    local elapsed=$(( $(date +%s) - start_time ))

    local unique_codes=$(printf '%s\n' "${status_codes[@]}" | sort -u | wc -l)

    if [[ "$success_count" -gt 3 ]]; then
        echo "RATE_LIMIT_WEAK|$attempts requests in ${elapsed}s|$success_count successful" >> "$rate_file"
        log_warn "Weak or no rate limiting on $endpoint ($success_count/$attempts requests succeeded)"
        record_finding "MEDIUM" "Weak 2FA Rate Limiting" \
            "2FA endpoint $endpoint allowed $success_count/$attempts OTP attempts in ${elapsed}s without lockout" \
            "Implement rate limiting with account lockout after 3-5 failed attempts. Add progressive delays."
    else
        log_ok "Rate limiting appears active on $endpoint"
        echo "RATE_LIMIT_OK|$success_count/$attempts succeeded" >> "$rate_file"
    fi
}

test_response_manipulation() {
    local endpoint="$1"
    local output="$2"

    local manip_file="$output/response_manipulation.txt"

    local manipulate_headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
        "X-Originating-IP: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Host: localhost"
        "X-Forwarded-Host: localhost"
    )

    for header in "${manipulate_headers[@]}"; do
        local resp=$(curl -s -k -L --max-time "$TIMEOUT" -H "$header" -X POST --data "otp=000000" -H "Content-Type: application/x-www-form-urlencoded" "$endpoint" 2>/dev/null)
        local http_code=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" -H "$header" -X POST --data "otp=000000" -H "Content-Type: application/x-www-form-urlencoded" "$endpoint" 2>/dev/null)

        if [[ "$http_code" == "302" ]] || [[ "$http_code" == "301" ]]; then
            local redirect=$(curl -s -k -o /dev/null -w "%{redirect_url}" --max-time "$TIMEOUT" -H "$header" -X POST --data "otp=000000" -H "Content-Type: application/x-www-form-urlencoded" "$endpoint" 2>/dev/null)
            if ! echo "$redirect" | grep -qi "login\|signin\|auth\|2fa\|mfa" 2>/dev/null; then
                echo "HEADER_BYPASS|$header|Redirect: $redirect" >> "$manip_file"
                log_warn "Potential 2FA bypass via header: ${header%%:*}"
                record_finding "HIGH" "2FA Header Manipulation Bypass" \
                    "2FA bypass possible on $endpoint by injecting header: ${header%%:*} (redirected to $redirect)" \
                    "Do not trust client-side headers for 2FA validation. Validate server-side session."
            fi
        fi
    done
}

test_session_bypass() {
    local target_url="$1"
    local output="$2"

    local session_file="$output/session_bypass.txt"

    local initial_cookie=$(curl -s -k -c - --max-time "$TIMEOUT" "$target_url/login" 2>/dev/null | grep -oP '^\S+\s+\S+' | head -1)
    if [[ -z "$initial_cookie" ]]; then
        local cookie_jar=$(mktemp)
        curl -s -k -c "$cookie_jar" --max-time "$TIMEOUT" "$target_url/login" > /dev/null 2>&1
        local session_cookie=$(grep -v "^#" "$cookie_jar" 2>/dev/null | head -1 | awk '{print $NF}')
        rm -f "$cookie_jar"

        if [[ -n "$session_cookie" ]]; then
            local protected_resp=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" -b "$session_cookie" "$target_url/dashboard" 2>/dev/null)
            if [[ "$protected_resp" == "200" ]]; then
                log_warn "Session cookie alone grants access to protected resources without 2FA"
                echo "SESSION_BYPASS|Session: $session_cookie|Dashboard: HTTP $protected_resp" >> "$session_file"
                record_finding "CRITICAL" "2FA Session Bypass" \
                    "Session cookie alone authenticates user at $target_url/dashboard without 2FA verification" \
                    "Ensure 2FA verification is stored as a separate session flag. Re-verify 2FA status on each sensitive request."
            fi
        fi
    fi
}
