# Raithani-Scan

Advanced vulnerability scanner for Kali Linux — scans web targets for all OWASP Top 10, network-level issues, and advanced bug bounty vulnerabilities using custom payloads, WAF bypass, integrated Kali tools, and port exploitation.

## Installation

```bash
git clone <repo-url> Raithani-Scan
cd Raithani-Scan
chmod +x raithani-scan.sh
./raithani-scan.sh -h
```

**Dependencies** (auto-installed on first run with permission):  
`nmap`, `curl`, `openssl`, `whois`, `whatweb`, `dnsrecon`, `wafw00f`, `gobuster`, `dirb`, `sslscan`, `hydra`, `sqlmap`, `nikto`, `searchsploit`, `subfinder`, `sublist3r`, `assetfinder`, `amass`, `googler`, `ddgr`, `jq`

## Usage

```bash
./raithani-scan.sh -t <target-url> [options]
```

If `-t` is omitted, the tool enters interactive mode and prompts for the URL.

### Options

| Option | Description |
|--------|-------------|
| `-t <url>` | Target URL (e.g., `https://example.com`) |
| `-o <dir>` | Output directory (default: `output/<domain>_<timestamp>`) |
| `-l <1-3>` | Scan level: 1=quick, 2=standard, 3=exhaustive |
| `--quick` | Alias for `-l 1` (skip slow scans) |
| `--no-tools` | Custom HTTP checks only, skip external tools |
| `--exploit` | Enable port exploitation (FTP/SSH/SMTP/IMAP/DNS/MySQL/Postgres/Redis/MongoDB/Telnet) |
| `--bugbounty` | Enable bug bounty modules (enabled by default, use `--skip-bugbounty` to disable) |
| `--skip-2fa` | Skip 2FA bypass check phase |
| `--skip-bugbounty` | Skip bug bounty testing phase |
| `--skip <list>` | Skip phases by name or number (e.g. `--skip waf,recon,2fa`) |
| `--danger-mode` | Enable destructive payloads (DELETE, DROP, rm) |
| `--resume` | Resume from last checkpoint |
| `--ignore-robots` | Ignore `robots.txt` restrictions |
| `-h, --help` | Show help |

### Examples

```bash
# Basic scan (2FA bypass and bug bounty run by default)
./raithani-scan.sh -t https://example.com

# Full scan with all features
./raithani-scan.sh -t https://example.com -l 3 --exploit -o ~/results

# Skip specific phases by name
./raithani-scan.sh -t https://example.com --skip waf,recon,2fa,bugbounty

# Skip specific phases by number
./raithani-scan.sh -t https://example.com --skip 1,5,6

# Quick scan (custom HTTP checks only)
./raithani-scan.sh -t https://example.com --quick --no-tools

# Interactive mode
./raithani-scan.sh
```

## Scan Phases

The tool runs 10 sequential phases:

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | **WAF Detection** | WAF detection (wafw00f, nmap, header analysis), CDN fingerprinting, bypass engine |
| 2 | **Reconnaissance** | WHOIS, DNS records, technology fingerprinting (whatweb), SSL/TLS, subdomain discovery (dnsrecon, crt.sh, SSL SAN, favicon hash, subfinder/sublist3r/assetfinder/amass + 300+ wordlist), robots.txt, sitemap.xml |
| 3 | **Port Scanning** | nmap port discovery (1-10000), service version detection, OS detection, NSE scripts |
| 4 | **Web Enumeration** | Directory brute-force (gobuster/dirb), parameter fuzzing, URL spidering, sensitive file discovery, form enumeration, API fuzzing (endpoint discovery, HTTP method testing, rate limit testing) |
| 5 | **2FA Bypass Check** | 2FA endpoint discovery, OTP bypass (default codes, null values), rate limiting tests, response manipulation, session-based bypass |
| 6 | **Bug Bounty** | Subdomain takeover (34 cloud provider fingerprints), SAST/DAST (JS secrets, source maps, form auto-submit), cloud bucket enumeration, OAuth/SSO testing, origin IP discovery, HTTP smuggling, race conditions, Google dorking (50 queries, 7 categories) |
| 7 | **Vulnerability Checks** | SQLi, XSS, LFI/RFI, CMDi, SSRF, SSTI, XXE, Open Redirect, Security Headers, CORS, CSRF, IDOR, JWT, GraphQL |
| 8 | **Port Exploitation** | FTP (anonymous/default creds/hydra), SSH (banner/weak algos/hydra), SMTP (open relay/user enum), IMAP (default creds), DNS (zone transfer/recursion), MySQL/Postgres (default creds/hydra), Redis/MongoDB (no-auth), Telnet (default creds) |
| 9 | **Tool Integration** | sqlmap deep SQLi, nikto web server audit, searchsploit CVE lookup, nmap NSE vulnerability scripts |
| 10 | **Reporting** | Terminal summary, HTML report, JSON report, CSV report |

## Payload System

- **954 base payloads** across 8 categories (SQli, XSS, LFI, CMDi, SSRF, SSTI, XXE, Open Redirect, directories)
- **~5,913 total variants** via Python obfuscation engine (`payloads/generator.py`)
- **4 WAF bypass technique files** (CloudFlare, ModSecurity, AWS WAF, generic)
- **Custom evasion**: encoding, case mutations, comment injection, parameter pollution, unicode normalization

## Output

Results are saved to `output/<domain>_<timestamp>/`:
```
output/
  <domain>_<timestamp>/
    evidence/         # Proof files for findings
    reports/          # Generated reports
    recon/            # Reconnaissance data
    port_scan/        # Port scan results
    web_enum/         # Web enumeration results
    vuln_checks/      # Vulnerability check results
    exploitation/     # Port exploitation evidence
    bugbounty/        # Bug bounty module results
    tool_integration/ # External tool results
    .checkpoint       # Resume checkpoint (auto)
```

Reports are available in:
- Terminal (colored summary with severity counts)
- HTML (formatted table)
- JSON (machine-readable)
- CSV (spreadsheet-compatible)

## Configuration

Edit `config/default.conf` to customize:
- Scan timing, concurrency, timeouts
- Which vulnerability checks to run
- WAF bypass intensity
- Port scanning range and timing
- Bug bounty module toggles
- Safety limits (max URLs, danger mode)

## Project Structure

```
Raithani-Scan/
  raithani-scan.sh       # Main orchestrator
  config/
    default.conf         # Configuration file
  lib/
    common.sh            # Colors, logging, args, HTTP helper, progress dashboard
    waf-bypass.sh        # WAF detection + CDN fingerprinting + bypass engine
    recon.sh             # Reconnaissance (DNS, SSL, subdomains, tech detection)
    port-scan.sh         # Port scanning with nmap
    exploit-ports.sh     # Port exploitation (FTP, SSH, SMTP, etc.)
    web-enum.sh          # Web enumeration + API fuzzing
    vuln-engine.sh       # Vulnerability engine (SQLi, XSS, JWT, GraphQL, etc.)
    bugbounty.sh         # Bug bounty modules (takeover, smuggling, dorking, etc.)
    tool-integration.sh  # External tool wrappers (sqlmap, nikto, etc.)
    report.sh            # Report generation (terminal, HTML, JSON, CSV)
  payloads/
    generator.py         # Python payload obfuscation engine
    sqli.txt             # SQL injection payloads
    xss.txt              # XSS payloads (+6 more .txt files)
    cloudflare.txt       # WAF bypass techniques
    ...
```

## Notes

- Requires Kali Linux (tested) or Debian-based distro with `apt`
- 2FA bypass and bug bounty modules run by default; use `--skip-2fa` or `--skip bugbounty` to disable them
- Port exploitation (`--exploit`) is opt-in; it adds time and noise
- Some features need root (SYN scan, raw sockets) — auto-sudo prompts are handled
- External tools (sqlmap, nikto, etc.) are auto-installed if missing (with permission)
- The tool does NOT actively exploit confirmed vulnerabilities — it reports findings for manual verification
