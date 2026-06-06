#!/usr/bin/env python3
"""
Raithani-Scan Payload Generator & Obfuscator
Generates multiple bypass variants for each base payload to evade WAF detection.

Usage:
    python3 generator.py <vuln-type> [--base-payload <payload>] [--list]
    
    <vuln-type>: sqli, xss, lfi, cmdi, ssti, ssrf, xxe, open-redirect
    --base-payload: optional single payload to generate variants for
    --list: list all payloads for a vuln type (no generation)
    --count: count total generated payloads for a vuln type
"""

import sys
import os
import base64
import urllib.parse
import random
import json

VULN_TYPES = ['sqli', 'xss', 'lfi', 'cmdi', 'ssti', 'ssrf', 'xxe', 'open-redirect']

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

BYPASS_TRANSFORMS = [
    'url_encode',
    'double_url_encode', 
    'hex_encode',
    'mixed_case',
    'comment_injection',
    'null_byte',
    'html_entity',
    'unicode_alt',
    'whitespace_mutation',
    'utf16_encode',
    'base64_wrap',
    'smart_padding',
]

def load_base_payloads(vuln_type):
    """Load base payloads from the text file."""
    filepath = os.path.join(PAYLOAD_DIR, f'{vuln_type}.txt')
    if not os.path.exists(filepath):
        print(f"Error: Payload file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def url_encode(payload):
    """Single URL encode special characters."""
    return urllib.parse.quote(payload, safe='')


def double_url_encode(payload):
    """Double URL encode the payload."""
    once = urllib.parse.quote(payload, safe='')
    return urllib.parse.quote(once, safe='')


def hex_encode(payload):
    """Convert payload to hex representation."""
    return '0x' + payload.encode().hex()


def mixed_case(payload):
    """Randomly change case of letters."""
    result = []
    for c in payload:
        if c.isalpha():
            result.append(c.upper() if random.random() > 0.5 else c.lower())
        else:
            result.append(c)
    return ''.join(result)


def comment_injection(payload, style='sql'):
    """Inject comments between keywords."""
    if style == 'sql':
        keywords = [" OR ", " AND ", " UNION ", " SELECT ", " SLEEP ", " BENCHMARK ",
                    " WHERE ", " FROM ", " INTO ", " ORDER ", " GROUP ",
                    "or ", "and ", "union ", "select ", "sleep ", "benchmark ",
                    "where ", "from ", "into ", "order ", "group "]
    else:
        keywords = []

    result = payload
    for kw in sorted(keywords, key=len, reverse=True):
        if kw in result:
            parts = result.split(kw)
            if len(parts) > 1:
                comment = '/**/'
                result = result.replace(kw, f'{comment}{kw.strip()}{comment}', 1)
                break

    return result


def null_byte(payload):
    """Append null byte to payload."""
    return payload + '%00'


def html_entity(payload):
    """Encode special chars as HTML entities."""
    result = ''
    for c in payload:
        if c in "'\"<>":
            result += f'&#x{ord(c):02x};'
        else:
            result += c
    return result


def unicode_alt(payload):
    """Use alternate Unicode representations."""
    replacements = {
        "'": '\uff07',
        '"': '\uff02',
        '<': '\uff1c',
        '>': '\uff1e',
        '(': '\uff08',
        ')': '\uff09',
        '.': '\uff0e',
        '/': '\uff0f',
        '=': '\uff1d',
        ' ': '\u3000',
    }
    result = ''
    for c in payload:
        result += replacements.get(c, c)
    return result


def whitespace_mutation(payload):
    """Replace spaces with various whitespace chars."""
    whitespace_chars = ['%09', '%0a', '%0c', '%0d', '%20', '%0b', '%a0']
    result = ''
    for c in payload:
        if c == ' ':
            result += random.choice(whitespace_chars)
        else:
            result += c
    return result


def utf16_encode(payload):
    """UTF-16LE encode the payload."""
    encoded = payload.encode('utf-16-le')
    return ''.join(f'%{b:02x}' for b in encoded)


def base64_wrap(payload):
    """Base64 encode and wrap for command execution."""
    b64 = base64.b64encode(payload.encode()).decode()
    if random.choice([True, False]):
        return f'echo {b64} | base64 -d | sh'
    else:
        return f'echo {b64} | base64 --decode | bash'


def smart_padding(payload):
    """Add benign-looking padding around sensitive parts."""
    pads = ['/**/', '/*!*/', '%20', '+']
    idx = len(payload) // 2
    pad = random.choice(pads)
    return payload[:idx] + pad + payload[idx:]


def generate_variants(payload, vuln_type):
    """Generate all bypass variants for a single payload."""
    variants = set()
    variants.add(payload)

    # URL encode
    try:
        variants.add(url_encode(payload))
    except:
        pass

    # Double URL encode
    try:
        variants.add(double_url_encode(payload))
    except:
        pass

    # Mixed case (multiple runs for variety)
    if vuln_type in ['sqli', 'xss']:
        for _ in range(3):
            try:
                variants.add(mixed_case(payload))
            except:
                pass

    # Comment injection (SQL specific)
    if vuln_type == 'sqli':
        try:
            variants.add(comment_injection(payload, 'sql'))
        except:
            pass

    # Null byte
    try:
        variants.add(null_byte(payload))
    except:
        pass

    # HTML entity
    try:
        variants.add(html_entity(payload))
    except:
        pass

    # Whitespace mutation
    try:
        variants.add(whitespace_mutation(payload))
    except:
        pass

    # Unicode alt (for XSS)
    if vuln_type in ['xss', 'sqli']:
        try:
            variants.add(unicode_alt(payload))
        except:
            pass

    # Smart padding
    try:
        variants.add(smart_padding(payload))
    except:
        pass

    # For cmd injection, add base64 variants
    if vuln_type == 'cmdi' and len(payload) < 50:
        try:
            variants.add(base64_wrap(payload))
        except:
            pass

    return list(variants)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    vuln_type = sys.argv[1]
    if vuln_type not in VULN_TYPES:
        print(f"Error: Unknown vuln type '{vuln_type}'. Choose from: {', '.join(VULN_TYPES)}")
        sys.exit(1)

    # Handle --list flag
    if '--list' in sys.argv:
        payloads = load_base_payloads(vuln_type)
        for p in payloads:
            print(p)
        return

    # Handle --count flag
    if '--count' in sys.argv:
        payloads = load_base_payloads(vuln_type)
        total = 0
        for p in payloads:
            total += len(generate_variants(p, vuln_type))
        print(f"{vuln_type}: {len(payloads)} base payloads -> ~{total} generated variants")
        return

    # Handle specific base payload
    if '--base-payload' in sys.argv:
        idx = sys.argv.index('--base-payload')
        if idx + 1 < len(sys.argv):
            payload = sys.argv[idx + 1]
            variants = generate_variants(payload, vuln_type)
            for v in variants:
                print(v)
            return

    # Default: generate all variants for all payloads
    payloads = load_base_payloads(vuln_type)
    all_variants = []
    for p in payloads:
        all_variants.extend(generate_variants(p, vuln_type))

    print(json.dumps(all_variants))


if __name__ == '__main__':
    main()
