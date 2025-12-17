#!/usr/bin/env python3

"""
This tool is intentionally conservative and respects legal/ethical boundaries.
Do not use it to probe systems you don't have permission to investigate.
"""

import argparse
import ipaddress
import socket
import sys
import json
import datetime
import time
import re
from pprint import pformat

try:
    import requests
except Exception:
    requests = None

VERSION = "1.0"

CLOUD_INDICATORS = {
    'aws': [r'cloudfront', r'amazonaws', r's3.amazonaws', r'aws-pay', r's3-website'],
    'azure': [r'azureedge', r'windows.net', r'azurewebsites.net', r'blob.core.windows.net'],
    'gcp': [r'googleapis', r'storage.googleapis.com', r'appspot.com', r'googlesyndication', r'youtube', r'withgoogle', r'esf'],
    'cloudflare': [r'cloudflare', r'cf-ray', r'cdn-cgi'],
    'fastly': [r'fastly', r'ssl.fastly', r'f.fastly'],
    'akamai': [r'akamai', r'noc.akamai', r'akamaiedge'],
    'digitalocean': [r'digitaloceanspaces', r'digitalocean'],
}

BUCKET_PATTERNS = [
    'https://{bucket}.s3.amazonaws.com/',
    'https://s3.amazonaws.com/{bucket}/',
    'http://{bucket}.s3-website-{region}.amazonaws.com/',
    'https://{bucket}.blob.core.windows.net/',
    'https://storage.googleapis.com/{bucket}/',
    'https://{bucket}.storage.googleapis.com/',
]

HTML_TMPL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud Footprint Report - {target}</title>
<style>body{{font-family:Arial,Helvetica,sans-serif;background:#f6f8fb;color:#111;margin:20px}}.card{{background:#fff;padding:16px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.08);margin-bottom:12px}}h1{{margin:0}}pre{{white-space:pre-wrap;background:#f4f6f8;padding:10px;border-radius:6px}}</style>
</head>
<body>
<h1>Cloud Footprint Report</h1>
<div class="muted">Generated: {generated}</div>
<div class="card"><h2>Target</h2><div><strong>{target}</strong></div><div class="muted">Resolved IPs: {ips}</div></div>
<div class="card"><h2>DNS</h2><pre>{dns}</pre></div>
<div class="card"><h2>Reverse DNS</h2><pre>{rdns}</pre></div>
<div class="card"><h2>HTTP / TLS</h2><pre>{http}</pre></div>
<div class="card"><h2>Cloud / CDN Indicators</h2><pre>{indicators}</pre></div>
<div class="card"><h2>IP Owner / ASN</h2><pre>{ipowner}</pre></div>
<div class="card"><h2>Public Storage Checks (bucket fingerprints)</h2><pre>{buckets}</pre></div>
<div class="card"><h2>Notes & Recommendations</h2><ul>{notes}</ul></div>
</body>
</html>"""


# ===== helpers =====
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*'
    r'\.[A-Za-z]{2,63}$'
)

def validate_target(value: str) -> bool:
    value = value.strip()

    if DOMAIN_RE.match(value):
        return True

    return False

def resolve_dns(target):
    out = {'A': [], 'AAAA': [], 'CNAME': [], 'error': None}
    try:
        try:
            infos = socket.getaddrinfo(target, None)
            ips = sorted({i[4][0] for i in infos})
            out['A'] = ips
        except Exception:
            out['A'] = []
        try:
            hn, aliases, addrs = socket.gethostbyname_ex(target)
            out['CNAME'] = aliases
        except Exception:
            out['CNAME'] = []
    except Exception as e:
        out['error'] = str(e)
    return out

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)
    except Exception as e:
        return (None, [], str(e))

def fetch_http(url, timeout=8):
    res = {'ok': False, 'status': None, 'headers': None, 'text': None, 'error': None}
    if not requests:
        res['error'] = 'requests not installed'
        return res
    try:
        r = requests.get(url, timeout=timeout, headers={'User-Agent':'Secuditor-CloudFootprint/1.0'})
        res['status'] = r.status_code
        res['headers'] = dict(r.headers)
        text = r.text or ''
        res['text'] = text[:20000]
        res['ok'] = True
    except Exception as e:
        res['error'] = str(e)
    return res

def probe_https(host):
    url = f'https://{host}/'
    return fetch_http(url)

def ip_owner_info(ip):
    out = {'ok': False, 'data': None, 'error': None}
    if not requests:
        out['error'] = 'requests not installed'
        return out
    services = [f'https://ip-api.com/json/{ip}', f'https://ipinfo.io/{ip}/json']
    for s in services:
        try:
            r = requests.get(s, timeout=6, headers={'User-Agent':'Secuditor-CloudFootprint/1.0'})
            if r.status_code == 200:
                out['data'] = r.json()
                out['ok'] = True
                return out
        except Exception:
            continue
    out['error'] = 'failed to query ip owner services'
    return out

def analyze_indicators(http_resps):
    findings = {}
    for host, res in http_resps.items():
        if not res or not res.get('ok'):
            continue
        headers = res.get('headers') or {}
        text = (res.get('text') or '').lower()

        # Combine headers and body for pattern matching
        combined = ' '.join(k.lower() + ' ' + str(v).lower() for k, v in headers.items()) + ' ' + text

        for provider, patterns in CLOUD_INDICATORS.items():
            for p in patterns:
                if re.search(p, combined):
                    findings.setdefault(provider, []).append(host)
                    break  # Only count one hit per host per provider
    return findings

def check_bucket_patterns(domain, ip):
    results = []
    parts = domain.split('.')
    candidate_buckets = [domain, parts[0]]
    candidate_buckets += [f"{parts[0]}-{parts[1]}" if len(parts) > 1 else parts[0]]
    candidate_buckets = list(dict.fromkeys(candidate_buckets))

    for b in candidate_buckets:
        for patt in BUCKET_PATTERNS:
            url = patt.format(bucket=b, region='')
            r = {'url': url, 'ok': False, 'status': None, 'note': ''}
            if requests:
                try:
                    h = requests.head(url, timeout=5, allow_redirects=True,
                                      headers={'User-Agent':'Secuditor-CloudFootprint/1.0'})
                    r['status'] = h.status_code
                    if h.status_code in (200, 301, 302, 403, 404):
                        r['ok'] = True
                        r['note'] = 'reachable'
                except Exception as e:
                    r['note'] = f'Error: {str(e)}'
            else:
                r['note'] = 'requests not installed'
            results.append(r)
    return results

def risk_notes(indicators, buckets, ipowner):
    notes = []

    # --- Cloud / CDN indicators ---
    if indicators:
        for provider, hits in indicators.items():
            # safely extract hosts
            hosts_list = []
            for h in hits:
                if isinstance(h, dict) and 'host' in h:
                    hosts_list.append(h['host'])
                elif isinstance(h, str):
                    hosts_list.append(h)
            hosts = ', '.join(sorted(set(hosts_list)))
            notes.append(
                f'Detected possible presence of {provider} services or CDN '
                f'(hosts: {hosts}; {len(hits)} fingerprint hits)'
            )
    else:
        notes.append(
            'No obvious cloud or CDN indicators were detected from HTTP headers or response body'
        )

    # --- Public storage / bucket patterns ---
    if buckets:
        reachable = [b for b in buckets if b.get('ok') and b.get('status')]
        if reachable:
            examples = ', '.join([b['url'] for b in reachable[:5]])
            notes.append(
                f'Potential public storage endpoints responded: {len(reachable)} '
                f'(examples: {examples}; manual verification recommended)'
            )
    else:
        notes.append(
            'Public storage checks were not performed or returned no results'
        )

    # --- IP owner / ASN ---
    if ipowner and ipowner.get('ok') and ipowner.get('data'):
        data = ipowner['data']
        org = (
            data.get('org')
            or data.get('organization')
            or data.get('company')
            or 'Unknown organization'
        )
        notes.append(f'IP owner / ASN organization identified as: {org}')
    else:
        notes.append(
            'IP owner / ASN information could not be reliably determined '
            '(blocked, rate-limited, or unavailable)'
        )

    return notes

def render_report(outpath, target, dns, rdns, http_resps, indicators, ipowner, buckets, notes):
    import datetime
    from pprint import pformat

    # generate timestamp for report
    generated_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    generated_fname = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # if the output path includes {generated}, replace it
    if '{generated}' in outpath:
        outpath = outpath.replace('{generated}', generated_fname)
    else:
        outpath = outpath.replace('.html', f'_{generated_fname}.html')

    ips = ', '.join(dns.get('A') or []) or '-'

    # Format rdns for readable output
    rdns_display = [f"{r['ip']} → {r['rdns']}" for r in rdns]

    # Clean up HTTP response text for readability
    http_cleaned = {}
    for host, resp in http_resps.items():
        text_snippet = None
        if resp.get('text'):
            # take first 200 chars, remove excessive whitespace
            text_snippet = ' '.join(resp['text'].split())[:200]
        http_cleaned[host] = {
            'ok': resp.get('ok'),
            'status': resp.get('status'),
            'headers': resp.get('headers'),
            'text': text_snippet,
            'error': resp.get('error')
        }

    # --- Process buckets with inline notes/errors ---
    if buckets:
        bucket_lines = []
        for b in buckets:
            status = b.get('status') if b.get('status') is not None else 'N/A'
            note = b.get('note') or ''
            ok = '✓' if b.get('ok') else '✗'
            bucket_lines.append(f"{ok} {b['url']} (status: {status}) {note}")
        buckets_display = '\n'.join(bucket_lines)
    else:
        buckets_display = 'No public storage fingerprints responded'

    html = HTML_TMPL.format(
        target=target,
        generated=generated_iso,
        ips=ips,
        dns=pformat(dns),
        rdns='\n'.join(rdns_display),
        http=pformat(http_cleaned) if http_cleaned else 'No HTTP/TLS data collected',
        indicators=pformat(indicators) if indicators else 'No cloud or CDN fingerprints detected',
        ipowner=pformat(ipowner) if ipowner else 'IP owner / ASN lookup unavailable',
        buckets=buckets_display,
        notes='\n'.join(f'<li>{n}</li>' for n in notes)
    )

    with open(outpath, 'w', encoding='utf-8') as f:
        f.write(html)
    return outpath


# ====== main =====
def main():
    import argparse, re, time

    print("This tool is only for ethical and legal use.\n")
    p = argparse.ArgumentParser(description='Cloud Footprint Detector')
    p.add_argument('--target', help='Domain or IP to analyze (external footprint only)')
    p.add_argument('--out', default='cloud_footprint_report{generated}.html', help='HTML output path (can include {generated})')
    p.add_argument('--no-http', action='store_true', help='Skip HTTP probes')
    p.add_argument('--no-buckets', action='store_true', help='Skip public bucket pattern checks')
    args = p.parse_args()

    try:
        # --- Get target ---
        while True:
            tgt = input("Enter a domain (example.com): ").strip()

            if validate_target(tgt):
                print(f"[+] Valid target: {tgt}")
                break

            print("Invalid input.\n")
            continue

        # --- DNS resolution ---
        dns = resolve_dns(tgt) if not re.match(r'^\d+\.\d+\.\d+\.\d+$', tgt) else {'A': [tgt]}

        # --- Reverse DNS ---
        rdns = []
        for ip in dns.get('A', [])[:4]:
            try:
                rd = reverse_dns(ip)
                rdns.append({'ip': ip, 'rdns': rd[0] if rd and rd[0] else 'No PTR record found'})
            except Exception as e:
                rdns.append({'ip': ip, 'rdns': f'Error: {str(e)}'})

        # --- HTTP probes ---
        http_resps = {}
        if not args.no_http:
            print(f'[+] Probing https://{tgt} ...')
            http_resps[tgt] = probe_https(tgt)
            time.sleep(0.5)

        print('[+] Analyzing indicators...')
        indicators = analyze_indicators(http_resps)

        # --- IP owner ---
        ipowner = None
        if dns.get('A'):
            primary_ip = dns['A'][0]
            print(f'[+] Querying IP owner for {primary_ip} ...')
            ipowner = ip_owner_info(primary_ip)

        # --- Bucket patterns ---
        buckets = []
        if not args.no_buckets:
            print('[+] Checking common storage URL patterns (best-effort) ...')
            buckets = check_bucket_patterns(tgt, dns.get('A', []))

        notes = risk_notes(indicators, buckets, ipowner)
        if not indicators and not buckets and not (ipowner and ipowner.get('ok') and ipowner.get('data')):
            notes.append('No observable cloud/CDN, ASN, or public storage fingerprints detected. Target may be hardened or intentionally silent.')

        out = render_report(args.out, tgt, dns, rdns, http_resps, indicators, ipowner, buckets, notes)
        print(f'[+] Report written to: {out}')

    except KeyboardInterrupt:
        print('\n[!] User aborted. Exiting.')
        sys.exit(0)

    input("\nPress Enter to exit...")

if __name__ == '__main__':
    main()

