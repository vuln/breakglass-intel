#!/usr/bin/env python3
"""
Coruna DGA Domain Monitor — Breakglass Intelligence
https://intel.breakglass.tech

Monitors Certificate Transparency logs for new domains matching the Coruna/PLASMAGRID
DGA pattern: 15-character alphanumeric .xyz domains registered via Gname.com Singapore.

UNC6691 uses batch-registered DGA domains for C2 resolution. This tool watches for
new registrations matching the pattern before they're weaponized.

Usage:
    python3 coruna-dga-monitor.py                    # Run once, check last 24h
    python3 coruna-dga-monitor.py --continuous        # Poll every 10 minutes
    python3 coruna-dga-monitor.py --days 7            # Check last 7 days
    python3 coruna-dga-monitor.py --webhook URL       # Send alerts to webhook

Requirements:
    pip install requests

Author: Breakglass Intelligence (security@breakglass.tech)
License: MIT
Reference: https://intel.breakglass.tech/post/plasmagrid-coruna-ios-exploit-kit-unc6691-dga-law-enforcement-takedown
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# === CONFIGURATION ===

# Known Coruna DGA domains (for validation — if we see more like these, it's a match)
KNOWN_DGA_DOMAINS = {
    "aidm8it5hf1jmtj.xyz",
    "b3k9m2x7n4p1q8r.xyz",  # placeholder patterns
}

# Known Coruna registrar
CORUNA_REGISTRAR = "gname.com"

# DGA pattern: exactly 15 alphanumeric chars + .xyz
DGA_PATTERN = re.compile(r'^[a-z0-9]{15}\.xyz$')

# Gname.com nameserver patterns
GNAME_NS_PATTERNS = [
    "dns1.gname.com",
    "dns2.gname.com",
]

# === FUNCTIONS ===

def check_crtsh(days=1):
    """Query crt.sh for recently issued .xyz certificates."""
    print(f"[*] Querying crt.sh for .xyz certificates from last {days} day(s)...")

    # crt.sh doesn't support date filtering well, so we query recent and filter
    url = "https://crt.sh/?q=%.xyz&output=json"
    req = Request(url, headers={"User-Agent": "Coruna-DGA-Monitor/1.0 (Breakglass Intelligence)"})

    try:
        with urlopen(req, timeout=30) as resp:
            certs = json.loads(resp.read())
    except Exception as e:
        print(f"[!] crt.sh query failed: {e}")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    matches = []

    for cert in certs:
        cn = cert.get("common_name", "").lower().strip()
        not_before = cert.get("not_before", "")

        # Check if it matches the DGA pattern
        if not DGA_PATTERN.match(cn):
            continue

        # Check if cert was issued recently
        try:
            cert_date = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            if cert_date < cutoff:
                continue
        except (ValueError, TypeError):
            continue

        matches.append({
            "domain": cn,
            "issuer": cert.get("issuer_name", ""),
            "not_before": not_before,
            "not_after": cert.get("not_after", ""),
            "cert_id": cert.get("id"),
        })

    return matches


def check_whois_registrar(domain):
    """Check if a domain was registered via Gname.com."""
    import subprocess
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.lower()
        if "gname" in output:
            return True, "gname.com"
        # Extract registrar name
        for line in result.stdout.split("\n"):
            if "registrar:" in line.lower():
                return False, line.split(":", 1)[1].strip()
        return False, "unknown"
    except Exception:
        return False, "error"


def check_nameservers(domain):
    """Check if domain uses Gname.com nameservers."""
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", "NS", domain],
            capture_output=True, text=True, timeout=10
        )
        ns_records = result.stdout.strip().lower().split("\n")
        for ns in ns_records:
            if "gname" in ns:
                return True, ns_records
        return False, ns_records
    except Exception:
        return False, []


def resolve_domain(domain):
    """Check if domain resolves to an IP."""
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", "A", domain],
            capture_output=True, text=True, timeout=10
        )
        ips = [ip.strip() for ip in result.stdout.strip().split("\n") if ip.strip()]
        return ips
    except Exception:
        return []


def check_domain_status(domain):
    """Check registrar status (serverHold = seized)."""
    import subprocess
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        statuses = []
        for line in result.stdout.split("\n"):
            if "status:" in line.lower() or "domain status:" in line.lower():
                statuses.append(line.strip())
        return statuses
    except Exception:
        return []


def score_match(domain, is_gname, nameservers_match, resolves, statuses):
    """Score how likely this is a Coruna DGA domain."""
    score = 50  # Base score for matching the 15-char .xyz pattern

    if is_gname:
        score += 30  # Strong signal
    if nameservers_match:
        score += 10
    if resolves:
        score += 5  # Active domain
    if any("serverhold" in s.lower() for s in statuses):
        score += 5  # Seized = was malicious

    # Check for batch registration (if we see multiple in the same time window)
    # This would be checked externally

    return min(score, 100)


def send_webhook(url, data):
    """Send alert to a webhook (Slack, Discord, etc.)."""
    import json
    req = Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=10):
            pass
    except Exception as e:
        print(f"[!] Webhook failed: {e}")


def monitor_once(days=1, webhook=None):
    """Run one monitoring cycle."""
    print(f"\n{'='*60}")
    print(f"  Coruna DGA Monitor — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Checking last {days} day(s) for 15-char .xyz DGA domains")
    print(f"{'='*60}\n")

    matches = check_crtsh(days)

    if not matches:
        print("[+] No matching domains found in CT logs.")
        return []

    print(f"[!] Found {len(matches)} potential DGA domain(s):\n")

    alerts = []
    for m in matches:
        domain = m["domain"]
        print(f"  Domain: {domain}")
        print(f"  Cert issued: {m['not_before']}")

        # Deep checks
        is_gname, registrar = check_whois_registrar(domain)
        ns_match, ns_records = check_nameservers(domain)
        ips = resolve_domain(domain)
        statuses = check_domain_status(domain)

        print(f"  Registrar: {registrar} {'[GNAME MATCH]' if is_gname else ''}")
        print(f"  Nameservers: {', '.join(ns_records) if ns_records else 'none'} {'[GNAME NS]' if ns_match else ''}")
        print(f"  Resolves to: {', '.join(ips) if ips else 'no resolution (seized/parked?)'}")
        print(f"  Status: {'; '.join(statuses) if statuses else 'unknown'}")

        score = score_match(domain, is_gname, ns_match, bool(ips), statuses)
        confidence = "HIGH" if score >= 80 else "MEDIUM" if score >= 60 else "LOW"

        print(f"  Score: {score}/100 ({confidence} confidence Coruna DGA)")

        if domain in KNOWN_DGA_DOMAINS:
            print(f"  ** KNOWN Coruna DGA domain **")

        print()

        alert = {
            "domain": domain,
            "score": score,
            "confidence": confidence,
            "registrar": registrar,
            "is_gname": is_gname,
            "nameservers": ns_records,
            "ips": ips,
            "statuses": statuses,
            "cert_issued": m["not_before"],
            "cert_id": m["cert_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        alerts.append(alert)

        if webhook and score >= 60:
            send_webhook(webhook, {
                "text": f"🚨 Coruna DGA Alert ({confidence}): {domain} | Registrar: {registrar} | Score: {score}/100 | Resolves: {', '.join(ips) if ips else 'no'}"
            })

    # Summary
    high = sum(1 for a in alerts if a["confidence"] == "HIGH")
    medium = sum(1 for a in alerts if a["confidence"] == "MEDIUM")
    low = sum(1 for a in alerts if a["confidence"] == "LOW")
    print(f"Summary: {len(alerts)} total | {high} HIGH | {medium} MEDIUM | {low} LOW")

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Monitor for Coruna/PLASMAGRID DGA domains (15-char .xyz via Gname.com)",
        epilog="Breakglass Intelligence — https://intel.breakglass.tech"
    )
    parser.add_argument("--days", type=int, default=1, help="Check certificates from last N days (default: 1)")
    parser.add_argument("--continuous", action="store_true", help="Run continuously, polling every 10 minutes")
    parser.add_argument("--interval", type=int, default=600, help="Poll interval in seconds (default: 600)")
    parser.add_argument("--webhook", help="Webhook URL for alerts (Slack/Discord compatible)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.continuous:
        print(f"[*] Continuous monitoring mode (every {args.interval}s)")
        while True:
            try:
                alerts = monitor_once(days=args.days, webhook=args.webhook)
                if args.json and alerts:
                    print(json.dumps(alerts, indent=2))
            except KeyboardInterrupt:
                print("\n[*] Stopped.")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
            time.sleep(args.interval)
    else:
        alerts = monitor_once(days=args.days, webhook=args.webhook)
        if args.json:
            print(json.dumps(alerts, indent=2))
        sys.exit(0 if not alerts else 1)


if __name__ == "__main__":
    main()
