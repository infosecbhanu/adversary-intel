"""
ASN and hosting provider clustering.

Adversary infrastructure clusters in specific ASNs offering crypto payment,
minimal abuse response, and favorable jurisdictions. This module identifies
the ASN for an IP, flags known bulletproof hosting, and groups discovered
IPs by ASN to reveal operator hosting preferences.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Optional

import requests

from adversary_intel.config import settings
from adversary_intel.models import ASNInfo

# Known bulletproof / high-abuse ASNs (community-maintained subset)
# Source: Spamhaus ASN-DROP, Recorded Future TAE research, community intel
BULLETPROOF_ASNS: dict[str, str] = {
    "AS209588": "Flyservers S.A. (bulletproof, Eastern Europe)",
    "AS48721":  "Flyservers S.A. (alt)",
    "AS44477":  "Stark Industries Solutions Ltd (bulletproof)",
    "AS47896":  "Serverius (frequently abused)",
    "AS202425": "IP Volume Inc (bulletproof)",
    "AS9009":   "M247 Ltd (frequently abused)",
    "AS59711":  "HZ Hosting Ltd",
    "AS174":    "Cogent (frequently abused transit)",
    "AS3223":   "Voxility (DDoS-for-hire hosting)",
    "AS8100":   "QuadraNet (bulletproof adjacent)",
    "AS63023":  "GTHost (bulletproof adjacent)",
    "AS53667":  "Frantech Solutions (bulletproof, privacy-focused)",
    "AS209103": "aurologic GmbH (TAE transit)",
}

# CDN / legitimate cloud ASNs — filter from C2 pivot results
LEGITIMATE_ASNS: set[str] = {
    "AS13335",  # Cloudflare
    "AS16509",  # AWS
    "AS15169",  # Google
    "AS8075",   # Microsoft Azure
    "AS54113",  # Fastly
    "AS20940",  # Akamai
    "AS14618",  # Amazon CloudFront
    "AS16625",  # Akamai
    "AS32787",  # Akamai
    "AS396982", # Google Cloud
    "AS19527",  # Google Cloud
    "AS36351",  # SoftLayer/IBM Cloud
}


def lookup(ip: str) -> ASNInfo | None:
    """
    Look up ASN information for an IP using BGP.tools (free, no key needed).
    Falls back to ipapi.co for additional metadata.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    time.sleep(settings.rate_limit_delay * 0.5)

    # BGP.tools whois-style API
    try:
        r = requests.get(
            f"https://bgp.tools/api/asn-by-ip?ip={ip}",
            timeout=10,
            headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            data = r.json()
            asn_str = f"AS{data.get('asn', '')}"
            return ASNInfo(
                asn=asn_str,
                asn_name=data.get("name"),
                asn_description=data.get("description"),
                country=data.get("country"),
                prefix=data.get("prefix"),
                is_bulletproof=asn_str in BULLETPROOF_ASNS,
                abuse_contacts=[],
            )
    except Exception:
        pass

    # ipapi.co fallback
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        if r.status_code == 200:
            data = r.json()
            asn_str = data.get("asn", "")
            return ASNInfo(
                asn=asn_str,
                asn_name=data.get("org"),
                country=data.get("country_code"),
                is_bulletproof=asn_str in BULLETPROOF_ASNS,
            )
    except Exception:
        pass

    return None


def cluster_by_asn(ips: list[str]) -> dict[str, list[str]]:
    """
    Group IPs by their ASN. Returns {asn_string: [ip1, ip2, ...]}
    Operators who deploy C2 in bulk tend to cluster in 1-2 preferred ASNs.
    """
    clusters: dict[str, list[str]] = {}
    for ip in ips:
        info = lookup(ip)
        asn = info.asn if info else "unknown"
        clusters.setdefault(asn, []).append(ip)
    return dict(sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True))


def filter_cdn(ips: list[str]) -> list[str]:
    """Remove IPs belonging to CDN / major cloud ASNs."""
    filtered = []
    for ip in ips:
        info = lookup(ip)
        if info and info.asn in LEGITIMATE_ASNS:
            continue
        filtered.append(ip)
    return filtered


def flag_bulletproof(ips: list[str]) -> list[tuple[str, str]]:
    """Return (ip, description) for IPs hosted on known bulletproof ASNs."""
    flagged = []
    for ip in ips:
        info = lookup(ip)
        if info and info.asn in BULLETPROOF_ASNS:
            flagged.append((ip, BULLETPROOF_ASNS[info.asn]))
    return flagged


def is_cdn(ip: str) -> bool:
    info = lookup(ip)
    return bool(info and info.asn in LEGITIMATE_ASNS)


def is_bulletproof(ip: str) -> bool:
    info = lookup(ip)
    return bool(info and info.asn in BULLETPROOF_ASNS)
