"""
Abuse.ch feed integrations (no API key required for basic queries).

Covers:
- MalwareBazaar — malware samples and C2 configs
- URLhaus     — malicious URLs and C2 infrastructure
- Feodo Tracker — Emotet/Cobalt Strike botnet C2 IPs
- ThreatFox   — IOC database (IPs, domains, URLs, hashes)
- SSLBL        — malicious SSL certificate blacklist (JARM + cert fingerprints)
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

import requests

from adversary_intel.config import settings
from adversary_intel.models import Indicator, NodeType

_DELAY = settings.rate_limit_delay


# ── MalwareBazaar ─────────────────────────────────────────────────────────────

def malwarebazaar_lookup(sha256: str) -> dict:
    """Look up a file hash in MalwareBazaar."""
    time.sleep(_DELAY)
    r = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": sha256},
        timeout=15,
    )
    if r.status_code == 200:
        data = r.json()
        if data.get("query_status") == "ok":
            return data.get("data", [{}])[0]
    return {}


def malwarebazaar_recent(limit: int = 100, tag: str = "") -> list[dict]:
    """Fetch recent samples from MalwareBazaar, optionally filtered by tag."""
    payload: dict = {"query": "get_recent", "selector": "time"}
    if tag:
        payload = {"query": "get_taginfo", "tag": tag, "limit": limit}
    time.sleep(_DELAY)
    r = requests.post("https://mb-api.abuse.ch/api/v1/", data=payload, timeout=15)
    if r.status_code == 200:
        data = r.json()
        if data.get("query_status") == "ok":
            return data.get("data", [])[:limit]
    return []


def malwarebazaar_query_tag(tag: str) -> list[dict]:
    """Get all samples for a specific malware family tag (e.g. 'CobaltStrike')."""
    return malwarebazaar_recent(tag=tag)


# ── URLhaus ───────────────────────────────────────────────────────────────────

def urlhaus_lookup_url(url: str) -> dict:
    time.sleep(_DELAY)
    r = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url},
        timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    return {}


def urlhaus_lookup_host(host: str) -> dict:
    time.sleep(_DELAY)
    r = requests.post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data={"host": host},
        timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    return {}


def urlhaus_recent(limit: int = 100) -> list[dict]:
    """Recent malicious URLs from URLhaus."""
    time.sleep(_DELAY)
    r = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=15)
    if r.status_code == 200:
        return r.json().get("urls", [])[:limit]
    return []


# ── Feodo Tracker ─────────────────────────────────────────────────────────────

def feodo_c2_list() -> list[dict]:
    """
    Feodo Tracker botnet C2 IP blocklist.
    Covers Emotet, QakBot, IcedID, Dridex C2 infrastructure.
    Returns list of {ip, port, malware, first_seen, last_seen, status}
    """
    time.sleep(_DELAY)
    r = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    return []


def feodo_check_ip(ip: str) -> Optional[dict]:
    """Check if an IP is in the Feodo C2 blocklist."""
    blocklist = feodo_c2_list()
    for entry in blocklist:
        if entry.get("ip_address") == ip:
            return entry
    return None


# ── ThreatFox ─────────────────────────────────────────────────────────────────

def threatfox_lookup(ioc: str) -> list[dict]:
    time.sleep(_DELAY)
    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "search_ioc", "search_term": ioc},
        timeout=15,
    )
    if r.status_code == 200:
        data = r.json()
        if data.get("query_status") == "ok":
            return data.get("data", [])
    return []


def threatfox_recent(limit: int = 100, days: int = 7) -> list[dict]:
    time.sleep(_DELAY)
    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": days},
        timeout=15,
    )
    if r.status_code == 200:
        data = r.json()
        if data.get("query_status") == "ok":
            return data.get("data", [])[:limit]
    return []


def threatfox_by_malware(malware: str, limit: int = 100) -> list[dict]:
    """Get IOCs for a specific malware family from ThreatFox."""
    time.sleep(_DELAY)
    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "taginfo", "tag": malware, "limit": limit},
        timeout=15,
    )
    if r.status_code == 200:
        data = r.json()
        if data.get("query_status") == "ok":
            return data.get("data", [])
    return []


# ── SSLBL ─────────────────────────────────────────────────────────────────────

def sslbl_sha1_list() -> list[dict]:
    """
    SSLBL: SSL certificate blacklist for C2 fingerprinting.
    Returns certs associated with known malicious C2 infrastructure.
    """
    time.sleep(_DELAY)
    r = requests.get(
        "https://sslbl.abuse.ch/blacklist/sslblacklist.json",
        timeout=15,
    )
    if r.status_code == 200:
        return r.json().get("results", [])
    return []


def sslbl_check_fingerprint(sha1: str) -> Optional[dict]:
    """Check a SHA-1 cert fingerprint against SSLBL."""
    sha1_clean = sha1.replace(":", "").lower()
    for entry in sslbl_sha1_list():
        if entry.get("SHA1", "").lower() == sha1_clean:
            return entry
    return None


# ── Unified check ─────────────────────────────────────────────────────────────

def check_all(value: str, ioc_type: NodeType) -> list[Indicator]:
    """
    Check a value across all Abuse.ch feeds.
    Returns matching indicators (empty list = not found in any feed).
    """
    indicators: list[Indicator] = []

    if ioc_type == NodeType.IP:
        feodo = feodo_check_ip(value)
        if feodo:
            indicators.append(Indicator(
                value=value,
                ioc_type=NodeType.IP,
                confidence=85,
                source="feodotracker",
                malware_families=[feodo.get("malware", "")],
                tags=["c2", "botnet", feodo.get("malware", "").lower()],
            ))
        tf = threatfox_lookup(value)
        for entry in tf:
            indicators.append(_tf_to_indicator(entry))

    elif ioc_type == NodeType.HASH:
        mb = malwarebazaar_lookup(value)
        if mb:
            indicators.append(Indicator(
                value=value,
                ioc_type=NodeType.HASH,
                confidence=90,
                source="malwarebazaar",
                malware_families=[mb.get("signature", "")],
                tags=mb.get("tags", []) + ["malware"],
            ))

    elif ioc_type == NodeType.CERTIFICATE:
        sslbl = sslbl_check_fingerprint(value)
        if sslbl:
            indicators.append(Indicator(
                value=value,
                ioc_type=NodeType.CERTIFICATE,
                confidence=85,
                source="sslbl",
                tags=["malicious-cert", "c2"],
                malware_families=[sslbl.get("Reason", "")],
            ))

    return indicators


def _tf_to_indicator(entry: dict) -> Indicator:
    ioc_type_str = entry.get("ioc_type", "ip:port")
    ioc_type = NodeType.IP if "ip" in ioc_type_str else NodeType.DOMAIN
    return Indicator(
        value=entry.get("ioc", ""),
        ioc_type=ioc_type,
        confidence=75,
        source="threatfox",
        malware_families=[entry.get("malware", "")],
        tags=[entry.get("threat_type", ""), "c2"],
        first_seen=_dt(entry.get("first_seen")),
    )


def _dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None
