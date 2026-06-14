"""
Certificate Transparency log monitoring via crt.sh.

crt.sh is a public CT log aggregator. This module queries it to:
1. Find all certificates issued for a domain or subdomain pattern
2. Detect phishing infrastructure standing up (lookalike domains)
3. Find bulk Let's Encrypt issuance for /24 IP ranges
4. Monitor newly issued certs matching org-name keywords

No API key required — crt.sh is freely available.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

import requests

from adversary_intel.config import settings

_BASE = "https://crt.sh"


def search(
    query: str,
    exclude_expired: bool = True,
    limit: int = 200,
) -> list[dict]:
    """
    Query crt.sh for certificates matching a domain/wildcard pattern.

    query examples:
      "%.targetorg.com"    → all subdomains of targetorg.com
      "%.slack.%.com"      → Slack impersonation certs
      "targetorg"          → any cert where CN/SAN contains the string
    """
    params = {"q": query, "output": "json"}
    time.sleep(settings.rate_limit_delay)
    try:
        r = requests.get(f"{_BASE}/", params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []

    results = []
    seen_ids: set[int] = set()
    for entry in data:
        cert_id = entry.get("id")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        not_after_str = entry.get("not_after", "")
        not_after = _parse_dt(not_after_str)
        if exclude_expired and not_after and not_after < datetime.now(timezone.utc):
            continue

        results.append({
            "id": cert_id,
            "issuer": entry.get("issuer_name", ""),
            "common_name": entry.get("common_name", ""),
            "name_value": entry.get("name_value", ""),
            "not_before": entry.get("not_before"),
            "not_after": not_after_str,
            "logged_at": entry.get("entry_timestamp"),
        })
        if len(results) >= limit:
            break
    return results


def monitor_org(org_name: str, exclude_expired: bool = True) -> list[dict]:
    """
    Find certs where the issuer/subject contains an organization name.
    Useful for detecting phishing certs impersonating your org.
    """
    return search(f"%{org_name}%", exclude_expired=exclude_expired)


def detect_bulk_issuance(
    results: list[dict],
    window_hours: int = 24,
    min_count: int = 5,
) -> list[list[dict]]:
    """
    Detect bulk certificate issuance: certs logged within the same
    time window suggest batch phishing infrastructure deployment.
    """
    from datetime import timedelta
    dated = [r for r in results if r.get("logged_at")]
    dated.sort(key=lambda r: r["logged_at"])

    clusters: list[list[dict]] = []
    window = timedelta(hours=window_hours)

    for i, anchor in enumerate(dated):
        try:
            anchor_dt = datetime.fromisoformat(anchor["logged_at"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        cluster = [anchor]
        for other in dated[i + 1:]:
            try:
                other_dt = datetime.fromisoformat(other["logged_at"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue
            if abs((other_dt - anchor_dt)) <= window:
                cluster.append(other)
        if len(cluster) >= min_count:
            clusters.append(cluster)

    seen: set[str] = set()
    unique = []
    for c in sorted(clusters, key=len, reverse=True):
        key = frozenset(e.get("id", "") for e in c)
        fk = str(sorted(key))
        if fk not in seen:
            seen.add(fk)
            unique.append(c)
    return unique


def extract_domains(results: list[dict]) -> list[str]:
    """Extract all unique domain values from CT results."""
    domains: set[str] = set()
    for r in results:
        for field in ("common_name", "name_value"):
            value = r.get(field, "")
            for domain in value.split("\n"):
                domain = domain.strip().lstrip("*.")
                if domain:
                    domains.add(domain)
    return sorted(domains)


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None
