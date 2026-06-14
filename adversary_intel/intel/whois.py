"""
WHOIS pivoting for registration intelligence.

Threat actors registering bulk domains reuse the same registrar, nameserver
pair, privacy proxy, and often registration timestamps — all pivot surfaces
that can connect dozens of domains into a single operator cluster.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
import whois as python_whois

from adversary_intel.config import settings
from adversary_intel.models import WHOISData


def lookup(domain: str) -> WHOISData | None:
    """WHOIS lookup using python-whois library."""
    try:
        w = python_whois.whois(domain)
        if not w:
            return None

        def _first(v):
            if isinstance(v, list):
                return v[0] if v else None
            return v

        def _list(v) -> list[str]:
            if not v:
                return []
            if isinstance(v, list):
                return [str(x).lower() for x in v]
            return [str(v).lower()]

        return WHOISData(
            domain=domain,
            registrar=_first(w.registrar),
            registrant_email=_first(w.emails),
            registrant_org=_first(w.org),
            nameservers=_list(w.name_servers),
            creation_date=_normalize_date(_first(w.creation_date)),
            updated_date=_normalize_date(_first(w.updated_date)),
            expiry_date=_normalize_date(_first(w.expiration_date)),
            privacy_protected=_is_privacy_protected(w),
            raw=str(w),
        )
    except Exception:
        return None


class SecurityTrailsWHOIS:
    """
    SecurityTrails API for WHOIS history and reverse NS/registrar lookups.
    Much richer than raw WHOIS — supports historical records and bulk search.
    """

    def __init__(self):
        self._key = settings.securitytrails_api_key
        self._delay = settings.rate_limit_delay

    def _get(self, path: str, params: dict | None = None) -> dict:
        if not self._key:
            return {}
        time.sleep(self._delay)
        r = requests.get(
            f"https://api.securitytrails.com/v1{path}",
            headers={"APIKEY": self._key},
            params=params or {},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        return {}

    def domain_info(self, domain: str) -> dict:
        return self._get(f"/domain/{domain}")

    def associated_domains(self, domain: str) -> list[str]:
        """All domains sharing nameservers, registrar, or email with this domain."""
        data = self._get(f"/domain/{domain}/associated")
        return [r.get("hostname", "") for r in data.get("records", [])]

    def reverse_nameserver(self, nameserver: str) -> list[str]:
        """All domains currently or historically using this nameserver."""
        data = self._get(f"/search/list/", params={"ns": nameserver})
        return [r.get("hostname", "") for r in data.get("records", [])]

    def whois_history(self, domain: str) -> list[dict]:
        data = self._get(f"/history/{domain}/whois")
        return data.get("result", {}).get("items", [])


def find_nameserver_cluster(
    domains: list[str],
    min_shared: int = 2,
) -> dict[str, list[str]]:
    """
    Group domains by shared nameserver pairs.
    Returns {nameserver_pair_key: [domain1, domain2, ...]}
    """
    ns_map: dict[str, list[str]] = {}
    for domain in domains:
        data = lookup(domain)
        if not data or not data.nameservers:
            continue
        ns_key = "|".join(sorted(data.nameservers[:2]))
        ns_map.setdefault(ns_key, []).append(domain)

    return {k: v for k, v in ns_map.items() if len(v) >= min_shared}


def find_batch_registration(
    domains: list[str],
    window_hours: int = 72,
) -> list[list[str]]:
    """
    Detect domains registered within the same time window (batch registration).
    Returns clusters of domains likely registered by the same operator in one session.
    """
    dated: list[tuple[datetime, str]] = []
    for domain in domains:
        data = lookup(domain)
        if data and data.creation_date:
            dated.append((data.creation_date, domain))
    dated.sort(key=lambda x: x[0])

    clusters: list[list[str]] = []
    window = timedelta(hours=window_hours)
    for i, (anchor_dt, anchor_domain) in enumerate(dated):
        cluster = [anchor_domain]
        for other_dt, other_domain in dated[i + 1:]:
            if abs((other_dt - anchor_dt)) <= window:
                cluster.append(other_domain)
        if len(cluster) >= 3:
            clusters.append(cluster)

    seen: set[str] = set()
    unique = []
    for c in sorted(clusters, key=len, reverse=True):
        key = str(sorted(c))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


# ── Helpers ──────────────────────────────────────────────────────────────────

_PRIVACY_KEYWORDS = {
    "privacy", "redacted", "whoisguard", "domains by proxy",
    "withheld", "identity protection", "perfect privacy",
    "registrant privacy", "data protected",
}


def _is_privacy_protected(w) -> bool:
    raw = str(w).lower()
    return any(kw in raw for kw in _PRIVACY_KEYWORDS)


def _normalize_date(v) -> Optional[datetime]:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v
    if isinstance(v, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None
