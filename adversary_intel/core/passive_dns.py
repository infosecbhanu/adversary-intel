"""
Passive DNS pivoting.

Queries Validin, SecurityTrails, and VirusTotal for historical DNS
resolution data. Detects batch activation clusters — the moment a threat
actor bulk-activates a set of domains to the same IP within a short window.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from adversary_intel.config import settings
from adversary_intel.models import PassiveDNSRecord


class PassiveDNSClient:
    def __init__(self):
        self._st_key = settings.securitytrails_api_key
        self._vt_key = settings.virustotal_api_key
        self._validin_key = settings.validin_api_key
        self._delay = settings.rate_limit_delay

    # ── SecurityTrails ──────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def _st_history(self, query: str, qtype: str = "ip") -> list[PassiveDNSRecord]:
        if not self._st_key:
            return []
        headers = {"APIKEY": self._st_key}
        if qtype == "ip":
            url = f"https://api.securitytrails.com/v1/ips/nearby/{query}"
            r = requests.get(url, headers=headers, timeout=15)
        else:
            url = f"https://api.securitytrails.com/v1/history/{query}/dns/a"
            r = requests.get(url, headers=headers, timeout=15)

        if r.status_code != 200:
            return []
        data = r.json()
        records = []
        for record in data.get("records", []):
            for val in record.get("values", []):
                ip = val.get("ip", "")
                records.append(PassiveDNSRecord(
                    query=query,
                    answer=ip,
                    record_type="A",
                    first_seen=_parse_dt(record.get("first_seen")),
                    last_seen=_parse_dt(record.get("last_seen")),
                    source="securitytrails",
                ))
        return records

    # ── VirusTotal ──────────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def _vt_pdns_ip(self, ip: str) -> list[PassiveDNSRecord]:
        if not self._vt_key:
            return []
        headers = {"x-apikey": self._vt_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return []
        records = []
        for item in r.json().get("data", []):
            attrs = item.get("attributes", {})
            records.append(PassiveDNSRecord(
                query=ip,
                answer=attrs.get("host_name", ""),
                record_type="PTR",
                last_seen=_parse_dt_epoch(attrs.get("date")),
                source="virustotal",
            ))
        return records

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def _vt_pdns_domain(self, domain: str) -> list[PassiveDNSRecord]:
        if not self._vt_key:
            return []
        headers = {"x-apikey": self._vt_key}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return []
        records = []
        for item in r.json().get("data", []):
            attrs = item.get("attributes", {})
            records.append(PassiveDNSRecord(
                query=domain,
                answer=attrs.get("ip_address", ""),
                record_type="A",
                last_seen=_parse_dt_epoch(attrs.get("date")),
                source="virustotal",
            ))
        return records

    # ── Validin ─────────────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def _validin_pdns(self, query: str, qtype: str = "ip") -> list[PassiveDNSRecord]:
        if not self._validin_key:
            return []
        headers = {"X-API-Key": self._validin_key}
        if qtype == "ip":
            url = f"https://api.validin.com/api/axfr/ip/{query}/history"
        else:
            url = f"https://api.validin.com/api/axfr/domain/{query}/history"
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return []
        records = []
        for item in r.json().get("results", []):
            records.append(PassiveDNSRecord(
                query=query,
                answer=item.get("value", ""),
                record_type=item.get("type", "A"),
                first_seen=_parse_dt(item.get("first_seen")),
                last_seen=_parse_dt(item.get("last_seen")),
                count=item.get("count", 0),
                source="validin",
            ))
        return records

    # ── Public API ───────────────────────────────────────────────────────────

    def resolve_history(self, domain: str) -> list[PassiveDNSRecord]:
        """All IPs a domain has ever resolved to, across all sources."""
        time.sleep(self._delay)
        records: list[PassiveDNSRecord] = []
        records.extend(self._st_history(domain, qtype="domain"))
        records.extend(self._vt_pdns_domain(domain))
        records.extend(self._validin_pdns(domain, qtype="domain"))
        return records

    def ip_history(self, ip: str) -> list[PassiveDNSRecord]:
        """All domains that have ever resolved to an IP."""
        time.sleep(self._delay)
        records: list[PassiveDNSRecord] = []
        records.extend(self._vt_pdns_ip(ip))
        records.extend(self._validin_pdns(ip, qtype="ip"))
        return records

    def find_batch_activation(
        self,
        records: list[PassiveDNSRecord],
        window_hours: int = 48,
    ) -> list[list[PassiveDNSRecord]]:
        """
        Detect batch activation clusters: groups of domains that first resolved
        within the same time window. Classic indicator of bulk infrastructure
        deployment by a single operator.
        """
        dated = [r for r in records if r.first_seen or r.last_seen]
        dated.sort(key=lambda r: (r.first_seen or r.last_seen))  # type: ignore[arg-type]

        clusters: list[list[PassiveDNSRecord]] = []
        window = timedelta(hours=window_hours)

        for i, anchor in enumerate(dated):
            anchor_dt = anchor.first_seen or anchor.last_seen
            cluster = [anchor]
            for other in dated[i + 1:]:
                other_dt = other.first_seen or other.last_seen
                if other_dt and anchor_dt and abs((other_dt - anchor_dt)) <= window:
                    cluster.append(other)
            if len(cluster) >= 3:
                clusters.append(cluster)

        # Deduplicate (clusters are nested)
        unique: list[list[PassiveDNSRecord]] = []
        seen: set[str] = set()
        for c in sorted(clusters, key=len, reverse=True):
            key = frozenset(r.answer for r in c)
            fk = str(sorted(key))
            if fk not in seen:
                seen.add(fk)
                unique.append(c)
        return unique


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _parse_dt_epoch(epoch: Optional[int]) -> Optional[datetime]:
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc)
