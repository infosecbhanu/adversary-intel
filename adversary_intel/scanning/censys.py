"""
Censys pivot client.

Uses the Censys Python SDK (v2) to search for hosts by certificate
fingerprint, JARM, and other structured fields. Censys uses different
scanner infrastructure from Shodan — providing complementary coverage.
"""
from __future__ import annotations

import time
from typing import Any

from adversary_intel.config import settings

try:
    from censys.search import CensysHosts
    _CENSYS_AVAILABLE = True
except ImportError:
    _CENSYS_AVAILABLE = False


class CensysClient:
    def __init__(self):
        if not _CENSYS_AVAILABLE:
            raise ImportError("censys package not installed. Run: pip install censys")
        if not settings.censys_api_id or not settings.censys_api_secret:
            raise ValueError("CENSYS_API_ID and CENSYS_API_SECRET not configured")
        self._hosts = CensysHosts(
            api_id=settings.censys_api_id,
            api_secret=settings.censys_api_secret,
        )
        self._delay = settings.rate_limit_delay

    def _search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        time.sleep(self._delay)
        results = []
        for hit in self._hosts.search(query, per_page=min(limit, 100)):
            results.append(hit)
            if len(results) >= limit:
                break
        return results

    def pivot_cert_sha256(self, sha256_fp: str, limit: int = 100) -> list[dict]:
        """Find hosts presenting a cert with the given SHA-256 fingerprint."""
        query = f"parsed.fingerprint_sha256:{sha256_fp.lower()}"
        return self._search(query, limit=limit)

    def pivot_cert_cn(self, cn: str, limit: int = 100) -> list[dict]:
        query = f'parsed.subject.common_name:"{cn}"'
        return self._search(query, limit=limit)

    def pivot_cert_serial(self, serial_hex: str, limit: int = 100) -> list[dict]:
        query = f"parsed.serial_number:{serial_hex.lower()}"
        return self._search(query, limit=limit)

    def pivot_jarm(self, jarm: str, limit: int = 100) -> list[dict]:
        """Censys stores JARM in tls.ja3s or services.jarm depending on version."""
        query = f'services.jarm.fingerprint:"{jarm}"'
        return self._search(query, limit=limit)

    def pivot_cert_san(self, san_value: str, limit: int = 100) -> list[dict]:
        """Find hosts with a specific value in cert Subject Alternative Names."""
        query = f'parsed.names:"{san_value}"'
        return self._search(query, limit=limit)

    def pivot_issuer_org(self, org: str, limit: int = 100) -> list[dict]:
        query = f'parsed.issuer.organization:"{org}"'
        return self._search(query, limit=limit)

    def compound_query(self, query: str, limit: int = 100) -> list[dict]:
        return self._search(query, limit=limit)

    def view_host(self, ip: str) -> dict:
        time.sleep(self._delay)
        try:
            return self._hosts.view(ip)
        except Exception:
            return {}
