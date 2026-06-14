"""
Shodan pivot client.

Uses the official Shodan Python library to pivot on JARM fingerprints,
TLS certificate hashes, favicon hashes, and HTTP response patterns.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from adversary_intel.config import settings

try:
    import shodan as shodan_lib
    _SHODAN_AVAILABLE = True
except ImportError:
    _SHODAN_AVAILABLE = False


class ShodanClient:
    def __init__(self):
        if not _SHODAN_AVAILABLE:
            raise ImportError("shodan package not installed. Run: pip install shodan")
        if not settings.shodan_api_key:
            raise ValueError("SHODAN_API_KEY not configured")
        self._api = shodan_lib.Shodan(settings.shodan_api_key)
        self._delay = settings.rate_limit_delay

    def _search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        time.sleep(self._delay)
        try:
            results = self._api.search(query, limit=limit)
            return results.get("matches", [])
        except shodan_lib.APIError as e:
            raise RuntimeError(f"Shodan search failed for '{query}': {e}") from e

    def pivot_jarm(self, jarm: str, limit: int = 100) -> list[dict]:
        """Find all IPs sharing a JARM fingerprint."""
        query = f'ssl.jarm:"{jarm}"'
        matches = self._search(query, limit=limit)
        return [
            {
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "org": m.get("org"),
                "asn": m.get("asn"),
                "country": m.get("location", {}).get("country_code"),
                "hostnames": m.get("hostnames", []),
                "jarm": jarm,
            }
            for m in matches
        ]

    def pivot_jarm_with_404(self, jarm: str, limit: int = 100) -> list[dict]:
        """Layer JARM + Cobalt Strike 404 response to reduce false positives."""
        query = (
            f'ssl.jarm:"{jarm}" '
            '"HTTP/1.1 404 Not Found" '
            '"Content-Length: 0"'
        )
        return self._search(query, limit=limit)

    def pivot_cert_fingerprint(self, sha1_fp: str, limit: int = 100) -> list[dict]:
        """Find all hosts serving a certificate with the given SHA-1 fingerprint."""
        query = f'ssl.cert.fingerprint:"{sha1_fp}"'
        matches = self._search(query, limit=limit)
        return [
            {"ip": m.get("ip_str"), "port": m.get("port"), "asn": m.get("asn"), "org": m.get("org")}
            for m in matches
        ]

    def pivot_cert_serial(self, serial_decimal: int, limit: int = 100) -> list[dict]:
        """Find all hosts presenting a cert with the given serial number."""
        query = f"ssl.cert.serial:{serial_decimal}"
        return self._search(query, limit=limit)

    def pivot_cert_cn(self, cn: str, limit: int = 100) -> list[dict]:
        """Find all hosts whose cert Subject CN matches."""
        query = f'ssl.cert.subject.cn:"{cn}"'
        return self._search(query, limit=limit)

    def pivot_favicon(self, mmh3_hash: int, limit: int = 100) -> list[dict]:
        """Find all hosts sharing a favicon hash — surfaces phishing clusters."""
        query = f"http.favicon.hash:{mmh3_hash}"
        return self._search(query, limit=limit)

    def pivot_http_title(self, title: str, limit: int = 100) -> list[dict]:
        query = f'http.title:"{title}"'
        return self._search(query, limit=limit)

    def pivot_html_content(self, snippet: str, limit: int = 100) -> list[dict]:
        """Find hosts whose HTTP response body contains a specific URI or string."""
        query = f'http.html:"{snippet}" http.status:200'
        return self._search(query, limit=limit)

    def compound_query(self, query: str, limit: int = 100) -> list[dict]:
        """Run an arbitrary Shodan query."""
        return self._search(query, limit=limit)

    def host_info(self, ip: str) -> dict:
        """Full Shodan host record for an IP."""
        time.sleep(self._delay)
        try:
            return self._api.host(ip)
        except shodan_lib.APIError:
            return {}

    def filter_cdn_asns(self, results: list[dict]) -> list[dict]:
        """
        Remove results hosted on known CDN ASNs to reduce false positives.
        Adversary C2 does not typically use Cloudflare, Akamai, Fastly.
        """
        cdn_asns = {
            "AS13335",  # Cloudflare
            "AS16509",  # Amazon (AWS)
            "AS15169",  # Google
            "AS8075",   # Microsoft Azure
            "AS54113",  # Fastly
            "AS20940",  # Akamai
            "AS14618",  # Amazon
            "AS16625",  # Akamai
            "AS32787",  # Akamai
        }
        return [r for r in results if r.get("asn") not in cdn_asns]
