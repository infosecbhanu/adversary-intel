"""
VirusTotal pivoting client.

VT is the richest single pivot source for malware-driven C2 tracking:
file → C2 config → JARM → cert → related samples → operator cluster.
"""
from __future__ import annotations

import time
from typing import Any, Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from adversary_intel.config import settings

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self):
        if not settings.virustotal_api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not configured")
        self._headers = {"x-apikey": settings.virustotal_api_key}
        self._delay = settings.rate_limit_delay

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _get(self, path: str, params: dict | None = None) -> dict:
        time.sleep(self._delay)
        r = requests.get(
            f"{_BASE}{path}",
            headers=self._headers,
            params=params or {},
            timeout=20,
        )
        if r.status_code == 429:
            raise RuntimeError("VT rate limit hit")
        if r.status_code != 200:
            return {}
        return r.json()

    # ── File / Hash analysis ─────────────────────────────────────────────────

    def file_report(self, sha256: str) -> dict:
        return self._get(f"/files/{sha256}")

    def file_behavior(self, sha256: str) -> list[dict]:
        """Sandbox behaviour reports — extracts C2 network connections."""
        data = self._get(f"/files/{sha256}/behaviours")
        return data.get("data", [])

    def extract_c2_from_behavior(self, sha256: str) -> list[str]:
        """
        Pull C2 IPs and domains from VT sandbox network behaviour.
        Returns a flat list of observed C2 indicators.
        """
        c2_indicators: list[str] = []
        for behaviour in self.file_behavior(sha256):
            attrs = behaviour.get("attributes", {})
            for item in attrs.get("ip_traffic", []):
                ip = item.get("destination_ip")
                if ip:
                    c2_indicators.append(ip)
            for item in attrs.get("dns_lookups", []):
                domain = item.get("hostname")
                if domain:
                    c2_indicators.append(domain)
            for item in attrs.get("http_conversations", []):
                url = item.get("url", "")
                if url:
                    c2_indicators.append(url)
        return list(set(c2_indicators))

    # ── IP analysis ──────────────────────────────────────────────────────────

    def ip_report(self, ip: str) -> dict:
        return self._get(f"/ip_addresses/{ip}")

    def ip_resolutions(self, ip: str) -> list[str]:
        """Domains that have resolved to this IP (passive DNS via VT)."""
        data = self._get(f"/ip_addresses/{ip}/resolutions")
        return [
            item["attributes"].get("host_name", "")
            for item in data.get("data", [])
            if item.get("attributes")
        ]

    def ip_communicating_files(self, ip: str) -> list[str]:
        """File hashes that communicated with this IP in sandbox analysis."""
        data = self._get(f"/ip_addresses/{ip}/communicating_files")
        return [item["id"] for item in data.get("data", [])]

    def ip_network_location(self, ip: str) -> dict:
        report = self.ip_report(ip)
        attrs = report.get("data", {}).get("attributes", {})
        return {
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "reputation": attrs.get("reputation"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
        }

    # ── Domain analysis ──────────────────────────────────────────────────────

    def domain_report(self, domain: str) -> dict:
        return self._get(f"/domains/{domain}")

    def domain_resolutions(self, domain: str) -> list[str]:
        """IPs this domain has resolved to."""
        data = self._get(f"/domains/{domain}/resolutions")
        return [
            item["attributes"].get("ip_address", "")
            for item in data.get("data", [])
            if item.get("attributes")
        ]

    def domain_subdomains(self, domain: str) -> list[str]:
        data = self._get(f"/domains/{domain}/subdomains")
        return [item["id"] for item in data.get("data", [])]

    # ── Search / Livehunt ────────────────────────────────────────────────────

    def search_intelligence(self, query: str, limit: int = 20) -> list[dict]:
        """VT Intelligence search (requires premium tier)."""
        data = self._get("/intelligence/search", params={"query": query, "limit": limit})
        return data.get("data", [])

    def search_watermark(self, watermark: int) -> list[str]:
        """Find Cobalt Strike beacons sharing a license watermark."""
        results = self.search_intelligence(f"content:{watermark} type:file", limit=40)
        return [r["id"] for r in results if r.get("type") == "file"]

    def search_uri_path(self, path: str) -> list[str]:
        """Find files that contain a specific beacon URI path."""
        results = self.search_intelligence(f'content:"{path}" type:file', limit=40)
        return [r["id"] for r in results if r.get("type") == "file"]

    # ── JARM / TLS ───────────────────────────────────────────────────────────

    def get_jarm(self, ip: str) -> Optional[str]:
        """
        Retrieve the JARM fingerprint VT recorded for an IP
        (from their network infrastructure tab).
        """
        report = self.ip_report(ip)
        attrs = report.get("data", {}).get("attributes", {})
        tls_info = attrs.get("last_https_certificate", {})
        # VT stores JARM under jarm key in newer API
        return attrs.get("jarm") or tls_info.get("jarm")

    def is_malicious(self, ip_or_domain: str) -> tuple[bool, int]:
        """
        Returns (is_malicious, malicious_vendor_count).
        Uses VT consensus: 5+ engines flagging = malicious.
        """
        if "." in ip_or_domain and not ip_or_domain.replace(".", "").isdigit():
            report = self.domain_report(ip_or_domain)
        else:
            report = self.ip_report(ip_or_domain)
        stats = (
            report.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        return malicious >= 5, malicious
