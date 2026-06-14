"""
SecurityTrails passive DNS and domain intelligence client.

Free tier: 50 API calls/month.
Sign up at https://securitytrails.com/app/account
"""
from __future__ import annotations

import time
from typing import Any

import requests

from adversary_intel.feeds.base import BaseFeed


class SecurityTrailsFeed(BaseFeed):
    """SecurityTrails passive DNS, subdomain, and WHOIS pivot client."""

    BASE = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: str, rate_delay: float = 1.0) -> None:
        super().__init__(rate_delay=rate_delay)
        self.headers = {"APIKEY": api_key, "Accept": "application/json"}

    def _get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        time.sleep(self.rate_delay)
        r = requests.get(f"{self.BASE}{path}", headers=self.headers, params=params or {}, timeout=20)
        r.raise_for_status()
        return r.json()

    def domain_info(self, domain: str) -> dict[str, Any]:
        """Current DNS records + WHOIS for a domain."""
        return self._get(f"/domain/{domain}")

    def passive_dns(self, hostname: str) -> list[dict[str, Any]]:
        """Historical A/AAAA records for a hostname."""
        data = self._get(f"/history/{hostname}/dns/a")
        return data.get("records", [])

    def subdomains(self, domain: str) -> list[str]:
        """All known subdomains for a domain."""
        data = self._get(f"/domain/{domain}/subdomains")
        subs = data.get("subdomains", [])
        return [f"{s}.{domain}" for s in subs]

    def associated_domains(self, domain: str) -> list[str]:
        """Domains sharing the same IP or nameserver at any point."""
        data = self._get(f"/domain/{domain}/associated")
        return [r.get("hostname", "") for r in data.get("records", [])]

    def ip_neighbors(self, ip: str) -> list[dict[str, Any]]:
        """Domains that have resolved to an IP and nearby block."""
        data = self._get(f"/ips/nearby/{ip}")
        return data.get("blocks", [])

    def search_by_ns(self, nameserver: str, page: int = 1) -> list[str]:
        """Find all domains using a specific nameserver — useful for registrar pivoting."""
        body = {"filter": {"ns": nameserver}}
        time.sleep(self.rate_delay)
        r = requests.post(
            f"{self.BASE}/domains/list",
            headers=self.headers,
            json=body,
            params={"page": page},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        return [rec.get("hostname", "") for rec in data.get("records", [])]

    def search_by_whois_email(self, email: str, page: int = 1) -> list[str]:
        """Find domains registered with a specific WHOIS email."""
        body = {"filter": {"whois_email": email}}
        time.sleep(self.rate_delay)
        r = requests.post(
            f"{self.BASE}/domains/list",
            headers=self.headers,
            json=body,
            params={"page": page},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        return [rec.get("hostname", "") for rec in data.get("records", [])]

    def whois_history(self, domain: str) -> list[dict[str, Any]]:
        """Historical WHOIS records for a domain."""
        data = self._get(f"/history/{domain}/whois")
        return data.get("result", {}).get("items", [])
