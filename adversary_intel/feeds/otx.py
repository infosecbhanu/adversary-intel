"""
AlienVault OTX (Open Threat Exchange) integration.

OTX is the world's largest open threat intelligence community — free with
registration. This client checks indicators against OTX pulses and retrieves
related threat intelligence for discovered infrastructure.

Sign up: https://otx.alienvault.com/
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

import requests

from adversary_intel.config import settings
from adversary_intel.feeds.base import ThreatFeed
from adversary_intel.models import Indicator, NodeType

_BASE = "https://otx.alienvault.com/api/v1"

_SECTION_MAP: dict[NodeType, tuple[str, str]] = {
    NodeType.IP: ("indicators/IPv4", "ip"),
    NodeType.DOMAIN: ("indicators/domain", "domain"),
    NodeType.HASH: ("indicators/file", "hash"),
    NodeType.URL: ("indicators/url", "url"),
}


class OTXFeed(ThreatFeed):
    name = "otx"

    def __init__(self):
        self._key = settings.otx_api_key
        self._delay = settings.rate_limit_delay

    def is_available(self) -> bool:
        return bool(self._key)

    def _get(self, path: str, params: dict | None = None) -> dict:
        if not self._key:
            return {}
        time.sleep(self._delay)
        r = requests.get(
            f"{_BASE}/{path}",
            headers={"X-OTX-API-KEY": self._key},
            params=params or {},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        return {}

    def check_indicator(self, value: str, ioc_type: NodeType) -> Optional[Indicator]:
        mapping = _SECTION_MAP.get(ioc_type)
        if not mapping:
            return None
        path_prefix, _ = mapping
        data = self._get(f"{path_prefix}/{value}/general")
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count == 0:
            return None
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags = []
        threat_actors = []
        malware_families = []
        for pulse in pulses[:5]:
            tags.extend(pulse.get("tags", []))
            if pulse.get("adversary"):
                threat_actors.append(pulse["adversary"])
            malware_families.extend(pulse.get("malware_families", []))

        return Indicator(
            value=value,
            ioc_type=ioc_type,
            confidence=min(50 + pulse_count * 5, 95),
            tags=list(set(tags))[:10],
            source="otx",
            malware_families=list(set(malware_families))[:5],
            threat_actors=list(set(threat_actors))[:3],
            meta={"pulse_count": pulse_count},
        )

    def get_recent(self, limit: int = 100) -> list[Indicator]:
        data = self._get("pulses/subscribed", params={"limit": limit})
        indicators: list[Indicator] = []
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                ioc_type = _detect_type(ind.get("type", ""))
                indicators.append(Indicator(
                    value=ind.get("indicator", ""),
                    ioc_type=ioc_type,
                    confidence=60,
                    source="otx",
                    tags=pulse.get("tags", []),
                    malware_families=pulse.get("malware_families", []),
                    threat_actors=[pulse.get("adversary")] if pulse.get("adversary") else [],
                    first_seen=_dt(ind.get("created")),
                ))
        return indicators[:limit]

    def get_ip_geo(self, ip: str) -> dict:
        return self._get(f"indicators/IPv4/{ip}/geo")

    def get_ip_malware(self, ip: str) -> list[str]:
        data = self._get(f"indicators/IPv4/{ip}/malware")
        return [r.get("hash", "") for r in data.get("data", [])]

    def get_domain_whois(self, domain: str) -> dict:
        return self._get(f"indicators/domain/{domain}/whois")

    def get_domain_passive_dns(self, domain: str) -> list[dict]:
        data = self._get(f"indicators/domain/{domain}/passive_dns")
        return data.get("passive_dns", [])

    def search_pulses(self, query: str, limit: int = 20) -> list[dict]:
        data = self._get("search/pulses", params={"q": query, "limit": limit})
        return data.get("results", [])


def _detect_type(otx_type: str) -> NodeType:
    return {
        "IPv4": NodeType.IP,
        "IPv6": NodeType.IP,
        "domain": NodeType.DOMAIN,
        "hostname": NodeType.DOMAIN,
        "FileHash-SHA256": NodeType.HASH,
        "FileHash-MD5": NodeType.HASH,
        "URL": NodeType.URL,
        "email": NodeType.EMAIL,
    }.get(otx_type, NodeType.DOMAIN)


def _dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
