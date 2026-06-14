"""
MISP (Malware Information Sharing Platform) integration.

MISP is the most widely deployed open-source threat intelligence platform.
This client supports event creation, indicator lookup, and sharing discovered
infrastructure with your MISP instance or community.

Self-hosted: https://github.com/MISP/MISP
Community instances: https://www.misp-project.org/communities/
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from adversary_intel.config import settings
from adversary_intel.feeds.base import ThreatFeed
from adversary_intel.models import Indicator, NodeType

try:
    from pymisp import MISPEvent, MISPObject, PyMISP
    _MISP_AVAILABLE = True
except ImportError:
    _MISP_AVAILABLE = False

_TYPE_MAP: dict[NodeType, str] = {
    NodeType.IP: "ip-dst",
    NodeType.DOMAIN: "domain",
    NodeType.HASH: "sha256",
    NodeType.URL: "url",
    NodeType.EMAIL: "email-src",
    NodeType.CERTIFICATE: "x509-fingerprint-sha256",
}


class MISPFeed(ThreatFeed):
    name = "misp"

    def __init__(self):
        if not _MISP_AVAILABLE:
            raise ImportError("pymisp not installed. Run: pip install pymisp")
        self._url = settings.misp_url
        self._key = settings.misp_key
        self._verify = settings.misp_verify_ssl
        self._misp: Optional[PyMISP] = None

    def is_available(self) -> bool:
        return bool(self._url and self._key)

    def _client(self) -> PyMISP:
        if not self._misp:
            self._misp = PyMISP(self._url, self._key, self._verify)
        return self._misp

    def check_indicator(self, value: str, ioc_type: NodeType) -> Optional[Indicator]:
        if not self.is_available():
            return None
        misp_type = _TYPE_MAP.get(ioc_type, "text")
        result = self._client().search(value=value, type_attribute=misp_type)
        attrs = result.get("Attribute", []) if isinstance(result, dict) else []
        if not attrs:
            return None
        attr = attrs[0]
        return Indicator(
            value=value,
            ioc_type=ioc_type,
            confidence=_misp_to_confidence(attr),
            tags=[t.get("name", "") for t in attr.get("Tag", [])],
            source="misp",
            first_seen=_dt(attr.get("timestamp")),
        )

    def get_recent(self, limit: int = 100) -> list[Indicator]:
        if not self.is_available():
            return []
        result = self._client().search(
            limit=limit,
            order="timestamp",
            publish_timestamp="1d",
        )
        events = result.get("Event", result) if isinstance(result, dict) else result
        indicators: list[Indicator] = []
        for event in (events or [])[:limit]:
            for attr in event.get("Attribute", []):
                ioc_type = _detect_type(attr.get("type", ""))
                indicators.append(Indicator(
                    value=attr.get("value", ""),
                    ioc_type=ioc_type,
                    confidence=50,
                    source="misp",
                    tags=[t.get("name", "") for t in attr.get("Tag", [])],
                    first_seen=_dt(attr.get("timestamp")),
                ))
        return indicators[:limit]

    def create_infrastructure_event(
        self,
        title: str,
        indicators: list[dict],
        threat_level: int = 2,
        distribution: int = 0,
        tags: list[str] | None = None,
    ) -> str | None:
        """
        Create a MISP event for a discovered infrastructure cluster.
        Returns the event UUID, or None on failure.

        threat_level: 1=high, 2=medium, 3=low, 4=undefined
        distribution: 0=org, 1=community, 2=connected, 3=all
        """
        if not self.is_available():
            return None
        event = MISPEvent()
        event.info = title
        event.threat_level_id = threat_level
        event.distribution = distribution

        for tag in (tags or []):
            event.add_tag(tag)

        for ind in indicators:
            misp_type = _TYPE_MAP.get(ind.get("type", NodeType.IP), "text")
            attr = event.add_attribute(
                type=misp_type,
                value=ind.get("value", ""),
                comment=ind.get("comment", ""),
            )
            for t in ind.get("tags", []):
                attr.add_tag(t)

        result = self._client().add_event(event)
        if isinstance(result, dict) and "Event" in result:
            return result["Event"].get("uuid")
        return None

    def search_by_tag(self, tag: str, limit: int = 100) -> list[Indicator]:
        if not self.is_available():
            return []
        result = self._client().search(tags=[tag], limit=limit)
        indicators: list[Indicator] = []
        events = result.get("Event", result) if isinstance(result, dict) else result
        for event in (events or []):
            for attr in event.get("Attribute", []):
                ioc_type = _detect_type(attr.get("type", ""))
                indicators.append(Indicator(
                    value=attr.get("value", ""),
                    ioc_type=ioc_type,
                    confidence=50,
                    source="misp",
                    tags=[t.get("name", "") for t in attr.get("Tag", [])],
                ))
        return indicators[:limit]


def _detect_type(misp_type: str) -> NodeType:
    return {
        "ip-dst": NodeType.IP,
        "ip-src": NodeType.IP,
        "domain": NodeType.DOMAIN,
        "hostname": NodeType.DOMAIN,
        "sha256": NodeType.HASH,
        "md5": NodeType.HASH,
        "url": NodeType.URL,
        "email-src": NodeType.EMAIL,
        "x509-fingerprint-sha256": NodeType.CERTIFICATE,
    }.get(misp_type, NodeType.DOMAIN)


def _misp_to_confidence(attr: dict) -> int:
    # MISP doesn't have a native confidence field; use to_ids as proxy
    return 70 if attr.get("to_ids") else 40


def _dt(timestamp: Optional[str | int]) -> Optional[datetime]:
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp))
    except (ValueError, TypeError):
        return None
