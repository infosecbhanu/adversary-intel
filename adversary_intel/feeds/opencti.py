"""
OpenCTI integration.

OpenCTI is the leading open-source CTI platform with STIX 2.1 support,
threat actor profiles, campaigns, and ATT&CK mapping.

Self-hosted: https://github.com/OpenCTI-Platform/opencti
SaaS: https://filigran.io/
"""
from __future__ import annotations

from typing import Optional

from adversary_intel.config import settings
from adversary_intel.feeds.base import ThreatFeed
from adversary_intel.models import Indicator, NodeType

try:
    from pycti import OpenCTIApiClient
    _OPENCTI_AVAILABLE = True
except ImportError:
    _OPENCTI_AVAILABLE = False

_TYPE_MAP: dict[NodeType, str] = {
    NodeType.IP: "IPv4-Addr",
    NodeType.DOMAIN: "Domain-Name",
    NodeType.HASH: "StixFile",
    NodeType.URL: "Url",
    NodeType.EMAIL: "Email-Addr",
}


class OpenCTIFeed(ThreatFeed):
    name = "opencti"

    def __init__(self):
        if not _OPENCTI_AVAILABLE:
            raise ImportError("pycti not installed. Run: pip install pycti")
        self._url = settings.opencti_url
        self._token = settings.opencti_token
        self._client: Optional[OpenCTIApiClient] = None

    def is_available(self) -> bool:
        return bool(self._url and self._token)

    def _get_client(self) -> OpenCTIApiClient:
        if not self._client:
            self._client = OpenCTIApiClient(self._url, self._token, ssl_verify=True)
        return self._client

    def check_indicator(self, value: str, ioc_type: NodeType) -> Optional[Indicator]:
        if not self.is_available():
            return None
        client = self._get_client()
        # Search in observables
        observables = client.stix_cyber_observable.list(
            filters={
                "mode": "and",
                "filters": [{"key": "value", "values": [value]}],
                "filterGroups": [],
            },
            first=1,
        )
        if not observables:
            return None
        obs = observables[0]
        return Indicator(
            value=value,
            ioc_type=ioc_type,
            confidence=obs.get("confidence", 50),
            source="opencti",
            tags=[label.get("value", "") for label in obs.get("objectLabel", [])],
        )

    def get_recent(self, limit: int = 100) -> list[Indicator]:
        if not self.is_available():
            return []
        client = self._get_client()
        observables = client.stix_cyber_observable.list(first=limit, orderBy="created_at")
        indicators = []
        for obs in observables:
            ioc_type = _detect_type(obs.get("entity_type", ""))
            indicators.append(Indicator(
                value=obs.get("value", obs.get("observable_value", "")),
                ioc_type=ioc_type,
                confidence=obs.get("confidence", 50),
                source="opencti",
                tags=[label.get("value", "") for label in obs.get("objectLabel", [])],
            ))
        return indicators

    def get_threat_actor(self, name: str) -> dict:
        if not self.is_available():
            return {}
        client = self._get_client()
        actors = client.threat_actor.list(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [name]}],
                "filterGroups": [],
            },
            first=1,
        )
        return actors[0] if actors else {}

    def get_campaign_indicators(self, campaign_name: str) -> list[Indicator]:
        if not self.is_available():
            return []
        client = self._get_client()
        campaigns = client.campaign.list(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [campaign_name]}],
                "filterGroups": [],
            },
            first=1,
        )
        if not campaigns:
            return []
        campaign = campaigns[0]
        # Get related indicators through relationships
        indicators = client.indicator.list(
            filters={
                "mode": "and",
                "filters": [{"key": "objectLabel", "values": [campaign_name]}],
                "filterGroups": [],
            },
            first=200,
        )
        return [
            Indicator(
                value=ind.get("pattern", "").strip("[]").split(" = ")[-1].strip("'"),
                ioc_type=NodeType.DOMAIN,  # simplified; real type from pattern
                confidence=ind.get("confidence", 50),
                source="opencti",
            )
            for ind in indicators
        ]

    def create_observable(self, value: str, ioc_type: NodeType, comment: str = "") -> Optional[str]:
        """Create a new observable in OpenCTI. Returns entity ID."""
        if not self.is_available():
            return None
        client = self._get_client()
        entity_type = _TYPE_MAP.get(ioc_type, "IPv4-Addr")
        result = client.stix_cyber_observable.create(
            simple_observable_key=entity_type,
            simple_observable_value=value,
            createIndicator=True,
        )
        return result.get("id") if result else None

    def create_infrastructure_report(
        self,
        name: str,
        description: str,
        indicators: list[dict],
        tags: list[str] | None = None,
    ) -> Optional[str]:
        """Create a report in OpenCTI documenting discovered infrastructure."""
        if not self.is_available():
            return None
        client = self._get_client()
        report = client.report.create(
            name=name,
            description=description,
            report_types=["threat-report"],
            published=None,
            confidence=70,
            objectLabel=tags or [],
        )
        return report.get("id") if report else None


def _detect_type(entity_type: str) -> NodeType:
    return {
        "IPv4-Addr": NodeType.IP,
        "IPv6-Addr": NodeType.IP,
        "Domain-Name": NodeType.DOMAIN,
        "Hostname": NodeType.DOMAIN,
        "StixFile": NodeType.HASH,
        "Url": NodeType.URL,
        "Email-Addr": NodeType.EMAIL,
    }.get(entity_type, NodeType.DOMAIN)
