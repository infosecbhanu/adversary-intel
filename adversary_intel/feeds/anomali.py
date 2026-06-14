"""
Anomali ThreatStream integration.

ThreatStream is one of the most comprehensive commercial threat intelligence
platforms. This client supports indicator lookup, bulk submission of newly
discovered infrastructure, and threat actor profile queries.

Free trial: https://www.anomali.com/products/threatstream
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

import requests

from adversary_intel.config import settings
from adversary_intel.feeds.base import ThreatFeed
from adversary_intel.models import Indicator, NodeType

_TYPE_MAP: dict[NodeType, str] = {
    NodeType.IP: "ip",
    NodeType.DOMAIN: "domain",
    NodeType.HASH: "md5",
    NodeType.URL: "url",
    NodeType.EMAIL: "email",
}


class AnomaliThreatStream(ThreatFeed):
    name = "anomali_threatstream"

    def __init__(self):
        self._url = settings.anomali_url.rstrip("/")
        self._user = settings.anomali_username
        self._key = settings.anomali_api_key
        self._delay = settings.rate_limit_delay

    def is_available(self) -> bool:
        return bool(self._user and self._key)

    def _auth_params(self) -> dict:
        return {"username": self._user, "api_key": self._key}

    def _get(self, path: str, params: dict | None = None) -> dict:
        if not self.is_available():
            return {}
        time.sleep(self._delay)
        p = {**(params or {}), **self._auth_params()}
        r = requests.get(f"{self._url}{path}", params=p, timeout=20)
        if r.status_code == 200:
            return r.json()
        return {}

    def _post(self, path: str, data: dict) -> dict:
        if not self.is_available():
            return {}
        time.sleep(self._delay)
        r = requests.post(
            f"{self._url}{path}",
            json={**data, **self._auth_params()},
            timeout=20,
        )
        if r.status_code in (200, 201, 202):
            return r.json()
        return {}

    # ── Indicator lookup ─────────────────────────────────────────────────────

    def check_indicator(self, value: str, ioc_type: NodeType) -> Optional[Indicator]:
        ts_type = _TYPE_MAP.get(ioc_type)
        if not ts_type:
            return None
        data = self._get(
            "/api/v2/intelligence/",
            params={"value": value, "type": ts_type, "limit": 1},
        )
        objects = data.get("objects", [])
        if not objects:
            return None
        obj = objects[0]
        return _to_indicator(obj, ioc_type)

    def get_recent(self, limit: int = 100) -> list[Indicator]:
        data = self._get("/api/v2/intelligence/", params={"limit": limit, "order_by": "-created_ts"})
        return [_to_indicator(obj, _detect_type(obj)) for obj in data.get("objects", [])]

    # ── Threat actor profiles ────────────────────────────────────────────────

    def get_threat_actor(self, name: str) -> dict:
        data = self._get("/api/v1/actor/", params={"name__icontains": name, "limit": 5})
        objects = data.get("objects", [])
        return objects[0] if objects else {}

    def get_actor_infrastructure(self, actor_id: int) -> list[Indicator]:
        data = self._get(
            "/api/v2/intelligence/",
            params={"actor_id": actor_id, "limit": 200},
        )
        return [_to_indicator(obj, _detect_type(obj)) for obj in data.get("objects", [])]

    # ── Submission ───────────────────────────────────────────────────────────

    def submit_indicator(
        self,
        value: str,
        ioc_type: NodeType,
        confidence: int = 75,
        tlp: str = "white",
        tags: list[str] | None = None,
        comment: str = "",
    ) -> bool:
        """
        Submit a newly discovered indicator to ThreatStream.
        Use this to contribute your discovered infrastructure back to the platform.
        """
        ts_type = _TYPE_MAP.get(ioc_type)
        if not ts_type:
            return False
        payload = {
            "objects": [{
                "itype": ts_type,
                "value": value,
                "confidence": confidence,
                "tlp": tlp,
                "tags": [{"name": t} for t in (tags or [])],
                "comment": comment,
            }]
        }
        result = self._post("/api/v1/intelligence/", payload)
        return bool(result)

    def submit_infrastructure_cluster(
        self,
        indicators: list[dict],
        source_name: str = "adversary-intel",
    ) -> int:
        """Bulk submit an operator's infrastructure cluster."""
        submitted = 0
        for ind in indicators:
            value = ind.get("value", "")
            ioc_type = ind.get("type", NodeType.IP)
            if value:
                ok = self.submit_indicator(
                    value=value,
                    ioc_type=ioc_type,
                    confidence=ind.get("confidence", 70),
                    tags=ind.get("tags", []) + [source_name],
                )
                if ok:
                    submitted += 1
        return submitted

    # ── Campaign search ──────────────────────────────────────────────────────

    def search_by_jarm(self, jarm: str) -> list[Indicator]:
        data = self._get(
            "/api/v2/intelligence/",
            params={"meta.jarm": jarm, "limit": 100},
        )
        return [_to_indicator(obj, NodeType.IP) for obj in data.get("objects", [])]

    def search_malware_family(self, family: str, limit: int = 200) -> list[Indicator]:
        data = self._get(
            "/api/v2/intelligence/",
            params={"malware_family": family, "limit": limit},
        )
        return [_to_indicator(obj, _detect_type(obj)) for obj in data.get("objects", [])]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _to_indicator(obj: dict, ioc_type: NodeType) -> Indicator:
    return Indicator(
        value=obj.get("value", ""),
        ioc_type=ioc_type,
        confidence=obj.get("confidence", 50),
        tags=[t.get("name", "") for t in obj.get("tags", [])],
        tlp=obj.get("tlp", "white"),
        source="anomali_threatstream",
        first_seen=_dt(obj.get("created_ts")),
        last_seen=_dt(obj.get("modified_ts")),
        malware_families=obj.get("malware_family", []) if isinstance(obj.get("malware_family"), list) else [],
    )


def _detect_type(obj: dict) -> NodeType:
    t = obj.get("type", "ip")
    return {
        "ip": NodeType.IP,
        "domain": NodeType.DOMAIN,
        "md5": NodeType.HASH,
        "sha256": NodeType.HASH,
        "url": NodeType.URL,
        "email": NodeType.EMAIL,
    }.get(t, NodeType.IP)


def _dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
