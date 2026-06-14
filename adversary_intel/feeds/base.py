"""Abstract base class for all threat feed integrations."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from adversary_intel.models import Indicator, NodeType


class ThreatFeed(ABC):
    name: str = "base"

    @abstractmethod
    def check_indicator(self, value: str, ioc_type: NodeType) -> Optional[Indicator]:
        """Look up a single indicator. Returns None if not found."""

    @abstractmethod
    def get_recent(self, limit: int = 100) -> list[Indicator]:
        """Fetch the most recent indicators from this feed."""

    def is_available(self) -> bool:
        """Return True if this feed's API credentials are configured."""
        return True

    def bulk_check(self, values: list[str], ioc_type: NodeType) -> list[Indicator]:
        results = []
        for v in values:
            indicator = self.check_indicator(v, ioc_type)
            if indicator:
                results.append(indicator)
        return results
