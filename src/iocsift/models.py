"""Data model for a single indicator of compromise."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict


@dataclass
class IOC:
    """One extracted indicator.

    Attributes:
        value: the (re-fanged / canonical) indicator string.
        type:  one of ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve.
        enrichment: arbitrary key/value metadata added by the enrich step.
    """

    value: str
    type: str
    enrichment: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
