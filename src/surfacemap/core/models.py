"""Core data models for SurfaceMap.

Defines the asset types, statuses, and result structures used throughout
the discovery pipeline.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    """Types of assets that can be discovered."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    ASN = "asn"
    IP_RANGE = "ip_range"
    CLOUD_BUCKET = "cloud_bucket"
    EMAIL_SERVER = "email_server"
    EMAIL = "email"
    NAMESERVER = "nameserver"
    CDN = "cdn"
    WAF = "waf"
    CERTIFICATE = "certificate"
    GITHUB_REPO = "github_repo"
    SOCIAL_MEDIA = "social_media"
    URL = "url"
    TECHNOLOGY = "technology"
    SUBSIDIARY = "subsidiary"
    WHOIS_RECORD = "whois_record"
    SENSITIVE_FILE = "sensitive_file"
    API_ENDPOINT = "api_endpoint"
    SECRET_LEAK = "secret_leak"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    COOKIE_ISSUE = "cookie_issue"
    DNS_ISSUE = "dns_issue"


class AssetStatus(str, Enum):
    """Status of a discovered asset."""

    LIVE = "live"
    DOWN = "down"
    REDIRECT = "redirect"
    FILTERED = "filtered"
    UNKNOWN = "unknown"
    TAKEOVER_POSSIBLE = "takeover_possible"
    VULNERABLE = "vulnerable"
    MISCONFIGURED = "misconfigured"


class Severity(str, Enum):
    """Severity classification for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Asset:
    """A single discovered asset in the attack surface."""

    value: str
    type: AssetType
    status: AssetStatus = AssetStatus.UNKNOWN
    parent: str | None = None
    source: str = "manual"
    metadata: dict[str, Any] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    notes: str = ""
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def fingerprint(self) -> str:
        """Generate a unique fingerprint for deduplication."""
        raw = f"{self.type.value}:{self.value}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the asset to a dictionary."""
        return {
            "value": self.value,
            "type": self.type.value,
            "status": self.status.value,
            "parent": self.parent,
            "source": self.source,
            "metadata": self.metadata,
            "technologies": self.technologies,
            "ports": self.ports,
            "ip_addresses": self.ip_addresses,
            "severity": self.severity.value,
            "notes": self.notes,
            "fingerprint": self.fingerprint,
            "discovered_at": self.discovered_at,
        }

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Asset):
            return NotImplemented
        return self.fingerprint == other.fingerprint


class ScanResult:
    """Container for a complete scan's results."""

    def __init__(self, target: str, scan_id: str | None = None) -> None:
        self.target = target
        self.scan_id = scan_id or uuid.uuid4().hex[:12]
        self.assets: list[Asset] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: str | None = None
        self._fingerprints: set[str] = set()
        # Analysis results (populated by LLM analysis phase)
        self.risk_score: int | None = None
        self.risk_grade: str | None = None
        self.executive_summary: str | None = None
        self.attack_paths: list[dict[str, Any]] = []

    def add_asset(self, asset: Asset) -> bool:
        """Add an asset with deduplication. Returns True if new."""
        fp = asset.fingerprint
        if fp in self._fingerprints:
            return False
        self._fingerprints.add(fp)
        self.assets.append(asset)
        return True

    def get_by_type(self, asset_type: AssetType) -> list[Asset]:
        """Get all assets of a given type."""
        return [a for a in self.assets if a.type == asset_type]

    def get_live(self) -> list[Asset]:
        """Get all live assets."""
        return [a for a in self.assets if a.status == AssetStatus.LIVE]

    def get_live_hosts(self) -> list[str]:
        """Get unique live hostnames from URL assets and live domain/subdomain assets."""
        hosts: set[str] = set()
        # Collect hosts from live URLs (HTTP probe results)
        for a in self.assets:
            if a.type == AssetType.URL and a.status in (AssetStatus.LIVE, AssetStatus.REDIRECT):
                host = a.value.split("://", 1)[-1].split("/", 1)[0]
                hosts.add(host)
            elif a.status == AssetStatus.LIVE and a.type in (
                AssetType.DOMAIN, AssetType.SUBDOMAIN,
            ):
                hosts.add(a.value)
        return sorted(hosts)

    def get_by_severity(self, severity: Severity) -> list[Asset]:
        """Get all assets with a given severity."""
        return [a for a in self.assets if a.severity == severity]

    def compute_stats(self) -> dict[str, Any]:
        """Compute summary statistics for this scan."""
        type_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for asset in self.assets:
            type_counts[asset.type.value] = type_counts.get(asset.type.value, 0) + 1
            status_counts[asset.status.value] = status_counts.get(asset.status.value, 0) + 1
            severity_counts[asset.severity.value] = severity_counts.get(asset.severity.value, 0) + 1

        all_technologies: set[str] = set()
        for asset in self.assets:
            all_technologies.update(asset.technologies)

        return {
            "total_assets": len(self.assets),
            "by_type": type_counts,
            "by_status": status_counts,
            "by_severity": severity_counts,
            "unique_technologies": sorted(all_technologies),
            "live_assets": len(self.get_live()),
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
        }

    def mark_complete(self) -> None:
        """Mark the scan as completed."""
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full scan result."""
        data: dict[str, Any] = {
            "target": self.target,
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "stats": self.compute_stats(),
            "assets": [a.to_dict() for a in self.assets],
        }
        if self.risk_score is not None:
            data["risk_score"] = self.risk_score
            data["risk_grade"] = self.risk_grade
        if self.executive_summary:
            data["executive_summary"] = self.executive_summary
        if self.attack_paths:
            data["attack_paths"] = self.attack_paths
        return data
