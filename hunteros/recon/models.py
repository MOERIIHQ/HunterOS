"""Recon models for HunterOS Phase 1."""
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from datetime import datetime
from typing import Optional, Dict, Any
import json
import uuid


class TargetType(Enum):
    """Types of recon targets."""
    DOMAIN = auto()
    IP = auto()
    URL = auto()
    SUBDOMAIN = auto()
    CIDR = auto()

    @classmethod
    def from_string(cls, name: str) -> "TargetType":
        for t in cls:
            if t.name == name.upper():
                return t
        return cls.DOMAIN


class ReconType(Enum):
    """Types of reconnaissance operations."""
    DNS = auto()
    HTTP = auto()
    ASSET_DISCOVERY = auto()

    def label(self) -> str:
        return self.name


class ReconStatus(Enum):
    """Recon operation status."""
    SUCCESS = auto()
    FAILED = auto()
    BLOCKED = auto()
    REVIEW = auto()

    def label(self) -> str:
        return self.name


@dataclass
class Target:
    """Represents a recon target before security gate."""
    target: str
    target_type: TargetType = TargetType.DOMAIN
    normalized_target: str = ""
    source: str = "cli"
    timestamp: str = ""

    def __post_init__(self):
        if not self.normalized_target:
            self.normalized_target = self._normalize(self.target)
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @staticmethod
    def _normalize(target: str) -> str:
        """Normalize target: strip whitespace, lowercase, remove protocol."""
        t = target.strip().lower()
        # Remove protocol prefix
        for proto in ("https://", "http://"):
            if t.startswith(proto):
                t = t[len(proto):]
        # Remove trailing slash
        t = t.rstrip("/")
        return t

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        data.setdefault("target_type", TargetType.DOMAIN.value)
        return cls(**data)


@dataclass
class ReconResult:
    """Result of a reconnaissance operation."""
    id: str = ""
    target: str = ""
    recon_type: ReconType = ReconType.DNS
    status: ReconStatus = ReconStatus.FAILED
    timestamp: str = ""
    duration: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"RECON-{uuid.uuid4().hex[:6].upper()}"
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["recon_type"] = self.recon_type.value if self.recon_type else ""
        d["status"] = self.status.value if self.status else ""
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class Asset:
    """Discovered asset that must be revalidated before use."""
    id: str = ""
    target: str = ""
    asset_type: str = "domain"
    source: str = ""
    discovered_at: str = ""
    status: str = "pending_validation"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = f"ASSET-{uuid.uuid4().hex[:6].upper()}"
        if not self.discovered_at:
            self.discovered_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def mark_validated(self) -> None:
        self.status = "validated"

    def mark_pending(self) -> None:
        self.status = "pending_validation"