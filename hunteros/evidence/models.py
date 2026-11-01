"""Evidence data models for HunterOS."""

from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
from typing import Optional
import json
import uuid


class EvidenceType(Enum):
    """Types of evidence."""
    NOTE = auto()
    SCREENSHOT = auto()
    HTTP_RESPONSE = auto()
    LOG = auto()
    DOCUMENT = auto()
    RAW_DATA = auto()

    def label(self) -> str:
        return self.name


@dataclass
class EvidenceItem:
    """Evidence item data model."""
    evidence_id: str = ""
    project_id: str = ""
    finding_id: Optional[str] = None
    evidence_type: str = "NOTE"
    title: str = ""
    description: str = ""
    file_path: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = f"EV-{uuid.uuid4().hex[:4].upper()}"
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "project_id": self.project_id,
            "finding_id": self.finding_id,
            "evidence_type": self.evidence_type,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceItem":
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceItem":
        return cls.from_dict(json.loads(json_str))

    def update(self) -> None:
        self.updated_at = datetime.now().isoformat()

    def set_metadata(self, key: str, value) -> None:
        self.metadata[key] = value
        self.update()