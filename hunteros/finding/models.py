"""Finding data models for HunterOS."""

from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
from typing import Optional
import json
import uuid


class FindingStatus(Enum):
    """Status of a finding."""
    OBSERVED = auto()
    HYPOTHESIS = auto()
    TESTING = auto()
    VALIDATED = auto()
    UNCONFIRMED = auto()
    DUPLICATE = auto()
    REPORTED = auto()
    RESOLVED = auto()

    def label(self) -> str:
        return self.name

    @classmethod
    def from_string(cls, name: str) -> "FindingStatus":
        """Get FindingStatus from string name."""
        for status in cls:
            if status.name == name.upper():
                return status
        return cls.UNCONFIRMED


@dataclass
class Finding:
    """Finding data model."""
    finding_id: str = ""
    title: str = ""
    status: str = "UNCONFIRMED"
    target: str = ""
    endpoint: Optional[str] = None
    vulnerability_class: Optional[str] = None
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    project_id: Optional[str] = None

    def __post_init__(self):
        """Set defaults for new findings."""
        if not self.finding_id:
            self.finding_id = f"HOS-{uuid.uuid4().hex[:4].upper()}"
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "status": self.status,
            "target": self.target,
            "endpoint": self.endpoint,
            "vulnerability_class": self.vulnerability_class,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "project_id": self.project_id,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create Finding from dictionary."""
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "Finding":
        """Create Finding from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def update_status(self, new_status: str) -> None:
        """Update finding status."""
        self.status = new_status
        self.updated_at = datetime.now().isoformat()

    def add_note(self, note: str) -> None:
        """Add a note to the finding."""
        self.notes = (self.notes + "\n" + note).strip()
        self.update()