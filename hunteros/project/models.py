"""Project data models for HunterOS."""

from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Optional
import json
import uuid


@dataclass
class Project:
    """Project data model."""
    project_id: str = ""
    project_name: str = ""
    created_at: str = ""
    updated_at: str = ""
    scope: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    safe_mode: bool = True
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    logs: list[dict] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        """Set defaults for new projects."""
        if not self.project_id:
            self.project_id = uuid.uuid4().hex[:8].upper()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
        if not self.safe_mode:
            self.safe_mode = True  # DEFAULT = ON

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "project_id": self.project_id,
            "project_name": self.project_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "scope": self.scope,
            "policy": self.policy,
            "safe_mode": self.safe_mode,
            "findings": self.findings,
            "evidence": self.evidence,
            "logs": self.logs,
            "description": self.description,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "Project":
        """Create Project from dictionary."""
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "Project":
        """Create Project from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def update(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now().isoformat()

    def add_scope(self, scope: str) -> None:
        """Add a scope entry."""
        if scope not in self.scope:
            self.scope.append(scope)
            self.update()

    def add_finding(self, finding_id: str) -> None:
        """Add a finding ID."""
        if finding_id not in self.findings:
            self.findings.append(finding_id)
            self.update()

    def add_evidence(self, evidence_id: str) -> None:
        """Add an evidence ID."""
        if evidence_id not in self.evidence:
            self.evidence.append(evidence_id)
            self.update()