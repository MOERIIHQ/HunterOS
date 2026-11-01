"""Evidence Manager for HunterOS.

Manages evidence storage structure for findings.
Structure:
projects/
└── <project_name>/
    └── findings/
        └── <finding_id>/
            ├── metadata.json
            ├── notes.md
            └── evidence/
"""

import os
import json
from pathlib import Path
import re
from typing import Optional
from datetime import datetime

from hunteros.evidence.models import EvidenceItem


# Regex for safe names: alphanumeric, hyphens, underscores only
_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')


def _sanitize_name(name: str) -> str:
    """Sanitize and validate a name to prevent path traversal.
    
    Only allows alphanumeric characters, hyphens, and underscores.
    Raises ValueError if the name contains path traversal characters.
    """
    name = name.strip().lower().replace(" ", "_")
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError(
            f"Invalid name '{name}': path traversal characters are not allowed"
        )
    if not _SAFE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid name '{name}': only alphanumeric characters, "
            f"hyphens, and underscores are allowed"
        )
    return name


class EvidenceManager:
    """Manages evidence for findings within a project."""

    def __init__(self, project_name: str, base_path: str = None):
        self._project_name = _sanitize_name(project_name)
        if base_path is None:
            home = os.path.expanduser("~")
            self._base_path = Path(home) / ".hunteros" / "projects" / self._project_name
        else:
            self._base_path = Path(base_path)

    def get_finding_evidence_dir(self, finding_id: str) -> Path:
        """Get the evidence directory for a finding."""
        return self._base_path / "findings" / finding_id / "evidence"

    def create_evidence_structure(self, finding_id: str) -> Path:
        """Create the evidence directory structure for a finding."""
        evidence_dir = self.get_finding_evidence_dir(finding_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return evidence_dir

    def save_metadata(self, finding_id: str, metadata: dict) -> bool:
        """Save finding metadata."""
        finding_dir = self._base_path / "findings" / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)
        meta_path = finding_dir / "metadata.json"
        meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        return True

    def get_metadata(self, finding_id: str) -> Optional[dict]:
        """Get finding metadata."""
        meta_path = self._base_path / "findings" / finding_id / "metadata.json"
        if meta_path.exists():
            try:
                return json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def save_notes(self, finding_id: str, notes: str) -> bool:
        """Save finding notes."""
        finding_dir = self._base_path / "findings" / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)
        notes_path = finding_dir / "notes.md"
        notes_path.write_text(notes, encoding="utf-8")
        return True

    def add_evidence_file(self, finding_id: str, file_path: str,
                          description: str = "") -> bool:
        """Add an evidence file reference."""
        evidence_dir = self.get_finding_evidence_dir(finding_id)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        # Record the file reference
        ref_path = evidence_dir / "files.json"
        refs = []
        if ref_path.exists():
            try:
                refs = json.loads(ref_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        refs.append({
            "path": file_path,
            "description": description,
            "added_at": datetime.now().isoformat(),
        })
        ref_path.write_text(json.dumps(refs, indent=2, ensure_ascii=False), encoding="utf-8")
        return True

    def __repr__(self) -> str:
        return f"EvidenceManager(project={self._project_name})"
