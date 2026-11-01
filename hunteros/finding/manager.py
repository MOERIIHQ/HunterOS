"""Finding Manager for HunterOS.

Manages finding creation, listing, status updates, and persistence.
"""

import os
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

from hunteros.finding.models import Finding, FindingStatus


class FindingManager:
    """Manages security findings within a project."""

    def __init__(self, project_name: str, storage_path: str = None):
        self._project_name = project_name
        if storage_path is None:
            home = os.path.expanduser("~")
            self._storage_path = Path(home) / ".hunteros" / "projects" / project_name / "findings"
        else:
            self._storage_path = Path(storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)

    def create_finding(self, title: str, target: str,
                       vulnerability_class: str = None,
                       endpoint: str = None,
                       notes: str = "") -> Finding:
        """Create a new finding."""
        finding = Finding(
            finding_id=f"HOS-{datetime.now().strftime('%Y%m%d')}-{len(self._list_files()) + 1:03d}",
            title=title,
            status=FindingStatus.UNCONFIRMED.name,
            target=target,
            endpoint=endpoint,
            vulnerability_class=vulnerability_class,
            notes=notes,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            project_id=self._project_name,
        )
        self._save(finding)
        return finding

    def list_findings(self) -> list[Finding]:
        """List all findings in the project."""
        findings = []
        for f in self._storage_path.glob("*.json"):
            try:
                finding = Finding.from_json(f.read_text(encoding="utf-8"))
                findings.append(finding)
            except Exception:
                continue
        return sorted(findings, key=lambda f: f.created_at)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID."""
        for finding in self.list_findings():
            if finding.finding_id == finding_id:
                return finding
        return None

    def update_status(self, finding_id: str, new_status: str) -> bool:
        """Update finding status."""
        finding = self.get_finding(finding_id)
        if finding:
            finding.update_status(new_status)
            self._save(finding)
            return True
        return False

    def _save(self, finding: Finding) -> None:
        """Save finding to file."""
        file_path = self._storage_path / f"{finding.finding_id}.json"
        file_path.write_text(finding.to_json(), encoding="utf-8")

    def _list_files(self) -> list:
        """List files in findings directory."""
        return list(self._storage_path.glob("*.json"))

    def __repr__(self) -> str:
        count = len(self.list_findings())
        return f"FindingManager(project={self._project_name}, findings={count})"