"""Storage layer for HunterOS Phase 1 Recon.

Provides simple JSON-based storage for recon results.
Uses project isolation and safe file paths.
"""

import json
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from hunteros.recon.models import ReconResult
from hunteros.project.manager import ProjectManager


_SAFE_NAME_RE = __import__("re").compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')


def _sanitize_name(name: str) -> str:
    """Sanitize storage name to prevent path traversal."""
    name = name.strip().lower().replace(" ", "_")
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError(f"Invalid name: path traversal detected")
    if not _SAFE_NAME_RE.match(name):
        raise ValueError(f"Invalid name: only alphanumeric, hyphens, underscores allowed")
    return name


class ReconStorage:
    """Storage for reconnaissance results.

    Features:
    - JSON/JSONL storage
    - Project isolation
    - Safe file paths
    - Graceful handling of corrupt/missing files
    """

    def __init__(self, storage_path: str = None, project_manager: Optional[ProjectManager] = None):
        self._project_manager = project_manager or ProjectManager()
        if storage_path is None:
            home = os.path.expanduser("~")
            self._storage_path = Path(home) / ".hunteros" / "recon" / "results"
        else:
            self._storage_path = Path(storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)

    def save_result(self, result: ReconResult, project_name: str = "default") -> str:
        """Save a recon result to storage.

        Args:
            result: The ReconResult to save.
            project_name: Project name for isolation.

        Returns:
            The file path where the result was saved.
        """
        safe_project = _sanitize_name(project_name)
        project_dir = self._storage_path / safe_project
        project_dir.mkdir(parents=True, exist_ok=True)

        file_path = project_dir / f"{result.id}.json"
        file_path.write_text(result.to_json(), encoding="utf-8")
        return str(file_path)

    def load_result(self, result_id: str, project_name: str = "default") -> Optional[ReconResult]:
        """Load a recon result from storage.

        Returns None if file is missing or corrupt.
        """
        try:
            safe_project = _sanitize_name(project_name)
        except ValueError:
            return None

        file_path = self._storage_path / safe_project / f"{result_id}.json"
        if not file_path.exists():
            return None

        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            return ReconResult.from_dict(data)
        except (json.JSONDecodeError, Exception):
            return None

    def list_results(self, project_name: str = "default") -> List[ReconResult]:
        """List all recon results for a project."""
        try:
            safe_project = _sanitize_name(project_name)
        except ValueError:
            return []

        project_dir = self._storage_path / safe_project
        if not project_dir.exists():
            return []

        results = []
        for f in project_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                results.append(ReconResult.from_dict(data))
            except (json.JSONDecodeError, Exception):
                continue
        return results

    def save_asset(self, asset_data: Dict[str, Any], project_name: str = "default") -> str:
        """Save asset data to storage."""
        try:
            safe_project = _sanitize_name(project_name)
        except ValueError:
            raise ValueError("Invalid project name")

        project_dir = self._storage_path / safe_project / "assets"
        project_dir.mkdir(parents=True, exist_ok=True)

        # Validate asset_id if provided explicitly; reject invalid IDs
        if "id" in asset_data:
            raw_id = asset_data["id"]
            try:
                asset_id = _sanitize_name(raw_id)
            except ValueError:
                raise ValueError(f"Invalid asset ID: {raw_id}")
        else:
            asset_id = f"ASSET-{uuid.uuid4().hex[:6].upper()}"
        file_path = project_dir / f"{asset_id}.json"
        file_path.write_text(json.dumps(asset_data, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(file_path)

    def load_asset(self, asset_id: str, project_name: str = "default") -> Optional[Dict[str, Any]]:
        """Load asset data from storage."""
        try:
            safe_project = _sanitize_name(project_name)
        except ValueError:
            return None

        file_path = self._storage_path / safe_project / "assets" / f"{asset_id}.json"
        if not file_path.exists():
            return None

        try:
            return json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, Exception):
            return None

    def to_dict(self) -> Dict[str, Any]:
        """Return storage configuration summary."""
        return {"storage_path": str(self._storage_path)}