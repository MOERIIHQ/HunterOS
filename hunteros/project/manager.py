"""Project Manager for HunterOS.

Manages project lifecycle: create, list, load, delete, info.
Uses JSON files for storage (lightweight, human-readable).
"""

import os
import json
import uuid
from pathlib import Path
import re
from typing import Optional

from hunteros.project.models import Project


# Regex for safe project names: alphanumeric, hyphens, underscores only
_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')


def _sanitize_project_name(name: str) -> str:
    """Sanitize and validate a project name.
    
    Only allows alphanumeric characters, hyphens, and underscores.
    Raises ValueError if the name contains path traversal characters
    or other unsafe patterns.
    """
    name = name.strip().lower().replace(" ", "_")
    # Reject path traversal attempts before any sanitization
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError(
            f"Invalid project name '{name}': path traversal characters are not allowed"
        )
    if not _SAFE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid project name '{name}': only alphanumeric characters, "
            f"hyphens, and underscores are allowed"
        )
    return name


class ProjectManager:
    """Manages HunterOS projects."""

    def __init__(self, storage_path: str = None):
        if storage_path is None:
            # Default: ~/.hunteros/projects/
            home = os.path.expanduser("~")
            storage_path = os.path.join(home, ".hunteros", "projects")
        self._storage_path = Path(storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)

    def _project_file(self, project_name: str) -> Path:
        """Get the file path for a project."""
        safe_name = _sanitize_project_name(project_name)
        return self._storage_path / f"{safe_name}.json"

    def create(self, name: str, description: str = "") -> Project:
        """Create a new project."""
        name = _sanitize_project_name(name)

        # Check if project exists
        if self.exists(name):
            raise ValueError(f"Project '{name}' already exists")

        project = Project(
            project_id=uuid.uuid4().hex[:8].upper(),
            project_name=name,
            description=description,
        )
        self._save(project)
        return project

    def exists(self, name: str) -> bool:
        """Check if a project exists."""
        try:
            safe_name = _sanitize_project_name(name.strip().lower())
        except ValueError:
            return False
        return self._storage_path.joinpath(f"{safe_name}.json").exists()

    def list_projects(self) -> list[Project]:
        """List all projects."""
        projects = []
        for f in self._storage_path.glob("*.json"):
            try:
                project = Project.from_json(f.read_text(encoding="utf-8"))
                projects.append(project)
            except (json.JSONDecodeError, Exception):
                continue
        return sorted(projects, key=lambda p: p.created_at, reverse=True)

    def get(self, name: str) -> Optional[Project]:
        """Get a project by name."""
        try:
            safe_name = _sanitize_project_name(name.strip().lower())
        except ValueError:
            return None
        file_path = self._storage_path / f"{safe_name}.json"
        if not file_path.exists():
            return None
        try:
            return Project.from_json(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, Exception):
            return None

    def delete(self, name: str) -> bool:
        """Delete a project."""
        try:
            safe_name = _sanitize_project_name(name.strip().lower())
        except ValueError:
            return False
        file_path = self._storage_path / f"{safe_name}.json"
        if file_path.exists():
            file_path.unlink()
            return True
        return False

    def save_scope(self, name: str, scope: list[str]) -> bool:
        """Save scope to a project."""
        project = self.get(name)
        if not project:
            return False
        project.scope = scope
        project.update()
        self._save(project)
        return True

    def add_scope_entry(self, name: str, scope: str) -> bool:
        """Add a single scope entry to a project."""
        project = self.get(name)
        if not project:
            return False
        project.add_scope(scope)
        self._save(project)
        return True

    def _save(self, project: Project) -> None:
        """Save project to file."""
        file_path = self._project_file(project.project_name)
        file_path.write_text(project.to_json(), encoding="utf-8")

    def __repr__(self) -> str:
        count = len(self.list_projects())
        return f"ProjectManager(storage={self._storage_path}, projects={count})"
