"""Configuration module for HunterOS.

Default configuration:
- language = id (Indonesian)
- safe_mode = true (ON by default)
- logging = true
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class HunterOSConfig:
    """HunterOS application configuration."""

    language: str = "id"
    safe_mode: bool = True
    logging_enabled: bool = True
    project_root: Optional[str] = None
    storage_path: Optional[str] = None
    debug_mode: bool = False

    # Derived fields
    _config_path: Optional[str] = None

    def __post_init__(self):
        """Ensure defaults are applied correctly."""
        if self.safe_mode is None:
            self.safe_mode = True  # DEFAULT = ON

    @classmethod
    def default(cls) -> "HunterOSConfig":
        """Return default configuration."""
        return cls()

    @classmethod
    def from_dict(cls, data: dict) -> "HunterOSConfig":
        """Create configuration from dictionary."""
        return cls(**data)

    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert configuration to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "HunterOSConfig":
        """Create configuration from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def save(self, path: str) -> None:
        """Save configuration to file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        self._config_path = path

    def load(self, path: str) -> "HunterOSConfig":
        """Load configuration from file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        config = self.from_dict(data)
        config._config_path = path
        return config

    def is_safe_mode(self) -> bool:
        """Check if Safe Mode is ON."""
        return self.safe_mode

    def enable_safe_mode(self) -> None:
        """Enable Safe Mode."""
        self.safe_mode = True

    def disable_safe_mode(self) -> None:
        """Disable Safe Mode."""
        self.safe_mode = False

    def validate(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []
        if not self.language:
            issues.append("language is empty")
        if self.language not in ("id", "en"):
            issues.append(f"language '{self.language}' may not be supported")
        return issues


# Module-level default configuration
_default_config: Optional[HunterOSConfig] = None


def get_default_config() -> HunterOSConfig:
    """Get the default configuration singleton."""
    global _default_config
    if _default_config is None:
        _default_config = HunterOSConfig.default()
    return _default_config


def set_default_config(config: HunterOSConfig) -> None:
    """Set the default configuration."""
    global _default_config
    _default_config = config