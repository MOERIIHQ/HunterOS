"""Scope Engine module for HunterOS.

Determines whether a target is IN_SCOPE, OUT_OF_SCOPE, or UNKNOWN.

Scope matching rules:
- Exact match: target == scope entry → IN_SCOPE
- Wildcard match: *.example.com matches api.example.com → IN_SCOPE
- Subdomain match: if scope is example.com, subdomain api.example.com matches → IN_SCOPE
- No match → OUT_OF_SCOPE or UNKNOWN depending on available information
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List
import ipaddress


class ScopeStatus(Enum):
    """Target scope status."""
    IN_SCOPE = auto()
    OUT_OF_SCOPE = auto()
    UNKNOWN = auto()

    def __str__(self) -> str:
        return self.name

    def label(self) -> str:
        return self.name

    @classmethod
    def from_string(cls, name: str) -> "ScopeStatus":
        """Get ScopeStatus from string name."""
        for status in cls:
            if status.name == name.upper():
                return status
        return cls.UNKNOWN


@dataclass
class ScopeEntry:
    """A single scope entry."""
    pattern: str
    description: str = ""
    is_wildcard: bool = False
    is_domain: bool = False
    is_ip: bool = False

    def __post_init__(self):
        self.is_wildcard = self.pattern.startswith("*")
        self.is_domain = "." in self.pattern and not self.pattern.startswith("*")
        try:
            ipaddress.ip_address(self.pattern.strip())
            self.is_ip = True
        except ValueError:
            self.is_ip = False


@dataclass
class ScopeResult:
    """Result of a scope check."""
    target: str
    status: ScopeStatus
    matched_scope: Optional[str] = None
    reason: str = ""

    def __repr__(self) -> str:
        return f"ScopeResult(target={self.target}, status={self.status.label()})"


_scope_engine_instance: Optional[ScopeEngine] = None

class ScopeEngine:
    """Engine for determining if targets are in scope.

    Scope entries can be:
    - Exact domains: example.com, api.example.com
    - Wildcards: *.example.com
    - IP addresses: 192.168.1.1
    - CIDR ranges: 192.168.0.0/16
    """

    _instance: Optional["ScopeEngine"] = None
    _initialized: bool = False

    def __new__(cls):
        """Singleton pattern: only one ScopeEngine instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._scope_entries: List[ScopeEntry] = []
        self._initialized = True

    def add_scope(self, pattern: str, description: str = "") -> None:
        """Add a scope entry."""
        entry = ScopeEntry(pattern=pattern, description=description)
        self._scope_entries.append(entry)

    def remove_scope(self, pattern: str) -> bool:
        """Remove a scope entry by pattern. Returns True if removed."""
        for i, entry in enumerate(self._scope_entries):
            if entry.pattern == pattern:
                del self._scope_entries[i]
                return True
        return False

    def get_scopes(self) -> List[ScopeEntry]:
        """Get all scope entries."""
        return list(self._scope_entries)

    def clear_scopes(self) -> None:
        """Remove all scope entries and reset singleton state."""
        self._scope_entries.clear()
        ScopeEngine._initialized = False
        ScopeEngine._instance = None

    def has_scopes(self) -> bool:
        """Check if there are any scope entries."""
        return len(self._scope_entries) > 0

    def check_target(self, target: str) -> ScopeResult:
        """Check if a target is in scope.

        Args:
            target: The target to check.

        Returns:
            ScopeResult with status, matched scope, and reason.
        """
        target = target.strip().lower()

        # Empty target
        if not target:
            return ScopeResult(
                target=target,
                status=ScopeStatus.UNKNOWN,
                reason="Empty target"
            )

        # No scopes defined
        if not self.has_scopes():
            return ScopeResult(
                target=target,
                status=ScopeStatus.UNKNOWN,
                reason="No scope entries defined"
            )

        # Check each scope entry
        for entry in self._scope_entries:
            if self._matches(target, entry):
                return ScopeResult(
                    target=target,
                    status=ScopeStatus.IN_SCOPE,
                    matched_scope=entry.pattern,
                    reason=f"Matched scope pattern: {entry.pattern}"
                )

        # Target checked but no match
        return ScopeResult(
            target=target,
            status=ScopeStatus.OUT_OF_SCOPE,
            reason=f"Target '{target}' does not match any scope entry"
        )

    def _matches(self, target: str, entry: ScopeEntry) -> bool:
        """Check if target matches a scope entry."""
        pattern = entry.pattern.lower()

        # IP address exact match
        if entry.is_ip:
            return target == pattern

        # Wildcard matching (*.example.com)
        if entry.is_wildcard:
            parent = pattern[1:]  # Remove leading *, gives e.g. ".example.com"
            if target.endswith(parent) and target != parent:
                return True
            return False

        # Domain/subdomain matching
        if entry.is_domain:
            # Exact match
            if target == pattern:
                return True
            # Subdomain match: api.example.com matches example.com
            if target.endswith(f".{pattern}"):
                return True
            return False

        # CIDR / IP range matching
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(target)
            return addr in network
        except ValueError:
            pass

        return False

    def get_status_string(self, target: str) -> str:
        """Get human-readable scope status for a target."""
        result = self.check_target(target)
        return f"Target '{target}': {result.status.label()} - {result.reason}"

    def __repr__(self) -> str:
        count = len(self._scope_entries)
        return f"ScopeEngine(scopes={count})"


def get_scope_engine() -> ScopeEngine:
    """Get the singleton ScopeEngine."""
    return ScopeEngine()
