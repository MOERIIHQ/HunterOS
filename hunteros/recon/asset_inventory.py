"""Asset Inventory for HunterOS Phase 1.

Manages discovered assets with mandatory revalidation before use.
Discovered assets must pass through the security gate again
before being used as targets for operations.

Security Principle: DISCOVERED ≠ AUTHORIZED
"""

import json
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

from hunteros.recon.models import Asset, Target
from hunteros.recon.target_validation import TargetValidator
from hunteros.core.scope import ScopeEngine, ScopeStatus
from hunteros.core.policy import PolicyEngine, PolicyDecision, ActionType
from hunteros.core.safe_mode import SafeMode


class AssetInventory:
    """Stores and manages discovered assets.

    Key security principle:
    Assets discovered by HunterOS are NOT automatically authorized.
    Before using a discovered asset as a target for operations,
    it must pass through Target Validation → Scope Guard → Policy → Safe Mode.
    """

    def __init__(self, storage_path: str = None):
        if storage_path is None:
            home = os.path.expanduser("~")
            self._storage_path = Path(home) / ".hunteros" / "recon" / "assets"
        else:
            self._storage_path = Path(storage_path)
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._assets: Dict[str, Asset] = {}

    def add_asset(self, target: str, asset_type: str = "domain",
                   source: str = "", metadata: Dict[str, Any] = None) -> Asset:
        """Add a discovered asset.

        Note: Adding an asset does NOT authorize it.
        The asset status will be 'pending_validation'.
        """
        asset = Asset(
            target=target,
            asset_type=asset_type,
            source=source,
            metadata=metadata or {}
        )
        self._assets[asset.id] = asset
        self._save_asset(asset)
        return asset

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get an asset by ID."""
        return self._assets.get(asset_id)

    def list_assets(self, status: Optional[str] = None) -> List[Asset]:
        """List all assets, optionally filtered by status."""
        if status:
            return [a for a in self._assets.values() if a.status == status]
        return list(self._assets.values())

    def validate_asset(self, asset_id: str, scope_engine: Optional[ScopeEngine] = None,
                        policy_engine: Optional[PolicyEngine] = None,
                        safe_mode: Optional[SafeMode] = None) -> bool:
        """Validate a discovered asset through the security gate.

        This implements the DISCOVER ≠ AUTHORIZED principle.

        Args:
            asset_id: The ID of the asset to validate.
            scope_engine: ScopeEngine instance for scope check.
            policy_engine: PolicyEngine instance for policy check.
            safe_mode: SafeMode instance for safety check.

        Returns:
            True if the asset is authorized for use, False otherwise.
        """
        asset = self._assets.get(asset_id)
        if not asset:
            return False

        if asset.status == "validated":
            return True

        # Revalidate through security gate
        scope_engine = scope_engine or ScopeEngine()
        policy_engine = policy_engine or PolicyEngine()
        safe_mode = safe_mode or SafeMode(enabled=True)

        try:
            target_obj = TargetValidator.validate(asset.target)
        except Exception:
            asset.status = "validation_failed"
            return False

        # Scope check
        scope_result = scope_engine.check_target(target_obj.normalized_target)
        if scope_result.status != ScopeStatus.IN_SCOPE:
            asset.status = "out_of_scope"
            return False

        # Policy check — use READ_ONLY action type for asset validation
        policy_result = policy_engine.check(
            target_obj.normalized_target,
            ActionType.READ_ONLY
        )

        # Policy decision must be ALLOW for asset to be authorized
        if policy_result.decision != PolicyDecision.ALLOW:
            if policy_result.decision == PolicyDecision.BLOCK:
                asset.status = "policy_blocked"
            else:
                asset.status = "pending_review"
            return False

        # Safe Mode check
        if safe_mode.is_on():
            safe_decision = safe_mode.check_action(ActionType.READ_ONLY)
            if safe_decision.decision.name == "BLOCK":
                asset.status = "safe_mode_blocked"
                return False

        asset.mark_validated()
        self._save_asset(asset)
        return True

    def mark_pending(self, asset_id: str) -> None:
        """Mark asset as pending validation."""
        asset = self._assets.get(asset_id)
        if asset:
            asset.mark_pending()
            self._save_asset(asset)

    def remove_asset(self, asset_id: str) -> bool:
        """Remove an asset by ID."""
        if asset_id in self._assets:
            del self._assets[asset_id]
            return True
        return False

    def _save_asset(self, asset: Asset) -> None:
        """Save asset to JSON file."""
        file_path = self._storage_path / f"{asset.id}.json"
        file_path.write_text(asset.to_json(), encoding="utf-8")

    def _load_asset(self, asset_id: str) -> Optional[Asset]:
        """Load asset from JSON file."""
        file_path = self._storage_path / f"{asset_id}.json"
        if file_path.exists():
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                return Asset.from_dict(data)
            except (json.JSONDecodeError, Exception):
                return None
        return None

    def load_all(self) -> None:
        """Load all assets from storage."""
        for f in self._storage_path.glob("*.json"):
            try:
                asset = Asset.from_dict(json.loads(f.read_text(encoding="utf-8")))
                self._assets[asset.id] = asset
            except (json.JSONDecodeError, Exception):
                continue

    def to_dict(self) -> Dict[str, Any]:
        """Return asset inventory summary."""
        return {
            "total_assets": len(self._assets),
            "validated": len([a for a in self._assets.values() if a.status == "validated"]),
            "pending": len([a for a in self._assets.values() if a.status == "pending_validation"]),
            "out_of_scope": len([a for a in self._assets.values() if a.status == "out_of_scope"]),
        }