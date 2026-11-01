"""Recon Engine for HunterOS Phase 1.

The Recon Engine is the central orchestration component that:
- Validates targets before security gate
- Integrates with ScopeEngine (Scope Guard)
- Integrates with PolicyEngine
- Integrates with Safe Mode
- Coordinates DNS and HTTP recon operations
- Ensures discovered assets are revalidated before use

Security Flow:
Target Validation → Scope Guard → Policy Engine → Safe Mode → Recon
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
from typing import Optional, Dict, Any, List
import time

from hunteros.core.scope import ScopeEngine, ScopeStatus
from hunteros.core.policy import PolicyEngine, PolicyDecision, ActionType
from hunteros.core.safe_mode import SafeMode
from hunteros.recon.target_validation import TargetValidator, ValidationError
from hunteros.recon.models import Target, ReconResult, ReconStatus as ReconResultStatus, ReconType
from hunteros.recon.asset_inventory import AssetInventory


class ReconOperationType(Enum):
    """Types of recon operations."""
    DNS = auto()
    HTTP = auto()
    ASSET_DISCOVERY = auto()


class ReconEngine:
    """Central reconnaissance engine with security gate integration.

    The ReconEngine does NOT perform any network operations directly.
    It orchestrates the security flow and delegates to specialized
    recon modules (DNSRecon, HTTPRecon).

    Security principle:
    No network request is made before security gate approval.
    """

    def __init__(self, scope_engine: Optional[ScopeEngine] = None,
                 policy_engine: Optional[PolicyEngine] = None,
                 safe_mode: Optional[SafeMode] = None,
                 asset_inventory: Optional[AssetInventory] = None):
        self._scope_engine = scope_engine or ScopeEngine()
        self._policy_engine = policy_engine or PolicyEngine()
        self._safe_mode = safe_mode or SafeMode(enabled=True)
        self._asset_inventory = asset_inventory or AssetInventory()

    def execute(self, target_str: str, recon_type: ReconOperationType) -> ReconResult:
        """Execute a recon operation with full security gate.

        Args:
            target_str: The target string (domain, IP, URL).
            recon_type: The type of recon operation.

        Returns:
            ReconResult with status, data, and any error.

        Security:
            - OUT_OF_SCOPE → BLOCK (no network)
            - UNKNOWN → REVIEW (no network)
            - Policy BLOCK → BLOCK (no network)
            - Safe Mode BLOCK → BLOCK (no network)
            - Only IN_SCOPE + Policy ALLOW + Safe Mode ALLOW → Recon
        """
        start_time = time.time()
        target_str = target_str.strip()

        # Step 0: Target Validation
        try:
            target = TargetValidator.validate(target_str)
        except ValidationError as e:
            return ReconResult(
                target=target_str,
                recon_type=recon_type,
                status=ReconResultStatus.FAILED,
                error=f"Target validation failed: {e}"
            )

        # Step 1: Scope Guard
        scope_result = self._scope_engine.check_target(target.normalized_target)
        if scope_result.status == ScopeStatus.OUT_OF_SCOPE:
            return ReconResult(
                target=target_str,
                recon_type=recon_type,
                status=ReconResultStatus.BLOCKED,
                error="Target is OUT_OF_SCOPE — network request blocked"
            )
        if scope_result.status == ScopeStatus.UNKNOWN:
            return ReconResult(
                target=target_str,
                recon_type=recon_type,
                status=ReconResultStatus.REVIEW,
                error="Target status is UNKNOWN — manual review required"
            )

        # Step 2: Policy Engine
        policy_action = self._map_recon_type_to_action(recon_type)
        policy_result = self._policy_engine.check(target.normalized_target, policy_action)
        if policy_result.decision == PolicyDecision.BLOCK:
            return ReconResult(
                target=target_str,
                recon_type=recon_type,
                status=ReconResultStatus.BLOCKED,
                error=f"Policy blocked: {policy_result.reason}"
            )
        if policy_result.decision == PolicyDecision.REVIEW:
            return ReconResult(
                target=target_str,
                recon_type=recon_type,
                status=ReconResultStatus.REVIEW,
                error=f"Policy requires review: {policy_result.reason}"
            )

        # Step 3: Safe Mode
        if self._safe_mode.is_on():
            safe_check = self._safe_mode.check_action(policy_action)
            if safe_check.decision.name == "BLOCK":
                return ReconResult(
                    target=target_str,
                    recon_type=recon_type,
                    status=ReconResultStatus.BLOCKED,
                    error=f"Safe Mode blocked: {safe_check.reason}"
                )
            if safe_check.decision.name == "REVIEW":
                return ReconResult(
                    target=target_str,
                    recon_type=recon_type,
                    status=ReconResultStatus.REVIEW,
                    error=f"Safe Mode requires review: {safe_check.reason}"
                )

        # All gates passed — proceed to recon
        # Actual network operation is delegated to the caller (DNSRecon, HTTPRecon)
        duration = time.time() - start_time
        return ReconResult(
            target=target_str,
            recon_type=recon_type,
            status=ReconResultStatus.SUCCESS,
            duration=duration,
            error=""
        )

    def execute_with_recon(self, target_str: str, recon_type: ReconOperationType,
                            recon_fn) -> ReconResult:
        """Execute recon with a callback function for the actual network operation.

        Args:
            target_str: The target string.
            recon_type: The recon operation type.
            recon_fn: A callable that takes a normalized target string
                      and returns a dict of results. Must NOT be called
                      if security gates fail.

        Returns:
            ReconResult with the recon data or error.
        """
        # First run through security gates
        result = self.execute(target_str, recon_type)
        if result.status != ReconResultStatus.SUCCESS:
            return result

        # Security gates passed — now perform the actual recon
        target = TargetValidator.validate(target_str)
        try:
            data = recon_fn(target.normalized_target)
            result.data = data
            result.status = ReconResultStatus.SUCCESS
            return result
        except Exception as e:
            result.status = ReconResultStatus.FAILED
            result.error = f"Recon operation failed: {e}"
            return result

    @staticmethod
    def _map_recon_type_to_action(recon_type: ReconOperationType) -> ActionType:
        """Map recon type to PolicyEngine ActionType."""
        mapping = {
            ReconOperationType.DNS: ActionType.READ_ONLY,
            ReconOperationType.HTTP: ActionType.READ_ONLY,
            ReconOperationType.ASSET_DISCOVERY: ActionType.PASSIVE,
        }
        return mapping.get(recon_type, ActionType.READ_ONLY)

    @property
    def scope_engine(self) -> ScopeEngine:
        return self._scope_engine

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def safe_mode(self) -> SafeMode:
        return self._safe_mode

    @property
    def asset_inventory(self) -> AssetInventory:
        return self._asset_inventory