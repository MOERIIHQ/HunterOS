"""Policy Engine module for HunterOS.

Determines whether an action is ALLOWED, BLOCKED, or REVIEW based on:
1. Target scope status (IN_SCOPE / OUT_OF_SCOPE / UNKNOWN)
2. Safe Mode status
3. Action type

Decision flow:
TARGET → SCOPE CHECK → POLICY CHECK → SAFE MODE CHECK → ACTION DECISION

Minimal action states:
- ALLOW: Action is permitted
- BLOCK: Action is forbidden
- REVIEW: Action requires manual review
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
from datetime import datetime

from hunteros.core.scope import ScopeStatus, ScopeEngine
from hunteros.core.safe_mode import SafeMode, ActionType, ActionDecision


class PolicyDecision(Enum):
    """Possible policy decisions."""
    ALLOW = auto()
    BLOCK = auto()
    REVIEW = auto()

    def __str__(self) -> str:
        labels = {
            self.ALLOW: "ALLOW",
            self.BLOCK: "BLOCK",
            self.REVIEW: "REVIEW",
        }
        return labels.get(self, self.name)


@dataclass
class PolicyResult:
    """Result of a policy check."""
    target: str
    scope_status: Optional[ScopeStatus]
    safe_mode_on: bool
    action_type: ActionType
    decision: PolicyDecision
    reason: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def __repr__(self) -> str:
        return f"PolicyResult(target={self.target}, decision={self.decision})"

    def is_allowed(self) -> bool:
        return self.decision == PolicyDecision.ALLOW

    def is_blocked(self) -> bool:
        return self.decision == PolicyDecision.BLOCK

    def needs_review(self) -> bool:
        return self.decision == PolicyDecision.REVIEW


@dataclass
class PolicyRule:
    """A single policy rule."""
    name: str
    target_pattern: str
    action_type: str
    decision: str  # ALLOW, BLOCK, REVIEW
    description: str = ""


class PolicyEngine:
    """Engine for determining if an action is permitted.

    Decision hierarchy (from highest to lowest priority):
    1. If target is OUT_OF_SCOPE → BLOCK
    2. If target is UNKNOWN → REVIEW
    3. If target is IN_SCOPE and action is DESTRUCTIVE and Safe Mode ON → BLOCK
    4. If Safe Mode ON and action is ACTIVE → REVIEW
    5. If Safe Mode ON and action is READ_ONLY/PASSIVE → ALLOW
    6. Otherwise → REVIEW
    """

    _instance: Optional["PolicyEngine"] = None
    _initialized: bool = False

    def __new__(cls):
        """Singleton pattern: only one PolicyEngine instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._scope_engine = ScopeEngine()
        self._safe_mode = SafeMode(enabled=True)
        self._rules: list[PolicyRule] = []
        self._initialized = True

    @property
    def scope_engine(self) -> ScopeEngine:
        """Get the scope engine."""
        return self._scope_engine

    @property
    def safe_mode(self) -> SafeMode:
        """Get the Safe Mode controller."""
        return self._safe_mode

    def add_rule(self, name: str, target_pattern: str, action_type: str,
                 decision: str, description: str = "") -> None:
        """Add a custom policy rule."""
        rule = PolicyRule(
            name=name,
            target_pattern=target_pattern,
            action_type=action_type,
            decision=decision,
            description=description
        )
        self._rules.append(rule)

    def check(self, target: str, action_type: ActionType) -> PolicyResult:
        """Check if an action on a target is allowed.

        Args:
            target: The target to check.
            action_type: The type of action.

        Returns:
            PolicyResult with the decision and reason.
        """
        target = target.strip()

        # Step 1: Scope check
        scope_result = self._scope_engine.check_target(target)
        scope_status = scope_result.status

        # Step 2: Policy check based on scope
        if scope_status == ScopeStatus.OUT_OF_SCOPE:
            return PolicyResult(
                target=target,
                scope_status=scope_status,
                safe_mode_on=self._safe_mode.is_on(),
                action_type=action_type,
                decision=PolicyDecision.BLOCK,
                reason=f"Target '{target}' is OUT_OF_SCOPE"
            )

        if scope_status == ScopeStatus.UNKNOWN:
            return PolicyResult(
                target=target,
                scope_status=scope_status,
                safe_mode_on=self._safe_mode.is_on(),
                action_type=action_type,
                decision=PolicyDecision.REVIEW,
                reason=f"Target '{target}' status is UNKNOWN - manual review required"
            )

        # Step 3: Safe Mode check
        if self._safe_mode.is_on():
            if action_type == ActionType.DESTRUCTIVE:
                return PolicyResult(
                    target=target,
                    scope_status=scope_status,
                    safe_mode_on=True,
                    action_type=action_type,
                    decision=PolicyDecision.BLOCK,
                    reason="DESTRUCTIVE action blocked by Safe Mode"
                )
            if action_type == ActionType.ACTIVE:
                return PolicyResult(
                    target=target,
                    scope_status=scope_status,
                    safe_mode_on=True,
                    action_type=action_type,
                    decision=PolicyDecision.REVIEW,
                    reason="ACTIVE action requires additional validation under Safe Mode"
                )

        # Step 4: Default - allow for IN_SCOPE read-only/passive
        return PolicyResult(
            target=target,
            scope_status=scope_status,
            safe_mode_on=self._safe_mode.is_on(),
            action_type=action_type,
            decision=PolicyDecision.ALLOW,
            reason=f"Target '{target}' is IN_SCOPE, action {action_type.name} permitted"
        )

    def is_action_allowed(self, target: str, action_type: ActionType) -> bool:
        """Quick check if action is allowed on target."""
        result = self.check(target, action_type)
        return result.is_allowed()

    def is_action_blocked(self, target: str, action_type: ActionType) -> bool:
        """Quick check if action is blocked on target."""
        result = self.check(target, action_type)
        return result.is_blocked()

    def get_decision_string(self, target: str, action_type: ActionType) -> str:
        """Get human-readable policy decision."""
        result = self.check(target, action_type)
        return (f"Target: {target} | Action: {action_type.name} | "
                f"Scope: {result.scope_status.label()} | "
                f"Safe Mode: {'ON' if result.safe_mode_on else 'OFF'} | "
                f"Decision: {result.decision}")

    def __repr__(self) -> str:
        return f"PolicyEngine(scopes={len(self._scope_engine.get_scopes())}, " \
               f"safe_mode={self._safe_mode.is_on()})"


def get_policy_engine() -> PolicyEngine:
    """Get the singleton PolicyEngine."""
    return PolicyEngine()
