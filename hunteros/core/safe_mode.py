"""Safe Mode module for HunterOS.

Safe Mode is ON by default. It acts as a global safety constraint
that prevents destructive actions from being executed.

Action types and their Safe Mode behavior:
- READ_ONLY  → ALLOWED
- PASSIVE    → ALLOWED
- ACTIVE     → POLICY DEPENDENT (requires policy + scope checks)
- DESTRUCTIVE → BLOCKED when Safe Mode is ON
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
from datetime import datetime


class ActionType(Enum):
    """Types of actions that can be performed."""
    READ_ONLY = auto()
    PASSIVE = auto()
    ACTIVE = auto()
    DESTRUCTIVE = auto()


class ActionDecision(Enum):
    """Possible decisions from the action system."""
    ALLOW = auto()
    BLOCK = auto()
    REVIEW = auto()


@dataclass
class SafeModeState:
    """Current state of Safe Mode."""
    enabled: bool = True
    action_type: Optional[ActionType] = None
    decision: Optional[ActionDecision] = None
    reason: Optional[str] = None
    checked_at: Optional[str] = None

    def __post_init__(self):
        if self.enabled is None:
            self.enabled = True  # DEFAULT = ON

    def is_safe(self) -> bool:
        """Check if current state is safe."""
        return self.enabled

    def __repr__(self) -> str:
        status = "ON" if self.enabled else "OFF"
        return f"SafeMode(status={status}, action={self.action_type}, decision={self.decision})"


class SafeMode:
    """Safe Mode controller.

    Default state is ON. When Safe Mode is enabled:
    - READ_ONLY actions are always allowed
    - PASSIVE actions are always allowed
    - ACTIVE actions require policy + scope validation
    - DESTRUCTIVE actions are always blocked
    """

    def __init__(self, enabled: bool = True):
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Get Safe Mode status."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        """Set Safe Mode status."""
        self._enabled = value

    def is_on(self) -> bool:
        """Check if Safe Mode is ON."""
        return self._enabled

    def turn_on(self) -> None:
        """Turn Safe Mode ON."""
        self._enabled = True

    def turn_off(self) -> None:
        """Turn Safe Mode OFF."""
        self._enabled = False

    def check_action(self, action_type: ActionType) -> SafeModeState:
        """Check if an action is allowed under current Safe Mode.

        Args:
            action_type: The type of action to check.

        Returns:
            SafeModeState with the decision and reason.
        """
        state = SafeModeState(
            enabled=self._enabled,
            action_type=action_type,
            checked_at=datetime.now().isoformat()
        )

        if not self._enabled:
            # Safe Mode OFF: actions proceed based on policy only
            state.decision = ActionDecision.REVIEW
            state.reason = "Safe Mode OFF - policy review required"
            return state

        # Safe Mode ON - apply restrictions
        if action_type == ActionType.READ_ONLY:
            state.decision = ActionDecision.ALLOW
            state.reason = "READ_ONLY action allowed under Safe Mode"
        elif action_type == ActionType.PASSIVE:
            state.decision = ActionDecision.ALLOW
            state.reason = "PASSIVE action allowed under Safe Mode"
        elif action_type == ActionType.ACTIVE:
            state.decision = ActionDecision.REVIEW
            state.reason = "ACTIVE action requires additional policy and scope validation"
        elif action_type == ActionType.DESTRUCTIVE:
            state.decision = ActionDecision.BLOCK
            state.reason = "DESTRUCTIVE action blocked by Safe Mode"

        return state

    def is_action_allowed(self, action_type: ActionType) -> bool:
        """Quick check if an action type is allowed."""
        state = self.check_action(action_type)
        return state.decision == ActionDecision.ALLOW

    def status_string(self) -> str:
        """Get human-readable Safe Mode status."""
        status = "ON" if self._enabled else "OFF"
        return f"Safe Mode: {status}"

    def __repr__(self) -> str:
        return f"SafeMode(enabled={self._enabled})"


# Module-level default Safe Mode
_default_safe_mode: Optional[SafeMode] = None


def get_safe_mode() -> SafeMode:
    """Get the default Safe Mode singleton."""
    global _default_safe_mode
    if _default_safe_mode is None:
        _default_safe_mode = SafeMode(enabled=True)
    return _default_safe_mode


def set_safe_mode(safe_mode: SafeMode) -> None:
    """Set the default Safe Mode."""
    global _default_safe_mode
    _default_safe_mode = safe_mode