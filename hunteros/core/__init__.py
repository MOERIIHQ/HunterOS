"""Core modules for HunterOS."""
from hunteros.core.config import HunterOSConfig, get_default_config
from hunteros.core.safe_mode import SafeMode, get_safe_mode
from hunteros.core.policy import PolicyEngine, get_policy_engine
from hunteros.core.scope import ScopeEngine, get_scope_engine

__all__ = ["HunterOSConfig", "get_default_config", "SafeMode", "get_safe_mode", "PolicyEngine", "get_policy_engine", "ScopeEngine", "get_scope_engine"]

# Module-level shared instances for CLI and simple usage
_policy_engine: PolicyEngine = None
_scope_engine: ScopeEngine = None

def reset_engines() -> None:
    """Reset all shared engines (for testing).
    
    Resets both ScopeEngine and PolicyEngine singleton state completely.
    After calling this, a new ScopeEngine() or PolicyEngine() call
    will create a fresh instance with clean state.
    """
    global _policy_engine, _scope_engine
    # Reset ScopeEngine singleton completely
    ScopeEngine._instance = None
    ScopeEngine._initialized = False
    # Reset PolicyEngine singleton completely
    PolicyEngine._instance = None
    PolicyEngine._initialized = False
    # Clear module-level references
    _policy_engine = None
    _scope_engine = None
