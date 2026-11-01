"""HunterOS - Personal Bug Hunter Research, Learning & Disclosure Framework."""

__version__ = "0.1.0"
__project__ = "HunterOS"

from hunteros.core.config import HunterOSConfig
from hunteros.core.safe_mode import SafeMode

__all__ = ["HunterOSConfig", "SafeMode"]