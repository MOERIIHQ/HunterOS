"""Target Validation for HunterOS Phase 1.

Validates targets before they reach the Scope Guard.
"""

import re
import ipaddress
from urllib.parse import urlparse
from hunteros.recon.models import Target, TargetType


class ValidationError(Exception):
    """Raised when a target fails validation."""
    pass


# Regex for valid domain names
_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?)*$'
)

# Regex for valid IPv4/IPv6
_IPv4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


class TargetValidator:
    """Validates targets before they enter the security gate.

    Checks:
    - Empty target
    - Malformed target
    - Invalid domain format
    - Invalid IP format
    - Unsupported protocol
    - Path traversal in target
    """

    SUPPORTED_PROTOCOLS = ("http", "https", "")

    @classmethod
    def validate(cls, target: str) -> Target:
        """Validate a target string and return a Target object.

        Raises:
            ValidationError: If target is invalid.
        """
        if not target or not target.strip():
            raise ValidationError("Target cannot be empty")

        target = target.strip()

        # Check for path traversal attempts
        if ".." in target or "\x00" in target:
            raise ValidationError("Target contains path traversal characters")

        # Check for unsupported protocols
        parsed = urlparse(target)
        if parsed.scheme and parsed.scheme not in cls.SUPPORTED_PROTOCOLS:
            raise ValidationError(
                f"Unsupported protocol: {parsed.scheme}. "
                f"Supported: {cls.SUPPORTED_PROTOCOLS}"
            )

        # Extract clean hostname
        hostname = parsed.hostname if parsed.hostname else target
        hostname = hostname.rstrip("/")

        # Determine target type and validate
        target_type = cls._detect_type(hostname)
        normalized = cls._normalize(hostname)

        return Target(
            target=target,
            target_type=target_type,
            normalized_target=normalized,
            source="cli",
        )

    @classmethod
    def _detect_type(cls, hostname: str) -> TargetType:
        """Detect the type of target from hostname."""
        # Check if it's an IP address
        try:
            ipaddress.ip_address(hostname)
            return TargetType.IP
        except ValueError:
            pass

        # Check if it has a scheme-like structure (URL)
        if "/" in hostname or hostname.startswith("http"):
            return TargetType.URL

        # Check if it's a CIDR notation
        if "/" in hostname and "." in hostname:
            try:
                ipaddress.ip_network(hostname, strict=False)
                return TargetType.CIDR
            except ValueError:
                pass

        # Check if it has a dot (subdomain or domain)
        if "." in hostname:
            # Could be subdomain or domain
            parts = hostname.split(".")
            if len(parts) >= 2:
                return TargetType.DOMAIN

        return TargetType.DOMAIN

    @classmethod
    def _normalize(cls, hostname: str) -> str:
        """Normalize hostname for scope matching."""
        hostname = hostname.strip().lower()
        # Remove trailing dot
        hostname = hostname.rstrip(".")
        return hostname

    @classmethod
    def is_valid_domain(cls, hostname: str) -> bool:
        """Check if a hostname is a valid domain format."""
        return bool(_DOMAIN_RE.match(hostname))

    @classmethod
    def is_valid_ip(cls, hostname: str) -> bool:
        """Check if a hostname is a valid IP address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False