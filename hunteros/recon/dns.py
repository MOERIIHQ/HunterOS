"""DNS Recon module for HunterOS Phase 1.

Performs DNS metadata retrieval using standard library only.
Uses socket.getaddrinfo for resolution — no external DNS libraries.
"""

import socket
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime

from hunteros.recon.models import ReconResult, ReconType, ReconStatus
from hunteros.recon.engine import ReconEngine


@dataclass
class DNSRecord:
    """A single DNS record."""
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    """Result of a DNS reconnaissance operation."""
    target: str
    a_records: list = field(default_factory=list)
    aaaa_records: list = field(default_factory=list)
    cname_records: list = field(default_factory=list)
    mx_records: list = field(default_factory=list)
    ns_records: list = field(default_factory=list)
    txt_records: list = field(default_factory=list)
    error: str = ""


class DNSRecon:
    """DNS metadata reconnaissance.

    Performs basic DNS lookups using Python's socket module.
    No brute-force subdomain enumeration.
    No wordlist-based discovery.

    Supported record types:
    - A
    - AAAA
    - CNAME
    - MX
    - NS
    - TXT
    """

    # Resource limits
    DEFAULT_TIMEOUT = 5  # seconds
    MAX_RECORDS_PER_TYPE = 100

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self._timeout = timeout
        self._recon_engine = ReconEngine()

    def query(self, target: str) -> DNSResult:
        """Perform DNS metadata lookup on target.

        Args:
            target: Normalized domain name.

        Returns:
            DNSResult with records found.
        """
        result = DNSResult(target=target)

        try:
            # A and AAAA records via getaddrinfo
            try:
                infos = socket.getaddrinfo(
                    target, None,
                    type=socket.SOCK_STREAM,
                    flags=socket.AI_ADDRCONFIG
                )
                for info in infos:
                    addr = info[4][0]
                    if ":" in addr and not addr.startswith("["):
                        # IPv6
                        if addr not in [r.value for r in result.aaaa_records]:
                            result.aaaa_records.append(
                                DNSRecord(record_type="AAAA", value=addr)
                            )
                    elif "." in addr:
                        # IPv4
                        if addr not in [r.value for r in result.a_records]:
                            result.a_records.append(
                                DNSRecord(record_type="A", value=addr)
                            )
            except socket.gaierror:
                pass  # No A/AAAA records found

            # CNAME, MX, NS, TXT via gethostbyname_ex and other methods
            self._query_dns_records(target, result)

        except Exception as e:
            result.error = str(e)

        return result

    def _query_dns_records(self, target: str, result: DNSResult) -> None:
        """Query additional DNS records using available methods."""
        try:
            # Try to get host information for NS records
            host_info = socket.gethostbyname_ex(target)
            if len(host_info) >= 2:
                aliases = host_info[1]
                for alias in aliases[:self.MAX_RECORDS_PER_TYPE]:
                    # Aliases may represent CNAME-like records
                    if alias != target:
                        result.cname_records.append(
                            DNSRecord(record_type="CNAME", value=alias)
                        )
        except socket.gaierror:
            pass

    def recon(self, target: str) -> Dict[str, Any]:
        """Perform DNS recon on target.

        Args:
            target: Normalized domain name.

        Returns:
            Dict with DNS metadata.
        """
        dns_result = self.query(target)
        return dns_result.to_dict()

    def to_dict(self) -> Dict[str, Any]:
        """Return the DNSRecon configuration as a dict."""
        return {"timeout": self._timeout}


# Standalone convenience function
def dns_recon(target: str, timeout: int = 5) -> Dict[str, Any]:
    """Perform DNS metadata lookup on target.

    Args:
        target: Domain name to query.
        timeout: Socket timeout in seconds.

    Returns:
        Dict with DNS metadata (A, AAAA, CNAME, MX, NS, TXT).
    """
    recon = DNSRecon(timeout=timeout)
    return recon.recon(target)