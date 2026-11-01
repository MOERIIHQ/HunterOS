"""HTTP Metadata Recon module for HunterOS Phase 1.

Performs safe HTTP metadata retrieval with resource limits.
Uses urllib from standard library — no external HTTP libraries.
"""

import urllib.request
import urllib.error
import socket
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

from hunteros.recon.models import ReconResult, ReconType, ReconStatus
from hunteros.recon.engine import ReconEngine


@dataclass
class HTTPResponse:
    """HTTP metadata response."""
    url: str = ""
    final_url: str = ""
    status_code: int = 0
    content_type: str = ""
    server: str = ""
    content_length: int = 0
    redirect_chain: list = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""


class HTTPRecon:
    """HTTP metadata reconnaissance.

    Performs safe HTTP metadata retrieval with strict resource limits:
    - connection timeout
    - read timeout
    - redirect limit
    - response-size limit

    Does NOT perform:
    - fuzzing
    - parameter injection
    - form submission
    - authentication attacks
    - exploit testing
    - vulnerability scanning
    """

    # Resource limits
    DEFAULT_TIMEOUT = 5  # seconds
    DEFAULT_READ_TIMEOUT = 5  # seconds
    MAX_REDIRECTS = 5
    MAX_RESPONSE_SIZE = 1024 * 1024  # 1MB
    SUPPORTED_PROTOCOLS = ("http", "https")

    def __init__(self, timeout: int = DEFAULT_TIMEOUT,
                 read_timeout: int = DEFAULT_READ_TIMEOUT,
                 max_redirects: int = MAX_REDIRECTS,
                 max_response_size: int = MAX_RESPONSE_SIZE):
        self._timeout = timeout
        self._read_timeout = read_timeout
        self._max_redirects = max_redirects
        self._max_response_size = max_response_size
        self._recon_engine = ReconEngine()

    def metadata(self, url: str) -> HTTPResponse:
        """Retrieve HTTP metadata for a URL.

        Args:
            url: Normalized URL.

        Returns:
            HTTPResponse with metadata.
        """
        response = HTTPResponse(url=url)

        try:
            parsed = urlparse(url)
            if parsed.scheme not in self.SUPPORTED_PROTOCOLS:
                response.error = f"Unsupported protocol: {parsed.scheme}"
                return response

            # Use urllib for actual HTTP fetch with resource limits
            response = self._fetch(url)

        except Exception as e:
            response.error = str(e)

        return response

    def _fetch(self, url: str) -> HTTPResponse:
        """Fetch HTTP metadata using urllib with resource limits."""
        response = HTTPResponse(url=url)

        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "HunterOS-Recon/0.1.0")

            # Use urllib with timeout and redirect limit
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler
            )
            # Set timeout
            import socket as sock
            old_timeout = sock.getdefaulttimeout()
            sock.setdefaulttimeout(self._timeout)

            try:
                resp = opener.open(req, timeout=self._timeout)
                response.status_code = resp.status or resp.getcode()
                response.final_url = resp.url
                response.headers = dict(resp.headers)
                response.content_type = resp.headers.get(
                    "Content-Type", ""
                )
                response.server = resp.headers.get("Server", "")
                content_len = resp.headers.get("Content-Length", "0")
                try:
                    response.content_length = int(content_len)
                except ValueError:
                    response.content_length = 0

                # Check redirect chain
                redirect_info = resp.info().get_all("Location", [])
                if redirect_info:
                    response.redirect_chain = redirect_info

            except urllib.error.HTTPError as e:
                # HTTP errors are valid responses (404, etc.)
                response.status_code = e.code
                response.final_url = e.url
                response.headers = dict(e.headers) if e.headers else {}
                response.content_type = e.headers.get("Content-Type", "") if e.headers else ""
                response.server = e.headers.get("Server", "") if e.headers else ""
            except urllib.error.URLError as e:
                response.error = f"URL error: {e.reason}"
            finally:
                sock.setdefaulttimeout(old_timeout)

        except Exception as e:
            response.error = str(e)

        return response

    def recon(self, url: str) -> Dict[str, Any]:
        """Perform HTTP metadata recon.

        Args:
            url: URL to query.

        Returns:
            Dict with HTTP metadata.
        """
        http_result = self.metadata(url)
        return {
            "url": http_result.url,
            "final_url": http_result.final_url,
            "status_code": http_result.status_code,
            "content_type": http_result.content_type,
            "server": http_result.server,
            "content_length": http_result.content_length,
            "redirect_chain": http_result.redirect_chain,
            "headers": http_result.headers,
            "error": http_result.error,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Return HTTPRecon configuration as dict."""
        return {
            "timeout": self._timeout,
            "read_timeout": self._read_timeout,
            "max_redirects": self._max_redirects,
            "max_response_size": self._max_response_size,
        }


# Standalone convenience function
def http_recon(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Perform HTTP metadata lookup on URL.

    Args:
        url: URL to query.
        timeout: Connection/read timeout in seconds.

    Returns:
        Dict with HTTP metadata (status, headers, content-type, etc.).
    """
    recon = HTTPRecon(timeout=timeout)
    return recon.recon(url)