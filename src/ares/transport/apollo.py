"""Apollo client — content-addressed storage for capture blobs (pcap/handshakes).

Captures are big binaries and do not belong on the bus; they go here and a
finding references the returned content address. When no base URL is configured
the client is a no-op that returns ``None`` so passive survey works standalone.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import httpx


class ApolloClient:
    def __init__(self, base_url: str | None, timeout_seconds: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._base_url is not None

    @staticmethod
    def content_address(data: bytes) -> str:
        """The address a blob will have — sha256, matching Apollo's scheme."""
        return "sha256:" + hashlib.sha256(data).hexdigest()

    def put_capture(self, path: Path) -> str | None:
        """Upload a capture file; return its Apollo content address (or None).

        Returns ``None`` when Apollo is not configured — the caller records a
        finding without a capture reference rather than failing the survey.
        """
        data = path.read_bytes()
        addr = self.content_address(data)
        if self._base_url is None:
            return None
        resp = httpx.put(
            f"{self._base_url}/blobs/{addr}",
            content=data,
            timeout=self._timeout,
            headers={"content-type": "application/octet-stream"},
        )
        resp.raise_for_status()
        return addr
