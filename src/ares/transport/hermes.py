"""Hermes client — emits ``security.wifi.finding`` events to the bus.

The event schema is coordinated with the HermesMQ session; keep the topic and
payload shape in sync with them before changing it. When no base URL is
configured the client logs the finding locally instead of emitting, so Ares runs
fully offline during bring-up.
"""

from __future__ import annotations

import json
import logging

import httpx

from ares.models import Finding

log = logging.getLogger("ares.hermes")

FINDING_TOPIC = "security.wifi.finding"


class HermesClient:
    def __init__(self, base_url: str | None, timeout_seconds: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout_seconds

    @property
    def enabled(self) -> bool:
        return self._base_url is not None

    def emit(self, finding: Finding) -> bool:
        """Publish a finding. Returns True if sent, False if only logged.

        A disabled transport is not an error — it is the offline default. Raises
        only on an actual HTTP failure when a base URL *is* configured.
        """
        payload = {"topic": FINDING_TOPIC, "data": finding.model_dump(mode="json")}
        if self._base_url is None:
            log.info("finding (transport disabled): %s", json.dumps(payload["data"]))
            return False
        resp = httpx.post(
            f"{self._base_url}/publish/{FINDING_TOPIC}",
            json=payload,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return True
