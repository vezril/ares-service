"""Scope configuration — the operator's declared own-network identity.

The config carries the SSID as a *human handle* (spoofable, used only for
discovery) and the BSSID/MAC allowlists as the *trust anchors* (what active
actions actually gate on). Loaded from a TOML file; the resolved own-BSSID set
is what ``ares.scope`` enforces.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

from ares.models import MacAddress

DEFAULT_CONFIG_PATH = Path("scope.local.toml")


class TransportConfig(BaseModel):
    """Where findings and captures go. Empty base URLs = emit disabled (log only)."""

    hermes_base_url: str | None = None
    apollo_base_url: str | None = None
    timeout_seconds: float = 10.0


class ActiveConfig(BaseModel):
    """Active-tier switches. Default OFF is not a default we relax casually."""

    enabled: bool = False
    require_confirmation: bool = True


class ScopeConfig(BaseModel):
    """The scope file.

    ``own_ssids`` is the human handle for discovery; ``own_bssids`` +
    ``own_client_macs`` are the enforced allowlists. A freshly seeded config has
    an SSID but an empty BSSID list — ``ares scope discover`` populates it and
    the operator pins it. Active actions refuse to run against an empty
    allowlist regardless of SSID.
    """

    own_ssids: list[str] = Field(default_factory=lambda: ["Experimental Neutron"])
    own_bssids: list[MacAddress] = Field(default_factory=list)
    own_client_macs: list[MacAddress] = Field(default_factory=list)
    interface: str = "wlan0"
    active: ActiveConfig = Field(default_factory=ActiveConfig)
    transport: TransportConfig = Field(default_factory=TransportConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> ScopeConfig:
        path = path or DEFAULT_CONFIG_PATH
        if not path.exists():
            raise FileNotFoundError(
                f"scope config not found at {path}. Copy scope.example.toml and edit it, "
                "then run `ares scope discover` to populate own_bssids."
            )
        data = tomllib.loads(path.read_text())
        return cls.model_validate(data)
