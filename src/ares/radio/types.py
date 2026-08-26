"""Radio-control types.

A radio is a single exclusive resource with one active mode; multiple radios
form a pool so conflicting modes (recon vs. AP) can run on different cards — the
two-radio shape the active/evil-twin tier needs.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class RadioMode(StrEnum):
    """The exclusive mode a radio is in. Only IDLE/RECON are exercised today;
    CAPTURE/AP are reserved for the active tier."""

    IDLE = "idle"
    RECON = "recon"  # monitor + channel hop
    CAPTURE = "capture"  # monitor + camp/inject
    AP = "ap"  # master / fixed channel


class RadioCapabilities(BaseModel):
    model_config = ConfigDict(frozen=True)

    monitor: bool  # can enter monitor mode (recon/capture)
    injection: bool  # can inject frames (deauth / capture-assist)
    ap: bool  # can run as an access point (rogue AP / evil twin)

    def count(self) -> int:
        """How versatile the radio is — used to keep capable radios free."""
        return int(self.monitor) + int(self.injection) + int(self.ap)


class RadioInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str  # interface name, e.g. "wlan0"
    phy: str  # underlying PHY, e.g. "phy0"
    driver: str  # kernel driver, e.g. "88XXau" / "mt76x2u"
    chipset: str | None = None  # human label if known
    capabilities: RadioCapabilities

    def supports(self, mode: RadioMode) -> bool:
        if mode is RadioMode.IDLE:
            return True
        if mode is RadioMode.AP:
            return self.capabilities.ap
        return self.capabilities.monitor  # RECON / CAPTURE
