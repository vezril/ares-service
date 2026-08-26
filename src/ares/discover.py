"""``ares scope discover`` — resolve a configured SSID to candidate own-BSSIDs.

SSID is spoofable, so we never gate on it. Discovery does a passive sweep, finds
every BSSID currently broadcasting one of the operator's ``own_ssids``, and
presents them as *candidates* for the operator to confirm and pin into
``own_bssids``. Ares never auto-trusts a discovered BSSID — a spoofer broadcasts
your SSID too; the human is the gate.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ares.models import AccessPoint


class BssidCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    bssid: str
    ssid: str
    channel: int | None = None
    signal_dbm: int | None = None


class DiscoveryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidates: list[BssidCandidate] = Field(default_factory=list)
    already_pinned: list[str] = Field(default_factory=list)


def find_candidates(
    aps: list[AccessPoint], own_ssids: list[str], already_pinned: list[str]
) -> DiscoveryResult:
    """Candidate BSSIDs = APs broadcasting an own SSID, minus already-pinned.

    Pure over parsed APs so it is testable without a radio.
    """
    names = {s.casefold() for s in own_ssids}
    pinned = {p.casefold() for p in already_pinned}
    candidates = [
        BssidCandidate(bssid=ap.bssid, ssid=ap.ssid, channel=ap.channel, signal_dbm=ap.signal_dbm)
        for ap in aps
        if ap.ssid is not None and ap.ssid.casefold() in names and ap.bssid.casefold() not in pinned
    ]
    return DiscoveryResult(
        candidates=candidates,
        already_pinned=[p for p in already_pinned],
    )
