"""Own-network posture — the honest self-assessment the console's Posture board
shows.

Pure fusion of what the service already knows: each own AP's survey facts
(channel, security) graded, plus its audit + rogue findings folded in. No new
capture happens here; it reads the survey snapshot and the findings store.
"""

from __future__ import annotations

from ares.http.wire import OwnAccessPoint, PostureItem, WireFinding
from ares.models import Security

# Encryption grade — WPA3 is good, WPA2 acceptable, everything older is weak.
_GRADE = {
    Security.WPA3: "good",
    Security.WPA2: "fair",
    Security.WPA: "weak",
    Security.WEP: "weak",
    Security.OPEN: "weak",
    Security.UNKNOWN: "weak",
}


def _passphrase_status(bssid: str, findings: list[WireFinding]) -> str:
    """weak if an audit cracked it, held if a capture survived, else untested."""
    for f in findings:
        if f.bssid != bssid:
            continue
        if f.kind == "passphrase_weak":
            return "weak"
        if f.kind in ("handshake_captured", "pmkid_captured"):
            return "held"
    return "untested"


def _rogue_spoof(ssid: str | None, findings: list[WireFinding]) -> bool:
    """True if a rogue_ap finding names this SSID (a foreign AP spoofing it)."""
    if ssid is None:
        return False
    return any(f.kind == "rogue_ap" and ssid in f.summary for f in findings)


def build_posture(own_aps: list[OwnAccessPoint], findings: list[WireFinding]) -> list[PostureItem]:
    """One PostureItem per own AP, worst grade first so problems surface."""
    items = [
        PostureItem(
            bssid=ap.bssid,
            ssid=ap.ssid,
            channel=ap.channel,
            band=ap.band,
            security=ap.security,
            security_grade=_GRADE.get(ap.security, "weak"),
            passphrase_status=_passphrase_status(ap.bssid, findings),
            rogue_spoof=_rogue_spoof(ap.ssid, findings),
        )
        for ap in own_aps
    ]
    # Surface weakest posture first: weak passphrase, then rogue, then grade.
    rank = {"weak": 0, "fair": 1, "good": 2}
    items.sort(
        key=lambda p: (
            p.passphrase_status != "weak",
            not p.rogue_spoof,
            rank.get(p.security_grade, 0),
        )
    )
    return items
