"""`scope discover`: own-SSID BSSIDs become candidates, never auto-trusted."""

from __future__ import annotations

from ares.discover import find_candidates
from ares.models import AccessPoint

OWN_SSID = "Experimental Neutron"


def _ap(bssid: str, ssid: str | None) -> AccessPoint:
    return AccessPoint(bssid=bssid, ssid=ssid, channel=6)


def test_candidates_are_aps_broadcasting_own_ssid() -> None:
    aps = [
        _ap("aa:bb:cc:dd:ee:ff", OWN_SSID),
        _ap("11:22:33:44:55:66", "Neighbor"),
    ]
    result = find_candidates(aps, [OWN_SSID], already_pinned=[])
    assert [c.bssid for c in result.candidates] == ["aa:bb:cc:dd:ee:ff"]


def test_already_pinned_bssid_excluded() -> None:
    aps = [_ap("aa:bb:cc:dd:ee:ff", OWN_SSID)]
    result = find_candidates(aps, [OWN_SSID], already_pinned=["AA:BB:CC:DD:EE:FF"])
    assert result.candidates == []


def test_spoofer_appears_as_candidate_for_human_review() -> None:
    # A spoofer broadcasts our SSID too — it shows up as a candidate precisely so
    # the human, not Ares, decides. Discovery never auto-trusts.
    aps = [_ap("de:ad:de:ad:de:ad", OWN_SSID)]
    result = find_candidates(aps, [OWN_SSID], already_pinned=[])
    assert len(result.candidates) == 1
