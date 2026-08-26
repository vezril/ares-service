"""Survey pipeline: parsing + the privacy-preserving scope filter.

The load-bearing assertion is that foreign detail never survives — only counts —
while a foreign AP spoofing our SSID is surfaced (attack on us, not surveillance).
"""

from __future__ import annotations

from ares.config import ScopeConfig
from ares.models import Security
from ares.scope import ScopeGuard
from ares.survey import build_survey, parse_airodump_csv

OWN = "aa:bb:cc:dd:ee:ff"
OWN_CLIENT = "de:ad:be:ef:00:01"

# Two APs (one own, one foreign) + two clients (one own, one foreign), airodump CSV shape.
CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
    "Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:DD:EE:FF, t, t, 6, 130, WPA2, CCMP, PSK, -40, 100, 0, 0.0.0.0, 18, Experimental Neutron, \n"  # noqa: E501
    "99:88:77:66:55:44, t, t, 11, 130, WPA2, CCMP, PSK, -70, 50, 0, 0.0.0.0, 8, Neighbor, \n"
    "\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probes\n"
    "DE:AD:BE:EF:00:01, t, t, -45, 20, AA:BB:CC:DD:EE:FF, \n"
    "CA:FE:CA:FE:CA:FE, t, t, -80, 5, 99:88:77:66:55:44, \n"
)


def _guard() -> ScopeGuard:
    return ScopeGuard(ScopeConfig(own_bssids=[OWN], own_client_macs=[OWN_CLIENT]))


def test_parse_airodump_csv_splits_aps_and_clients() -> None:
    aps, clients = parse_airodump_csv(CSV)
    assert len(aps) == 2
    assert len(clients) == 2
    own = next(ap for ap in aps if ap.bssid == OWN)
    assert own.ssid == "Experimental Neutron"
    assert own.channel == 6
    assert own.security is Security.WPA2


def test_survey_keeps_own_detail_only() -> None:
    aps, clients = parse_airodump_csv(CSV)
    result = build_survey(aps, clients, _guard(), ["Experimental Neutron"])
    assert [ap.bssid for ap in result.own_aps] == [OWN]
    assert [c.mac for c in result.own_clients] == [OWN_CLIENT]


def test_survey_reduces_foreign_to_counts() -> None:
    aps, clients = parse_airodump_csv(CSV)
    result = build_survey(aps, clients, _guard(), ["Experimental Neutron"])
    assert result.foreign_ap_count == 1
    assert result.foreign_client_count == 1
    # No structured foreign detail is exposed anywhere on the result.
    assert not hasattr(result, "foreign_aps")


def test_survey_flags_foreign_ap_spoofing_own_ssid() -> None:
    spoof_csv = CSV.replace(", Neighbor, ", ", Experimental Neutron, ")
    aps, clients = parse_airodump_csv(spoof_csv)
    result = build_survey(aps, clients, _guard(), ["Experimental Neutron"])
    assert result.foreign_ssids_spoofing_own == ["Experimental Neutron"]


def test_survey_channels_seen_counts_own_only() -> None:
    aps, clients = parse_airodump_csv(CSV)
    result = build_survey(aps, clients, _guard(), ["Experimental Neutron"])
    assert result.channels_seen == {6: 1}
