"""Posture fusion: survey facts + findings → per-AP self-assessment."""

from __future__ import annotations

from starlette.testclient import TestClient

from ares.config import ScopeConfig
from ares.http.app import create_app
from ares.http.findings import FindingsStore
from ares.http.posture import build_posture
from ares.http.source import MockSurveySource
from ares.http.wire import OwnAccessPoint, WireFinding


def _ap(bssid: str, security: str, ssid: str = "Experimental Neutron") -> OwnAccessPoint:
    return OwnAccessPoint(
        bssid=bssid,
        ssid=ssid,
        channel=6,
        band="2.4GHz",
        security=security,  # type: ignore[arg-type]
        signal_dbm=-45,
        client_count=0,
        first_seen="2026-08-26T09:00:00Z",
        last_seen="2026-08-26T09:00:00Z",
    )


def _finding(kind: str, bssid: str | None, summary: str = "") -> WireFinding:
    return WireFinding(
        id="x", at="2026-08-26T09:00:00Z", kind=kind, severity="high", summary=summary, bssid=bssid
    )


class TestGrade:
    def test_wpa3_is_good_wpa2_fair_open_weak(self) -> None:
        aps = [_ap("aa:bb:cc:dd:ee:f0", "wpa3"), _ap("aa:bb:cc:dd:ee:f1", "open")]
        grades = {p.bssid: p.security_grade for p in build_posture(aps, [])}
        assert grades["aa:bb:cc:dd:ee:f0"] == "good"
        assert grades["aa:bb:cc:dd:ee:f1"] == "weak"


class TestPassphraseStatus:
    def test_weak_when_cracked(self) -> None:
        ap = _ap("aa:bb:cc:dd:ee:f0", "wpa2")
        f = _finding("passphrase_weak", "aa:bb:cc:dd:ee:f0")
        assert build_posture([ap], [f])[0].passphrase_status == "weak"

    def test_held_when_capture_survived(self) -> None:
        ap = _ap("aa:bb:cc:dd:ee:f0", "wpa3")
        f = _finding("handshake_captured", "aa:bb:cc:dd:ee:f0")
        assert build_posture([ap], [f])[0].passphrase_status == "held"

    def test_untested_by_default(self) -> None:
        ap = _ap("aa:bb:cc:dd:ee:f0", "wpa3")
        assert build_posture([ap], [])[0].passphrase_status == "untested"


class TestRogueSpoof:
    def test_flagged_when_rogue_names_the_ssid(self) -> None:
        ap = _ap("aa:bb:cc:dd:ee:f0", "wpa3", ssid="Experimental Neutron")
        rogue = _finding(
            "rogue_ap", None, summary="Foreign AP broadcasting own SSID 'Experimental Neutron'"
        )
        assert build_posture([ap], [rogue])[0].rogue_spoof is True

    def test_not_flagged_without_rogue(self) -> None:
        ap = _ap("aa:bb:cc:dd:ee:f0", "wpa3")
        assert build_posture([ap], [])[0].rogue_spoof is False


def test_weakest_posture_sorts_first() -> None:
    good = _ap("aa:bb:cc:dd:ee:f0", "wpa3")
    weak = _ap("aa:bb:cc:dd:ee:f1", "wpa2")
    f = _finding("passphrase_weak", "aa:bb:cc:dd:ee:f1")
    order = [p.bssid for p in build_posture([good, weak], [f])]
    assert order[0] == "aa:bb:cc:dd:ee:f1"  # the weak-passphrase AP first


class TestPostureRoute:
    def test_route_returns_camelcase_items(self) -> None:
        store = FindingsStore()
        store.add(_finding("passphrase_weak", "aa:bb:cc:dd:ee:f0"))
        body = (
            TestClient(create_app(MockSurveySource(), ScopeConfig(), findings=store))
            .get("/posture")
            .json()
        )
        assert len(body) == 2  # the mock's two own APs
        assert {"securityGrade", "passphraseStatus", "rogueSpoof"} <= set(body[0])
        assert "security_grade" not in body[0]
