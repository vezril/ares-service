"""Radio layer: iw parsing, the mode state machine, and pool selection.

Ported from shodan; the state machine's fail-closed behaviour (busy / incapable)
and the pool's keep-the-versatile-radio-free selection are the load-bearing bits.
"""

from __future__ import annotations

import pytest

from ares.radio.pool import ClaimError, RadioPool
from ares.radio.provider import (
    MockRadioProvider,
    capabilities_from_modes,
    parse_iw_dev,
    parse_supported_modes,
)
from ares.radio.state import RadioState, TransitionError
from ares.radio.types import RadioCapabilities, RadioInfo, RadioMode

IW_DEV = """phy#1
\tInterface wlan1
\t\tifindex 4
\t\ttype managed
phy#0
\tInterface wlan0
\t\tifindex 3
\t\ttype managed
"""

IW_PHY_INFO = """Wiphy phy0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * monitor
\tBand 1:
\t\tCapabilities: 0x1234
"""


class TestIwParsing:
    def test_parse_iw_dev_pairs_iface_to_phy(self) -> None:
        assert parse_iw_dev(IW_DEV) == [("wlan1", "phy1"), ("wlan0", "phy0")]

    def test_parse_supported_modes_stops_at_next_section(self) -> None:
        modes = parse_supported_modes(IW_PHY_INFO)
        assert modes == {"IBSS", "managed", "AP", "monitor"}
        assert "Capabilities:" not in modes

    def test_capabilities_infer_injection_from_monitor(self) -> None:
        caps = capabilities_from_modes({"managed", "monitor", "AP"})
        assert caps.monitor and caps.injection and caps.ap

    def test_capabilities_managed_only_has_nothing(self) -> None:
        caps = capabilities_from_modes({"managed"})
        assert not caps.monitor and not caps.injection and not caps.ap


def _radio(rid: str, *, monitor: bool, ap: bool) -> RadioInfo:
    return RadioInfo(
        id=rid,
        phy="phy0",
        driver="test",
        capabilities=RadioCapabilities(monitor=monitor, injection=monitor, ap=ap),
    )


class TestStateMachine:
    def test_idle_to_recon_when_capable(self) -> None:
        s = RadioState(_radio("wlan0", monitor=True, ap=False))
        s.transition(RadioMode.RECON)
        assert s.mode is RadioMode.RECON

    def test_recon_refused_without_monitor(self) -> None:
        s = RadioState(_radio("wlan0", monitor=False, ap=False))
        with pytest.raises(TransitionError, match="no monitor mode"):
            s.transition(RadioMode.RECON)

    def test_ap_refused_without_ap_capability(self) -> None:
        s = RadioState(_radio("wlan0", monitor=True, ap=False))
        with pytest.raises(TransitionError, match="no AP"):
            s.transition(RadioMode.AP)

    def test_busy_radio_refuses_second_active_mode(self) -> None:
        s = RadioState(_radio("wlan0", monitor=True, ap=True))
        s.transition(RadioMode.RECON)
        with pytest.raises(TransitionError, match="busy in"):
            s.transition(RadioMode.AP)

    def test_idle_always_allowed_safe_teardown(self) -> None:
        s = RadioState(_radio("wlan0", monitor=True, ap=False))
        s.transition(RadioMode.RECON)
        s.transition(RadioMode.IDLE)  # never stuck in monitor
        assert s.mode is RadioMode.IDLE

    def test_reentering_same_mode_is_idempotent(self) -> None:
        s = RadioState(_radio("wlan0", monitor=True, ap=False))
        s.transition(RadioMode.RECON)
        s.transition(RadioMode.RECON)
        assert s.mode is RadioMode.RECON


class TestPool:
    def test_claim_prefers_least_capable_sufficient_radio(self) -> None:
        # wlan0 monitor-only, wlan1 monitor+ap. A RECON claim should take wlan0,
        # keeping the AP-capable wlan1 free.
        pool = RadioPool(
            MockRadioProvider(
                [_radio("wlan0", monitor=True, ap=False), _radio("wlan1", monitor=True, ap=True)]
            )
        )
        assert pool.claim(RadioMode.RECON) == "wlan0"

    def test_two_conflicting_modes_land_on_different_radios(self) -> None:
        pool = RadioPool(
            MockRadioProvider(
                [_radio("wlan0", monitor=True, ap=True), _radio("wlan1", monitor=True, ap=True)]
            )
        )
        recon = pool.claim(RadioMode.RECON)
        ap = pool.claim(RadioMode.AP)
        assert recon != ap

    def test_claim_fails_when_no_capable_radio(self) -> None:
        pool = RadioPool(MockRadioProvider([_radio("wlan0", monitor=True, ap=False)]))
        with pytest.raises(ClaimError, match="no idle radio can enter"):
            pool.claim(RadioMode.AP)

    def test_release_returns_radio_to_pool(self) -> None:
        pool = RadioPool(MockRadioProvider([_radio("wlan0", monitor=True, ap=False)]))
        rid = pool.claim(RadioMode.RECON)
        pool.release(rid)
        assert pool.claim(RadioMode.RECON) == rid  # claimable again

    def test_list_reports_mode_and_caps(self) -> None:
        pool = RadioPool(MockRadioProvider([_radio("wlan0", monitor=True, ap=False)]))
        [report] = pool.list()
        assert report.id == "wlan0"
        assert report.mode is RadioMode.IDLE
        assert report.capabilities.monitor is True
