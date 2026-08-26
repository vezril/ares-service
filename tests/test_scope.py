"""The scope guard is the safety boundary — it gets the hardest tests.

Every active path must fail closed: disabled tier, empty allowlist, off-list
target. And classification/membership must be robust to MAC formatting so a
hand-edited scope file cannot silently mismatch a live capture.
"""

from __future__ import annotations

import pytest

from ares.config import ActiveConfig, ScopeConfig
from ares.models import Scope
from ares.scope import ScopeError, ScopeGuard

OWN = "AA:BB:CC:DD:EE:FF"
OTHER = "11:22:33:44:55:66"


def guard(**overrides: object) -> ScopeGuard:
    base: dict[str, object] = {"own_bssids": [OWN], "own_client_macs": ["de:ad:be:ef:00:01"]}
    base.update(overrides)
    return ScopeGuard(ScopeConfig(**base))  # type: ignore[arg-type]


class TestClassification:
    def test_own_bssid_classified_own(self) -> None:
        assert guard().classify(OWN) is Scope.OWN

    def test_foreign_bssid_classified_foreign(self) -> None:
        assert guard().classify(OTHER) is Scope.FOREIGN

    @pytest.mark.parametrize(
        "variant",
        ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AABBCCDDEEFF"],
    )
    def test_membership_is_format_insensitive(self, variant: str) -> None:
        # A scope file in any common MAC notation must still match a live BSSID.
        assert guard().is_own_bssid(variant)

    def test_garbage_bssid_is_not_own_and_does_not_raise(self) -> None:
        assert guard().is_own_bssid("not-a-mac") is False


class TestActiveGate:
    def test_refuses_when_tier_disabled(self) -> None:
        g = guard(active=ActiveConfig(enabled=False))
        with pytest.raises(ScopeError, match="disabled"):
            g.assert_active_allowed(OWN)

    def test_refuses_empty_allowlist_even_when_enabled(self) -> None:
        g = guard(own_bssids=[], active=ActiveConfig(enabled=True))
        with pytest.raises(ScopeError, match="empty"):
            g.assert_active_allowed(OWN)

    def test_refuses_off_allowlist_target(self) -> None:
        g = guard(active=ActiveConfig(enabled=True))
        with pytest.raises(ScopeError, match="not on the own-network allowlist"):
            g.assert_active_allowed(OTHER)

    def test_allows_own_target_when_enabled(self) -> None:
        g = guard(active=ActiveConfig(enabled=True))
        g.assert_active_allowed(OWN)  # must not raise

    def test_allows_own_target_in_any_format(self) -> None:
        g = guard(active=ActiveConfig(enabled=True))
        g.assert_active_allowed("aa-bb-cc-dd-ee-ff")


def test_requires_confirmation_default_true() -> None:
    assert guard().requires_confirmation() is True
