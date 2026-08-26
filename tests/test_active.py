"""Active tier: the gates get the hardest tests — this is the tier that radiates.

Every refusal path must fail closed (disabled tier, empty allowlist, off-list
target, non-own client, missing confirmation, evil-twin without a test-bed), and
--dry-run must never reach the transmit boundary.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ares.active import (
    ConfirmationRequiredError,
    DeauthParams,
    EvilTwinParams,
    deauth_finding,
    preflight_deauth,
    preflight_evil_twin,
)
from ares.cli import app
from ares.config import ActiveConfig, ScopeConfig
from ares.scope import ScopeError, ScopeGuard

runner = CliRunner()
OWN = "aa:bb:cc:dd:ee:f0"
OWN_CLIENT = "de:ad:be:ef:00:01"
FOREIGN = "11:22:33:44:55:66"


def _config(**over: object) -> ScopeConfig:
    base: dict[str, object] = {
        "own_ssids": ["Experimental Neutron"],
        "own_bssids": [OWN],
        "own_client_macs": [OWN_CLIENT],
        "active": ActiveConfig(enabled=True),
    }
    base.update(over)
    return ScopeConfig(**base)  # type: ignore[arg-type]


class TestDeauthGate:
    def test_refuses_when_tier_disabled(self) -> None:
        guard = ScopeGuard(_config(active=ActiveConfig(enabled=False)))
        with pytest.raises(ScopeError, match="disabled"):
            preflight_deauth(guard, DeauthParams(target_bssid=OWN), confirmed=True)

    def test_refuses_foreign_target(self) -> None:
        guard = ScopeGuard(_config())
        with pytest.raises(ScopeError, match="not on the own-network allowlist"):
            preflight_deauth(guard, DeauthParams(target_bssid=FOREIGN), confirmed=True)

    def test_refuses_non_own_client(self) -> None:
        guard = ScopeGuard(_config())
        with pytest.raises(ScopeError, match="not an own test device"):
            preflight_deauth(
                guard, DeauthParams(target_bssid=OWN, client_mac=FOREIGN), confirmed=True
            )

    def test_requires_confirmation_for_in_scope_target(self) -> None:
        guard = ScopeGuard(_config())
        with pytest.raises(ConfirmationRequiredError, match="--yes"):
            preflight_deauth(guard, DeauthParams(target_bssid=OWN), confirmed=False)

    def test_allows_confirmed_in_scope(self) -> None:
        guard = ScopeGuard(_config())
        preflight_deauth(guard, DeauthParams(target_bssid=OWN), confirmed=True)  # no raise

    def test_scope_checked_before_confirmation(self) -> None:
        # A foreign target is refused as out-of-scope, never merely "unconfirmed".
        guard = ScopeGuard(_config())
        with pytest.raises(ScopeError):
            preflight_deauth(guard, DeauthParams(target_bssid=FOREIGN), confirmed=False)


class TestEvilTwinGate:
    def test_refuses_when_disabled(self) -> None:
        guard = ScopeGuard(_config(active=ActiveConfig(enabled=False)))
        with pytest.raises(ScopeError, match="disabled"):
            preflight_evil_twin(
                guard,
                _config(active=ActiveConfig(enabled=False)),
                EvilTwinParams(ssid="Experimental Neutron"),
                confirmed=True,
            )

    def test_refuses_foreign_ssid(self) -> None:
        cfg = _config()
        with pytest.raises(ScopeError, match="not one of your own_ssids"):
            preflight_evil_twin(
                ScopeGuard(cfg), cfg, EvilTwinParams(ssid="Neighbor"), confirmed=True
            )

    def test_refuses_without_test_devices(self) -> None:
        cfg = _config(own_client_macs=[])
        with pytest.raises(ScopeError, match="test devices"):
            preflight_evil_twin(
                ScopeGuard(cfg), cfg, EvilTwinParams(ssid="Experimental Neutron"), confirmed=True
            )

    def test_requires_confirmation(self) -> None:
        cfg = _config()
        with pytest.raises(ConfirmationRequiredError):
            preflight_evil_twin(
                ScopeGuard(cfg), cfg, EvilTwinParams(ssid="Experimental Neutron"), confirmed=False
            )


def test_deauth_finding_records_transmit_state() -> None:
    tx = deauth_finding(DeauthParams(target_bssid=OWN), transmitted=True)
    dry = deauth_finding(DeauthParams(target_bssid=OWN), transmitted=False)
    assert tx.detail["transmitted"] == "true"
    assert dry.detail["transmitted"] == "false"
    assert "dry-run" in dry.summary


class TestActiveCli:
    def _scope(self, tmp_path: Path, *, enabled: bool, clients: str = f'["{OWN_CLIENT}"]') -> str:
        p = tmp_path / "scope.toml"
        p.write_text(
            f'own_ssids = ["Experimental Neutron"]\nown_bssids = ["{OWN}"]\n'
            f"own_client_macs = {clients}\n[active]\nenabled = {str(enabled).lower()}\n"
        )
        return str(p)

    def test_deauth_refused_when_disabled(self, tmp_path: Path) -> None:
        scope = self._scope(tmp_path, enabled=False)
        result = runner.invoke(app, ["active", "deauth", OWN, "-c", scope])
        assert result.exit_code == 1
        assert "REFUSED" in result.output

    def test_deauth_dry_run_passes_without_transmit(self, tmp_path: Path) -> None:
        scope = self._scope(tmp_path, enabled=True)
        result = runner.invoke(app, ["active", "deauth", OWN, "-c", scope, "--yes", "--dry-run"])
        assert result.exit_code == 0
        assert "[dry-run]" in result.output
        # The real transmit line ("transmitting N deauth bursts at …") never runs.
        assert "deauth bursts at" not in result.output

    def test_deauth_needs_yes(self, tmp_path: Path) -> None:
        scope = self._scope(tmp_path, enabled=True)
        result = runner.invoke(app, ["active", "deauth", OWN, "-c", scope])
        assert result.exit_code == 1
        assert "--yes" in result.output

    def test_evil_twin_refused_without_test_devices(self, tmp_path: Path) -> None:
        scope = self._scope(tmp_path, enabled=True, clients="[]")
        result = runner.invoke(
            app, ["active", "evil-twin", "Experimental Neutron", "-c", scope, "--yes"]
        )
        assert result.exit_code == 1
        assert "REFUSED" in result.output
