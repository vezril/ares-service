"""Config loading, MAC normalization, and the disabled-transport default."""

from __future__ import annotations

from pathlib import Path

import pytest

from ares.config import ScopeConfig
from ares.models import Finding, Severity, normalize_mac
from ares.transport.hermes import HermesClient


def test_normalize_mac_canonicalizes() -> None:
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_rejects_junk() -> None:
    with pytest.raises(ValueError, match="not a valid MAC"):
        normalize_mac("zz:zz:zz:zz:zz:zz")


def test_config_defaults_are_safe() -> None:
    cfg = ScopeConfig()
    assert cfg.own_ssids == ["Experimental Neutron"]
    assert cfg.own_bssids == []
    assert cfg.active.enabled is False  # default OFF is the whole point


def test_config_load_from_file(tmp_path: Path) -> None:
    p = tmp_path / "scope.toml"
    p.write_text(
        'own_ssids = ["Net"]\nown_bssids = ["AA-BB-CC-DD-EE-FF"]\n[active]\nenabled = true\n'
    )
    cfg = ScopeConfig.load(p)
    assert cfg.own_bssids == ["aa:bb:cc:dd:ee:ff"]  # normalized on load
    assert cfg.active.enabled is True


def test_config_load_missing_file_is_actionable(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="ares scope discover"):
        ScopeConfig.load(tmp_path / "nope.toml")


def test_hermes_disabled_transport_logs_not_raises() -> None:
    client = HermesClient(base_url=None)
    finding = Finding(kind="test", severity=Severity.INFO, summary="hi")
    assert client.emit(finding) is False  # logged, not sent, no exception
