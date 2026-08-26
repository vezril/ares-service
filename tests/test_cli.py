"""CLI smoke tests — focused on the safety-critical command paths.

The active-gate refusal is the one the user's fingers reach for, so it is tested
at the CLI boundary (exit code + message), not just at the guard.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ares.cli import app

runner = CliRunner()

CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
    "Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:DD:EE:FF, t, t, 6, 130, WPA2, CCMP, PSK, -40, 100, 0, 0.0.0.0, 18, Experimental Neutron, \n"  # noqa: E501
    "99:88:77:66:55:44, t, t, 11, 130, WPA2, CCMP, PSK, -70, 50, 0, 0.0.0.0, 8, Neighbor, \n"
    "\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probes\n"
    "DE:AD:BE:EF:00:01, t, t, -45, 20, AA:BB:CC:DD:EE:FF, \n"
)


def _write_scope(tmp_path: Path, *, active: bool, bssids: str = '["aa:bb:cc:dd:ee:ff"]') -> Path:
    p = tmp_path / "scope.toml"
    p.write_text(
        f'own_ssids = ["Experimental Neutron"]\nown_bssids = {bssids}\n'
        'own_client_macs = ["de:ad:be:ef:00:01"]\n'
        f"[active]\nenabled = {str(active).lower()}\nrequire_confirmation = true\n"
    )
    return p


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ares" in result.stdout


def test_survey_from_csv_shows_own_detail_and_foreign_counts(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path, active=False)
    csv_file = tmp_path / "sweep.csv"
    csv_file.write_text(CSV)
    result = runner.invoke(app, ["survey", "-c", str(scope), "--from-csv", str(csv_file)])
    assert result.exit_code == 0
    assert "own APs:          1" in result.stdout
    assert "foreign APs:      1" in result.stdout
    assert "99:88:77:66:55:44" not in result.stdout  # foreign detail never printed


def test_active_deauth_refused_when_tier_disabled(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path, active=False)
    result = runner.invoke(app, ["active", "deauth", "aa:bb:cc:dd:ee:ff", "-c", str(scope)])
    assert result.exit_code == 1
    assert "REFUSED" in result.output


def test_active_deauth_refused_for_offlist_target(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path, active=True)
    result = runner.invoke(app, ["active", "deauth", "11:22:33:44:55:66", "-c", str(scope)])
    assert result.exit_code == 1
    assert "not on the own-network allowlist" in result.output


def test_active_deauth_needs_confirmation_even_on_allowlist(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path, active=True)
    result = runner.invoke(app, ["active", "deauth", "aa:bb:cc:dd:ee:ff", "-c", str(scope)])
    assert result.exit_code == 1
    assert "--yes to confirm" in result.output


def test_active_deauth_scaffold_passes_with_confirmation(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path, active=True)
    result = runner.invoke(
        app, ["active", "deauth", "aa:bb:cc:dd:ee:ff", "-c", str(scope), "--yes"]
    )
    assert result.exit_code == 0
    assert "transmission not yet wired" in result.output


def test_scope_discover_from_csv_lists_candidates(tmp_path: Path) -> None:
    # own_bssids empty so the own-SSID AP shows up as an unpinned candidate.
    scope = _write_scope(tmp_path, active=False, bssids="[]")
    csv_file = tmp_path / "sweep.csv"
    csv_file.write_text(CSV)
    result = runner.invoke(
        app, ["scope", "discover", "-c", str(scope), "--from-csv", str(csv_file)]
    )
    assert result.exit_code == 0
    assert "aa:bb:cc:dd:ee:ff" in result.stdout
