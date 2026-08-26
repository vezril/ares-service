"""Audit tier: the own-scope gate, the aircrack parser, and the finding builder.

The two load-bearing properties: audit refuses anything off the own-BSSID
allowlist (own-scope only), and the cracked passphrase NEVER reaches the emitted
finding (a finding must not carry the secret).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from ares.audit import AuditReport, PassphraseAudit, assert_auditable, parse_aircrack, to_finding
from ares.cli import app
from ares.config import ScopeConfig
from ares.models import Severity
from ares.scope import ScopeError, ScopeGuard

runner = CliRunner()
OWN = "aa:bb:cc:dd:ee:f0"
FOREIGN = "11:22:33:44:55:66"


def _guard(bssids: list[str]) -> ScopeGuard:
    return ScopeGuard(ScopeConfig(own_bssids=bssids))


class TestScopeGate:
    def test_refuses_foreign_bssid(self) -> None:
        with pytest.raises(ScopeError, match="own-network allowlist"):
            assert_auditable(_guard([OWN]), FOREIGN)

    def test_refuses_empty_allowlist(self) -> None:
        with pytest.raises(ScopeError, match="empty"):
            assert_auditable(_guard([]), OWN)

    def test_allows_own_bssid_any_format(self) -> None:
        assert_auditable(_guard([OWN]), "AA-BB-CC-DD-EE-F0")  # must not raise


class TestAircrackParser:
    def test_key_found(self) -> None:
        out = "Current passphrase: hunter2\n\nKEY FOUND! [ hunter2 ]\nTested 1024 keys\n"
        result = parse_aircrack(out, "rockyou.txt")
        assert result.cracked is True
        assert result.key == "hunter2"
        assert result.keys_tested == 1024

    def test_not_in_dictionary(self) -> None:
        out = "Tested 14344391 keys\n\nPassphrase not in dictionary\n"
        result = parse_aircrack(out, "rockyou.txt")
        assert result.cracked is False
        assert result.key is None
        assert result.keys_tested == 14344391

    def test_ambiguous_output_defaults_to_not_cracked(self) -> None:
        # We never claim a pass we did not explicitly see.
        assert parse_aircrack("garbage output", "w.txt").cracked is False


class TestFinding:
    def test_cracked_is_high_and_omits_the_key(self) -> None:
        report = AuditReport(
            bssid=OWN,
            passphrase=PassphraseAudit(cracked=True, wordlist="rockyou.txt", key="hunter2"),
        )
        finding = to_finding(report)
        assert finding.kind == "passphrase_weak"
        assert finding.severity is Severity.HIGH
        # The secret must never ride the finding onto the bus.
        blob = finding.model_dump_json()
        assert "hunter2" not in blob
        assert finding.bssid == OWN

    def test_held_passphrase_is_info(self) -> None:
        report = AuditReport(
            bssid=OWN,
            handshake_captured=True,
            passphrase=PassphraseAudit(cracked=False, wordlist="rockyou.txt"),
        )
        finding = to_finding(report)
        assert finding.severity is Severity.INFO
        assert finding.kind == "handshake_captured"


class TestAuditCli:
    def _scope(self, tmp_path: object, bssids: str) -> str:
        from pathlib import Path

        p = Path(str(tmp_path)) / "scope.toml"
        p.write_text(f'own_ssids = ["Net"]\nown_bssids = {bssids}\n')
        return str(p)

    def test_cli_refuses_foreign_target(self, tmp_path: object) -> None:
        scope = self._scope(tmp_path, f'["{OWN}"]')
        result = runner.invoke(app, ["audit", FOREIGN, "-c", scope])
        assert result.exit_code == 1
        assert "REFUSED" in result.output
        assert "own-scope only" in result.output

    def test_cli_refuses_empty_allowlist(self, tmp_path: object) -> None:
        scope = self._scope(tmp_path, "[]")
        result = runner.invoke(app, ["audit", OWN, "-c", scope])
        assert result.exit_code == 1
        assert "REFUSED" in result.output
