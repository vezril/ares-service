"""Own-network audit tier — WPA handshake / PMKID capture against *my own* AP,
then an offline passphrase-strength test.

Passive and own-scope: it captures a handshake for one of the operator's own
BSSIDs and runs it against a wordlist offline, to answer "is my passphrase weak?"
Capturing and cracking a handshake for a network you do not own is not authorized
even though the capture is passive at the antenna — so the scope gate here refuses
any target that is not on the own-BSSID allowlist, exactly like the active tier's
gate, minus the radiation.

The pieces are split so the safety-relevant logic is pure and testable without a
radio: :func:`assert_auditable` (the gate), :func:`parse_aircrack` (the cracker's
output), and :func:`to_finding` (what reaches Hermes). The actual capture and
crack subprocesses live behind :mod:`ares.monitor`.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from ares.models import Finding, Severity
from ares.scope import ScopeError, ScopeGuard


class AuditError(Exception):
    """An audit could not run (capture failed, or no capture to crack)."""


def assert_auditable(guard: ScopeGuard, bssid: str) -> None:
    """Refuse to audit a BSSID that is not the operator's own.

    Raises :class:`ScopeError` for anything off the own-BSSID allowlist, and when
    the allowlist is empty — you cannot audit "your own" network before pinning
    which BSSIDs are yours. Fails closed, like every scope decision.
    """
    if not guard.own_bssids:
        raise ScopeError(
            "own_bssids allowlist is empty — nothing is auditable. "
            "Run `ares scope discover` and pin your own BSSIDs first."
        )
    if not guard.is_own_bssid(bssid):
        raise ScopeError(
            f"{bssid} is not on the own-network allowlist. Audit is own-scope only — "
            "capturing/cracking a handshake for gear you do not own is out of scope."
        )


class PassphraseAudit(BaseModel):
    """The offline crack outcome. ``key`` is kept LOCAL only — never emitted."""

    model_config = ConfigDict(frozen=True)

    cracked: bool
    wordlist: str
    keys_tested: int | None = None
    # The plaintext key stays on the operator's box; it is deliberately excluded
    # from the finding that goes on the bus (a finding must not carry the secret).
    key: str | None = None


_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(?P<key>.*?)\s*\]")
_KEYS_TESTED_RE = re.compile(r"Tested\s+(?P<n>\d+)\s+keys", re.IGNORECASE)


def parse_aircrack(output: str, wordlist: str) -> PassphraseAudit:
    """Parse ``aircrack-ng`` stdout into a :class:`PassphraseAudit`.

    Pure over the tool's text so it is tested without cracking anything. A run
    that neither reports a key nor an explicit not-found is treated as not
    cracked (the honest default — we never claim a pass we did not see).
    """
    tested_match = _KEYS_TESTED_RE.search(output)
    keys_tested = int(tested_match.group("n")) if tested_match else None
    key_match = _KEY_FOUND_RE.search(output)
    if key_match:
        return PassphraseAudit(
            cracked=True, wordlist=wordlist, keys_tested=keys_tested, key=key_match.group("key")
        )
    return PassphraseAudit(cracked=False, wordlist=wordlist, keys_tested=keys_tested)


class AuditReport(BaseModel):
    """The full local result of auditing one own AP."""

    model_config = ConfigDict(frozen=True)

    bssid: str
    ssid: str | None = None
    handshake_captured: bool = False
    pmkid_captured: bool = False
    passphrase: PassphraseAudit | None = None
    capture_ref: str | None = None  # Apollo content-address of the capture blob


def to_finding(report: AuditReport) -> Finding:
    """Build the ``security.wifi.finding`` for an audit — WITHOUT the secret.

    A cracked own passphrase is a HIGH finding (weak key); a captured handshake
    that survived the wordlist is INFO (good — it held). The plaintext key is
    never placed on the finding.
    """
    cracked = report.passphrase is not None and report.passphrase.cracked
    if cracked:
        assert report.passphrase is not None
        return Finding(
            kind="passphrase_weak",
            severity=Severity.HIGH,
            summary=f"Own AP {report.bssid} passphrase cracked with {report.passphrase.wordlist}",
            bssid=report.bssid,
            detail={"wordlist": report.passphrase.wordlist},
            capture_ref=report.capture_ref,
        )
    captured = report.handshake_captured or report.pmkid_captured
    kind = "handshake_captured" if report.handshake_captured else "pmkid_captured"
    return Finding(
        kind=kind if captured else "audit_completed",
        severity=Severity.INFO,
        summary=(
            f"Own AP {report.bssid} audited — passphrase held against {report.passphrase.wordlist}"
            if report.passphrase
            else f"Own AP {report.bssid} audit completed"
        ),
        bssid=report.bssid,
        capture_ref=report.capture_ref,
    )
