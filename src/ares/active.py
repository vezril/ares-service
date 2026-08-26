"""Active tier — the radiating actions, gated to exhaustion.

Active frames (deauth, evil-twin beacons) reach **every device in range**, not
just the target — so this tier is the opposite of the passive default in every
respect. It is off unless ``active.enabled`` is set, it refuses any target not on
the own-network allowlist, and it takes one explicit confirmation per run. The
clean way to exercise it is a dedicated test AP + throwaway clients (own_client_
macs), RF-isolated, so nothing touches the household net or the neighbours.

This module is the pure orchestration + gate + finding side; the actual frame
transmission lives behind :mod:`ares.radiate`, kept separate from the passive
:mod:`ares.monitor` so "the thing that transmits" is one small, isolated surface.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ares.config import ScopeConfig
from ares.models import Finding, Severity
from ares.scope import ScopeError, ScopeGuard


class ConfirmationRequiredError(Exception):
    """The action is in-scope but the one-per-run confirmation was not given."""


class DeauthParams(BaseModel):
    model_config = ConfigDict(frozen=True)

    target_bssid: str
    client_mac: str | None = None  # a specific own client, or all clients
    count: int = 5  # deauth bursts; a resilience probe, not a sustained flood


class EvilTwinParams(BaseModel):
    model_config = ConfigDict(frozen=True)

    ssid: str
    channel: int = 6


def preflight_deauth(guard: ScopeGuard, params: DeauthParams, *, confirmed: bool) -> None:
    """Gate a deauth-resilience test. Raises before anything transmits.

    Order matters: the allowlist gate (tier enabled + own BSSID) runs first, then
    the human confirmation — so an out-of-scope target is refused outright and a
    confirmation is only ever asked for an in-scope one. If a client MAC is given
    it must be an own test device.
    """
    guard.assert_active_allowed(params.target_bssid)
    if params.client_mac is not None and not guard.is_own_client(params.client_mac):
        raise ScopeError(
            f"client {params.client_mac} is not an own test device (own_client_macs). "
            "Deauth is aimed only at your own gear."
        )
    if guard.requires_confirmation() and not confirmed:
        raise ConfirmationRequiredError(
            f"about to deauth {params.target_bssid} — this radiates to devices in range. "
            "Re-run with --yes to confirm."
        )


def preflight_evil_twin(
    guard: ScopeGuard, config: ScopeConfig, params: EvilTwinParams, *, confirmed: bool
) -> None:
    """Gate an evil-twin test. Stricter than deauth: it broadcasts a *lure*.

    An evil-twin has no single target BSSID — it beacons your SSID to draw
    clients — so the gate is: tier enabled, the SSID is one you own, and you have
    designated throwaway test devices (own_client_macs). Refusing an empty
    own_client_macs is the software stand-in for "only against your own test
    clients": without declared test devices there is nothing legitimate to lure.
    """
    guard.assert_active_enabled()
    if params.ssid not in config.own_ssids:
        raise ScopeError(
            f"SSID {params.ssid!r} is not one of your own_ssids. Evil-twin may only "
            "re-broadcast a name you own."
        )
    if not config.own_client_macs:
        raise ScopeError(
            "own_client_macs is empty — evil-twin needs declared throwaway test devices to lure. "
            "It radiates a lure to everything in range; refusing without a test-bed."
        )
    if config.active.require_confirmation and not confirmed:
        raise ConfirmationRequiredError(
            f"about to stand up an evil-twin of {params.ssid!r} — this lures clients in range. "
            "Re-run with --yes to confirm."
        )


def deauth_finding(params: DeauthParams, *, transmitted: bool) -> Finding:
    return Finding(
        kind="deauth_test_completed",
        severity=Severity.MEDIUM,
        summary=(
            f"Deauth resilience test against own AP {params.target_bssid}"
            f"{' (dry-run)' if not transmitted else ''}"
        ),
        bssid=params.target_bssid,
        detail={"count": str(params.count), "transmitted": str(transmitted).lower()},
    )


def evil_twin_finding(params: EvilTwinParams, *, transmitted: bool) -> Finding:
    return Finding(
        kind="evil_twin_test_completed",
        severity=Severity.MEDIUM,
        summary=(
            f"Evil-twin test of own SSID {params.ssid!r}{' (dry-run)' if not transmitted else ''}"
        ),
        detail={"channel": str(params.channel), "transmitted": str(transmitted).lower()},
    )
