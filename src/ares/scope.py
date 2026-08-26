"""The scope guard — Ares' load-bearing safety boundary.

Radio cannot honor an IP allowlist, so scope is enforced here on BSSID/MAC:

* **Passive / storage:** :meth:`ScopeGuard.classify` tags an observed BSSID as
  own or foreign; the survey pipeline keeps detail only for ``own`` and reduces
  foreign observations to aggregate counts. This is the "discard third-party
  frames" rule made mechanical.
* **Active / emission:** :meth:`ScopeGuard.assert_active_allowed` refuses any
  active action whose target BSSID is not on the allowlist, and refuses outright
  when the active tier is disabled or the allowlist is empty. This is the RF
  equivalent of the wired scope file.

If this guard ever feels like it is "in the way," that feeling is the guard
working. It is deliberately strict and fails closed.
"""

from __future__ import annotations

from ares.config import ScopeConfig
from ares.models import Scope, normalize_mac


class ScopeError(Exception):
    """Raised when an action would cross the authorization boundary.

    Distinct exception type so callers (and the CLI) can never accidentally
    swallow a scope refusal as a generic error.
    """


class ScopeGuard:
    """Enforces the own-network boundary against a loaded :class:`ScopeConfig`."""

    def __init__(self, config: ScopeConfig) -> None:
        self._config = config
        # Normalize once so lookups are pure set membership on canonical form.
        self._own_bssids: frozenset[str] = frozenset(normalize_mac(b) for b in config.own_bssids)
        self._own_client_macs: frozenset[str] = frozenset(
            normalize_mac(m) for m in config.own_client_macs
        )

    @property
    def own_bssids(self) -> frozenset[str]:
        return self._own_bssids

    @staticmethod
    def _canonical_or_none(value: str) -> str | None:
        """Normalize any accepted MAC notation, or None for non-MAC junk.

        Membership must not fail on formatting (a hand-edited scope file may use
        hyphens/dots), but a garbage string must be *not own* rather than raise.
        """
        try:
            return normalize_mac(value)
        except ValueError:
            return None

    def is_own_bssid(self, bssid: str) -> bool:
        canonical = self._canonical_or_none(bssid)
        return canonical is not None and canonical in self._own_bssids

    def is_own_client(self, mac: str) -> bool:
        canonical = self._canonical_or_none(mac)
        return canonical is not None and canonical in self._own_client_macs

    def classify(self, bssid: str) -> Scope:
        """Own vs foreign for a passively observed BSSID (governs storage)."""
        return Scope.OWN if self.is_own_bssid(bssid) else Scope.FOREIGN

    def assert_active_allowed(self, target_bssid: str) -> None:
        """Gate an active (radiating) action on ``target_bssid``.

        Fails closed on every path: tier disabled, empty allowlist, or target
        not on the allowlist all raise :class:`ScopeError`. Callers must also
        obtain per-run confirmation (see :attr:`ScopeConfig.active`); this method
        enforces the allowlist, not the human confirmation.
        """
        if not self._config.active.enabled:
            raise ScopeError(
                "active tier is disabled (active.enabled = false). Active frames radiate "
                "to every device in range; enable it deliberately and only against your own gear."
            )
        if not self._own_bssids:
            raise ScopeError(
                "own_bssids allowlist is empty — refusing every active action. "
                "Run `ares scope discover` and pin your own BSSIDs first."
            )
        if not self.is_own_bssid(target_bssid):
            raise ScopeError(
                f"target BSSID {target_bssid} is not on the own-network allowlist. "
                "Active actions against gear you do not own are out of scope and refused."
            )

    def requires_confirmation(self) -> bool:
        """Whether an active run must obtain one explicit confirmation."""
        return self._config.active.require_confirmation
