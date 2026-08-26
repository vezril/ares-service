"""The radio pool — enumerate, report, and claim radios for a mode.

Recon claims one idle monitor-capable radio and leaves the rest free, so
conflicting modes run on distinct cards concurrently. When several radios can
serve a mode, the *least* versatile sufficient one is picked, keeping the
most-capable radios (e.g. the only AP-capable card) free for modes that need
them.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from ares.radio.provider import RadioProvider
from ares.radio.state import RadioState, TransitionError
from ares.radio.types import RadioCapabilities, RadioMode


class ClaimError(Exception):
    """No idle radio could serve the requested mode."""


class RadioReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    phy: str
    driver: str
    chipset: str | None
    capabilities: RadioCapabilities
    mode: RadioMode


class RadioPool:
    def __init__(self, provider: RadioProvider) -> None:
        self._states = [RadioState(info) for info in provider.enumerate()]

    def list(self) -> list[RadioReport]:
        return [
            RadioReport(
                id=s.info.id,
                phy=s.info.phy,
                driver=s.info.driver,
                chipset=s.info.chipset,
                capabilities=s.info.capabilities,
                mode=s.mode,
            )
            for s in self._states
        ]

    def claim(self, mode: RadioMode) -> str:
        """Claim one idle radio capable of ``mode`` and transition it; return its id.

        Raises :class:`ClaimError` if none is available.
        """
        candidates = sorted(
            (s for s in self._states if s.mode is RadioMode.IDLE and s.info.supports(mode)),
            key=lambda s: s.info.capabilities.count(),
        )
        if not candidates:
            raise ClaimError(f"no idle radio can enter {mode}")
        chosen = candidates[0]
        try:
            chosen.transition(mode)
        except TransitionError as e:  # capability re-checked inside transition
            raise ClaimError(str(e)) from e
        return chosen.id

    def release(self, radio_id: str) -> None:
        """Return a radio to IDLE (safe teardown — leave monitor mode)."""
        for s in self._states:
            if s.id == radio_id:
                s.transition(RadioMode.IDLE)
                return

    def release_all(self) -> None:
        for s in self._states:
            s.transition(RadioMode.IDLE)
