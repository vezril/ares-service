"""The per-radio mode state machine.

A radio holds exactly one active mode. Entering an active mode (RECON/CAPTURE/AP)
requires the radio to be IDLE first — you stop before switching — and requires
the matching capability. Returning to IDLE (teardown) is always allowed, so a
radio is never left stuck in monitor mode.
"""

from __future__ import annotations

from ares.radio.types import RadioInfo, RadioMode


class TransitionError(Exception):
    """A mode transition was refused (busy in another mode, or incapable)."""


class RadioState:
    def __init__(self, info: RadioInfo) -> None:
        self.info = info
        self._mode = RadioMode.IDLE

    @property
    def id(self) -> str:
        return self.info.id

    @property
    def mode(self) -> RadioMode:
        return self._mode

    def check_enter(self, mode: RadioMode) -> None:
        """Raise :class:`TransitionError` if entering ``mode`` is illegal now.

        Legal iff: it is IDLE (always), or the same mode (idempotent), or the
        radio is currently IDLE and has the capability. Fails closed otherwise.
        """
        if mode is RadioMode.IDLE or mode is self._mode:
            return
        if self._mode is not RadioMode.IDLE:
            raise TransitionError(f"radio {self.id} is busy in {self._mode}")
        if not self.info.supports(mode):
            cap = "AP" if mode is RadioMode.AP else "monitor mode"
            raise TransitionError(f"radio {self.id} cannot enter {mode}: no {cap}")

    def transition(self, mode: RadioMode) -> None:
        """Apply the transition if legal; raise :class:`TransitionError` if not."""
        self.check_enter(mode)
        self._mode = mode
