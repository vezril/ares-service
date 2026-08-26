"""Radio layer — enumerate the WiFi adapters and manage their monitor/AP modes.

Ported from the shodan console's radio subsystem (deprecated in favour of Ares),
adapted to Ares' synchronous CLI: the mode state machine, capability gating,
``iw`` parsing, and pool selection are kept; the JS async promise-queue
serialization is dropped (a CLI invocation is single-threaded).

* :mod:`ares.radio.types` — RadioMode / RadioCapabilities / RadioInfo.
* :mod:`ares.radio.state` — the per-radio mode state machine (fails closed on
  capability and exclusivity).
* :mod:`ares.radio.provider` — Linux (real ``iw``) and Mock (hardware-free)
  enumeration; the parsers are pure and testable.
* :mod:`ares.radio.pool` — the radio pool: claim one idle capable radio, keep the
  most versatile ones free.
"""

from ares.radio.pool import ClaimError, RadioPool, RadioReport
from ares.radio.provider import MockRadioProvider, RadioProvider, select_provider
from ares.radio.state import RadioState, TransitionError
from ares.radio.types import RadioCapabilities, RadioInfo, RadioMode

__all__ = [
    "ClaimError",
    "MockRadioProvider",
    "RadioCapabilities",
    "RadioInfo",
    "RadioMode",
    "RadioPool",
    "RadioProvider",
    "RadioReport",
    "RadioState",
    "TransitionError",
    "select_provider",
]
