"""Core RF domain types.

MAC/BSSID values are normalized to lowercase colon-separated form on the way in
so scope comparisons never fail on formatting. A BSSID is just a MAC on an AP;
we keep the two aliases for readability at call sites.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize_mac(value: str) -> str:
    """Canonicalize a MAC/BSSID to lowercase ``aa:bb:cc:dd:ee:ff``.

    Accepts colon-, hyphen-, or dot-separated and bare 12-hex forms so that a
    scope file hand-edited in any common notation still matches live captures.
    """
    raw = value.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(raw) != 12 or not re.fullmatch(r"[0-9a-f]{12}", raw):
        raise ValueError(f"not a valid MAC address: {value!r}")
    mac = ":".join(raw[i : i + 2] for i in range(0, 12, 2))
    return mac


MacAddress = Annotated[str, BeforeValidator(normalize_mac)]


def is_mac(value: str) -> bool:
    """True if ``value`` is already a normalized MAC (cheap guard, no raise)."""
    return bool(_MAC_RE.match(value))


class Band(StrEnum):
    TWO_GHZ = "2.4GHz"
    FIVE_GHZ = "5GHz"
    SIX_GHZ = "6GHz"


class Security(StrEnum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    UNKNOWN = "unknown"


class Scope(StrEnum):
    """Whether an observation belongs to the operator or a third party.

    Third-party detail is discarded by the survey pipeline; this tag records the
    decision explicitly so the privacy boundary is visible in the data model.
    """

    OWN = "own"
    FOREIGN = "foreign"


class AccessPoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    bssid: MacAddress
    ssid: str | None = None  # None = hidden SSID
    channel: int | None = None
    band: Band | None = None
    signal_dbm: int | None = None
    security: Security = Security.UNKNOWN
    scope: Scope = Scope.FOREIGN


class Client(BaseModel):
    model_config = ConfigDict(frozen=True)

    mac: MacAddress
    associated_bssid: MacAddress | None = None
    signal_dbm: int | None = None
    scope: Scope = Scope.FOREIGN


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A discrete ``security.wifi.finding`` event.

    Small JSON destined for Hermes; any large capture lives in Apollo and is
    referenced by ``capture_ref`` (a content address), never inlined. Raw RF
    frames never appear here — that is the bus-drowning anti-pattern the design
    forbids.
    """

    model_config = ConfigDict(frozen=True)

    kind: str = Field(description="e.g. rogue_ap, handshake_captured, new_own_device")
    severity: Severity
    summary: str
    bssid: MacAddress | None = None
    detail: dict[str, str] = Field(default_factory=dict)
    capture_ref: str | None = Field(
        default=None, description="Apollo content-address of an associated capture blob"
    )
