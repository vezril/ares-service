"""The daemon↔console wire contract — the Python side of ares-ui's ``types.ts``.

Serialized camelCase (via a pydantic alias generator) so the JSON matches what
the console consumes byte-for-byte. The load-bearing privacy property is the same
as on the TS side: **there is no foreign per-device type.** Own observations
carry detail; foreign collapses to :class:`ForeignAggregate` (counts + spoof
flags). The contract cannot express a browsable neighbour list.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

from ares.models import Band, Security


class _Wire(BaseModel):
    """Base for wire models: camelCase aliases, frozen, populate by field name."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, frozen=True)

    def dump(self) -> dict[str, object]:
        return self.model_dump(by_alias=True)


class OwnAccessPoint(_Wire):
    bssid: str
    ssid: str | None
    channel: int | None
    band: Band | None
    security: Security
    signal_dbm: int | None
    client_count: int
    first_seen: str
    last_seen: str


class OwnClient(_Wire):
    mac: str
    bssid: str | None
    signal_dbm: int | None
    last_seen: str


class ForeignAggregate(_Wire):
    ap_count: int
    client_count: int
    spoofing_own_ssid: list[str]


class SurveySnapshot(_Wire):
    type: str = "snapshot"
    at: str
    own_aps: list[OwnAccessPoint]
    own_clients: list[OwnClient]
    foreign: ForeignAggregate


# --- delta events (built as dicts so the discriminated "type" stays explicit) --


def own_ap_upsert(ap: OwnAccessPoint) -> dict[str, object]:
    return {"type": "own.ap.upsert", "ap": ap.dump()}


def own_ap_remove(bssid: str) -> dict[str, object]:
    return {"type": "own.ap.remove", "bssid": bssid}


def own_client_upsert(client: OwnClient) -> dict[str, object]:
    return {"type": "own.client.upsert", "client": client.dump()}


def own_client_remove(mac: str) -> dict[str, object]:
    return {"type": "own.client.remove", "mac": mac}


def foreign_update(foreign: ForeignAggregate) -> dict[str, object]:
    return {"type": "foreign.update", "foreign": foreign.dump()}


class HealthBody(_Wire):
    """``GET /health`` — the shape the console's BFF parses (status UP/DOWN)."""

    service: str = "ares"
    status: str  # "UP" | "DOWN"
    version: str | None = None


class ScopeBody(_Wire):
    """``GET /scope`` — read-only view of the own-network scope."""

    own_ssids: list[str]
    own_bssid_count: int
    active_enabled: bool


class PostureItem(_Wire):
    """``GET /posture`` item — the honest self-assessment of one own AP.

    Fuses survey facts (channel/security) with audit + rogue findings into a
    per-AP grade. ``security_grade`` rates the encryption; ``passphrase_status``
    reflects whether an audit has run and what it found (never the key itself);
    ``rogue_spoof`` is true when a foreign AP is broadcasting this AP's SSID.
    """

    bssid: str
    ssid: str | None
    channel: int | None
    band: Band | None
    security: Security
    security_grade: str  # good | fair | weak
    passphrase_status: str  # untested | held | weak
    rogue_spoof: bool


class WireFinding(_Wire):
    """``GET /findings`` item — a ``security.wifi.finding`` for the board.

    The same discrete finding the service emits to Hermes, plus a timestamp and
    an id for the UI. Never carries a secret (see ``ares.audit.to_finding``); a
    ``capture_ref`` points at the Apollo blob, it does not inline it.
    """

    id: str
    at: str
    kind: str
    severity: str  # info | low | medium | high | critical
    summary: str
    bssid: str | None = None
    capture_ref: str | None = None
