"""Survey sources feeding the SSE stream.

A source produces an initial :class:`SurveySnapshot` and, on each ``tick()``, a
list of delta events. Two implementations:

* :class:`MockSurveySource` — a representative own-network model, so the HTTP
  surface (and the whole console) runs with no radio. Deterministic timestamps
  make it testable. Mirrors ares-ui's mock and shodan's mock adapter.
* :class:`LiveSurveySource` — a real monitor-mode sweep per tick, mapped through
  the scope guard (:func:`ares.survey.build_survey`) into the wire contract,
  tracking prior state so APs upsert and removals are emitted.

Both honour the privacy boundary: foreign is only ever an aggregate.
"""

from __future__ import annotations

import datetime as dt
import random
from dataclasses import dataclass
from typing import Protocol

from ares.http.wire import (
    ForeignAggregate,
    OwnAccessPoint,
    OwnClient,
    SurveySnapshot,
    foreign_update,
    own_ap_remove,
    own_ap_upsert,
    own_client_upsert,
)
from ares.scope import ScopeGuard
from ares.survey import build_survey, parse_airodump_csv

_OWN_SSID = "Experimental Neutron"
_BASE_EPOCH = 1_787_734_800  # 2026-08-26T09:00:00Z, a fixed readable base


def _iso(epoch: int) -> str:
    # Deterministic ISO-8601 (UTC) without wall-clock — matches ares-ui's mock.
    return dt.datetime.fromtimestamp(epoch, tz=dt.UTC).isoformat().replace("+00:00", "Z")


class SurveySource(Protocol):
    def snapshot(self) -> SurveySnapshot: ...
    def tick(self) -> list[dict[str, object]]: ...


@dataclass
class _MockAp:
    bssid: str
    channel: int
    band: str
    signal: int
    clients: int


@dataclass
class _MockClient:
    mac: str
    bssid: str
    signal: int


class MockSurveySource:
    """A drifting own-network model with an occasional rogue-SSID spoof."""

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random(1)  # non-crypto jitter, seeded for tests
        self._ticks = 0
        self._aps = [
            _MockAp("aa:bb:cc:dd:ee:f0", 6, "2.4GHz", -41, 3),
            _MockAp("aa:bb:cc:dd:ee:f1", 149, "5GHz", -58, 1),
        ]
        self._clients = [
            _MockClient("de:ad:be:ef:00:01", "aa:bb:cc:dd:ee:f0", -47),
            _MockClient("de:ad:be:ef:00:02", "aa:bb:cc:dd:ee:f0", -60),
            _MockClient("de:ad:be:ef:00:03", "aa:bb:cc:dd:ee:f0", -72),
            _MockClient("de:ad:be:ef:00:04", "aa:bb:cc:dd:ee:f1", -55),
        ]
        self._foreign_ap = 14
        self._foreign_client = 31

    def _jitter(self, dbm: int) -> int:
        return max(-90, min(-30, dbm + round((self._rng.random() - 0.5) * 6)))

    def _now(self) -> str:
        return _iso(_BASE_EPOCH + self._ticks)

    def _ap(self, a: _MockAp, at: str) -> OwnAccessPoint:
        return OwnAccessPoint(
            bssid=a.bssid,
            ssid=_OWN_SSID,
            channel=a.channel,
            band=a.band,  # type: ignore[arg-type]  # validated against Band on construct
            security="wpa3",  # type: ignore[arg-type]
            signal_dbm=a.signal,
            client_count=a.clients,
            first_seen=_iso(_BASE_EPOCH),
            last_seen=at,
        )

    def _client_wire(self, c: _MockClient, at: str) -> OwnClient:
        return OwnClient(mac=c.mac, bssid=c.bssid, signal_dbm=c.signal, last_seen=at)

    def _foreign_agg(self) -> ForeignAggregate:
        spoof = [_OWN_SSID] if self._ticks % 5 == 0 and self._ticks > 0 else []
        return ForeignAggregate(
            ap_count=self._foreign_ap,
            client_count=self._foreign_client,
            spoofing_own_ssid=spoof,
        )

    def snapshot(self) -> SurveySnapshot:
        at = self._now()
        return SurveySnapshot(
            at=at,
            own_aps=[self._ap(a, at) for a in self._aps],
            own_clients=[self._client_wire(c, at) for c in self._clients],
            foreign=self._foreign_agg(),
        )

    def tick(self) -> list[dict[str, object]]:
        self._ticks += 1
        at = self._now()
        events: list[dict[str, object]] = []
        for a in self._aps:
            a.signal = self._jitter(a.signal)
            events.append(own_ap_upsert(self._ap(a, at)))
        c = self._clients[self._ticks % len(self._clients)]
        c.signal = self._jitter(c.signal)
        events.append(own_client_upsert(self._client_wire(c, at)))
        self._foreign_ap = max(0, self._foreign_ap + (1 if self._rng.random() < 0.5 else -1))
        self._foreign_client = max(0, self._foreign_client + round((self._rng.random() - 0.5) * 4))
        events.append(foreign_update(self._foreign_agg()))
        return events


class LiveSurveySource:
    """A real monitor-mode sweep per tick, mapped to the wire contract.

    Each sweep runs airodump for ``sweep_seconds`` and applies the scope guard;
    only own detail survives. Prior own-BSSIDs are tracked so a disappeared AP
    emits ``own.ap.remove``. Requires hardware — used when ``ares serve --live``.
    """

    def __init__(self, guard: ScopeGuard, interface: str, sweep_seconds: float = 10.0) -> None:
        self._guard = guard
        self._interface = interface
        self._sweep_seconds = sweep_seconds
        self._own_ssids: list[str] = []
        self._seen_bssids: set[str] = set()
        self._epoch = _BASE_EPOCH

    def set_own_ssids(self, ssids: list[str]) -> None:
        self._own_ssids = ssids

    def _sweep(self) -> tuple[list[OwnAccessPoint], list[OwnClient], ForeignAggregate, str]:
        from ares.monitor import capture_airodump_csv

        csv = capture_airodump_csv(self._interface, self._sweep_seconds)
        aps, clients = parse_airodump_csv(csv)
        result = build_survey(aps, clients, self._guard, self._own_ssids)
        self._epoch += int(self._sweep_seconds)
        at = _iso(self._epoch)
        client_counts: dict[str, int] = {}
        for c in result.own_clients:
            if c.associated_bssid:
                client_counts[c.associated_bssid] = client_counts.get(c.associated_bssid, 0) + 1
        own_aps = [
            OwnAccessPoint(
                bssid=ap.bssid,
                ssid=ap.ssid,
                channel=ap.channel,
                band=ap.band,
                security=ap.security,
                signal_dbm=ap.signal_dbm,
                client_count=client_counts.get(ap.bssid, 0),
                first_seen=at,
                last_seen=at,
            )
            for ap in result.own_aps
        ]
        own_clients = [
            OwnClient(mac=c.mac, bssid=c.associated_bssid, signal_dbm=c.signal_dbm, last_seen=at)
            for c in result.own_clients
        ]
        foreign = ForeignAggregate(
            ap_count=result.foreign_ap_count,
            client_count=result.foreign_client_count,
            spoofing_own_ssid=result.foreign_ssids_spoofing_own,
        )
        return own_aps, own_clients, foreign, at

    def snapshot(self) -> SurveySnapshot:
        own_aps, own_clients, foreign, at = self._sweep()
        self._seen_bssids = {ap.bssid for ap in own_aps}
        return SurveySnapshot(at=at, own_aps=own_aps, own_clients=own_clients, foreign=foreign)

    def tick(self) -> list[dict[str, object]]:
        own_aps, own_clients, foreign, _at = self._sweep()
        events: list[dict[str, object]] = []
        current = {ap.bssid for ap in own_aps}
        for gone in self._seen_bssids - current:
            events.append(own_ap_remove(gone))
        for ap in own_aps:
            events.append(own_ap_upsert(ap))
        for c in own_clients:
            events.append(own_client_upsert(c))
        events.append(foreign_update(foreign))
        self._seen_bssids = current
        return events
