"""HTTP surface: wire serialization, the mock source, and the routes.

The wire JSON must match ares-ui's contract byte-for-byte (camelCase keys), and
the privacy invariant must hold at the boundary: no foreign per-device shape ever
crosses the wire — foreign is only ever the aggregate.
"""

from __future__ import annotations

from starlette.testclient import TestClient

from ares.config import ScopeConfig
from ares.http.app import create_app, stream_events
from ares.http.source import MockSurveySource
from ares.http.wire import ForeignAggregate, OwnAccessPoint, SurveySnapshot


class TestWireSerialization:
    def test_own_ap_serializes_camelcase(self) -> None:
        ap = OwnAccessPoint(
            bssid="aa:bb:cc:dd:ee:f0",
            ssid="Experimental Neutron",
            channel=6,
            band="2.4GHz",
            security="wpa3",
            signal_dbm=-41,
            client_count=3,
            first_seen="2026-08-26T09:00:00Z",
            last_seen="2026-08-26T09:00:01Z",
        )
        d = ap.dump()
        # The console reads these exact keys — snake_case would silently render "—".
        assert d["signalDbm"] == -41
        assert d["clientCount"] == 3
        assert d["firstSeen"] == "2026-08-26T09:00:00Z"
        assert "signal_dbm" not in d

    def test_foreign_aggregate_keys(self) -> None:
        d = ForeignAggregate(ap_count=14, client_count=31, spoofing_own_ssid=[]).dump()
        assert sorted(d.keys()) == ["apCount", "clientCount", "spoofingOwnSsid"]

    def test_snapshot_has_no_foreign_device_list(self) -> None:
        snap = MockSurveySource().snapshot().dump()
        assert snap["type"] == "snapshot"
        # foreign is an aggregate object, never a list of foreign devices.
        assert isinstance(snap["foreign"], dict)
        assert "apCount" in snap["foreign"]  # type: ignore[operator]
        assert sorted(snap.keys()) == ["at", "foreign", "ownAps", "ownClients", "type"]


class TestMockSource:
    def test_snapshot_has_own_detail(self) -> None:
        snap = MockSurveySource().snapshot()
        assert isinstance(snap, SurveySnapshot)
        assert len(snap.own_aps) == 2
        assert snap.own_aps[0].ssid == "Experimental Neutron"

    def test_tick_emits_own_and_foreign_deltas(self) -> None:
        src = MockSurveySource()
        events = src.tick()
        types = {e["type"] for e in events}
        assert "own.ap.upsert" in types
        assert "foreign.update" in types
        # No foreign per-device delta type exists in the emitted set.
        assert not any(str(t).startswith("foreign.ap") for t in types)

    def test_rogue_spoof_appears_periodically(self) -> None:
        src = MockSurveySource()
        seen_spoof = False
        for _ in range(6):
            for e in src.tick():
                if e["type"] == "foreign.update":
                    foreign = e["foreign"]
                    assert isinstance(foreign, dict)
                    if foreign["spoofingOwnSsid"]:
                        seen_spoof = True
        assert seen_spoof  # the rogue scenario fires within a few ticks


class TestRoutes:
    def _client(self) -> TestClient:
        return TestClient(
            create_app(MockSurveySource(), ScopeConfig(own_bssids=["aa:bb:cc:dd:ee:f0"]))
        )

    def test_health_reports_up(self) -> None:
        resp = self._client().get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["service"] == "ares"
        assert body["status"] == "UP"
        assert body["version"]

    def test_scope_is_read_only_summary(self) -> None:
        body = self._client().get("/scope").json()
        assert body["ownSsids"] == ["Experimental Neutron"]
        assert body["ownBssidCount"] == 1
        assert body["activeEnabled"] is False


class TestStreamGenerator:
    """Drive the SSE generator directly — an infinite stream is fragile to test
    through a live client, so the route delegates to this testable generator."""

    async def _collect(self, disconnect_after: int) -> list[dict[str, object]]:
        import json

        calls = {"n": 0}

        async def is_disconnected() -> bool:
            calls["n"] += 1
            return calls["n"] > disconnect_after

        async def no_sleep(_seconds: float) -> None:
            return None

        frames: list[dict[str, object]] = []
        async for frame in stream_events(
            MockSurveySource(), is_disconnected, tick_seconds=0.0, sleep=no_sleep
        ):
            frames.append(json.loads(frame["data"]))
        return frames

    async def test_first_frame_is_snapshot(self) -> None:
        frames = await self._collect(disconnect_after=0)
        assert frames[0]["type"] == "snapshot"
        assert "ownAps" in frames[0]
        assert len(frames) == 1  # disconnected before any tick

    async def test_deltas_follow_snapshot(self) -> None:
        frames = await self._collect(disconnect_after=1)  # one tick then disconnect
        assert frames[0]["type"] == "snapshot"
        delta_types = {f["type"] for f in frames[1:]}
        assert "own.ap.upsert" in delta_types
        assert "foreign.update" in delta_types
