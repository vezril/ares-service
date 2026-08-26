"""Findings store for the HTTP surface — what the console's Findings board reads.

Findings are the discrete ``security.wifi.finding`` events the service produces
(rogue AP seen, passphrase weak, deauth test completed). The bus (Hermes) is
their real home; this bounded in-process store is what a *single* ``ares serve``
holds so the board has something to rank now — seeded with a representative set
in mock mode, and appended to live when the survey stream sees a rogue.

Newest first, capped so a long-running server never grows unbounded.
"""

from __future__ import annotations

from collections import deque

from ares.http.wire import WireFinding

_BASE_EPOCH = 1_787_734_800  # 2026-08-26T09:00:00Z — matches the survey mock


def _iso(epoch: int) -> str:
    import datetime as dt

    return dt.datetime.fromtimestamp(epoch, tz=dt.UTC).isoformat().replace("+00:00", "Z")


class FindingsStore:
    def __init__(self, maxlen: int = 200) -> None:
        self._items: deque[WireFinding] = deque(maxlen=maxlen)

    def add(self, finding: WireFinding) -> None:
        self._items.appendleft(finding)

    def list(self) -> list[WireFinding]:
        return list(self._items)


def seed_mock_findings() -> list[WireFinding]:
    """A representative severity-ranked set so the board demos with no radio."""
    return [
        WireFinding(
            id="f-001",
            at=_iso(_BASE_EPOCH + 40),
            kind="rogue_ap",
            severity="high",
            summary="Foreign AP broadcasting own SSID 'Experimental Neutron'",
            bssid="de:ad:de:ad:de:ad",
        ),
        WireFinding(
            id="f-002",
            at=_iso(_BASE_EPOCH + 25),
            kind="passphrase_weak",
            severity="high",
            summary="Own AP aa:bb:cc:dd:ee:f0 passphrase cracked with rockyou.txt",
            bssid="aa:bb:cc:dd:ee:f0",
            capture_ref="sha256:9f2c…",
        ),
        WireFinding(
            id="f-003",
            at=_iso(_BASE_EPOCH + 12),
            kind="deauth_test_completed",
            severity="medium",
            summary="Deauth resilience test against own AP aa:bb:cc:dd:ee:f0",
            bssid="aa:bb:cc:dd:ee:f0",
        ),
        WireFinding(
            id="f-004",
            at=_iso(_BASE_EPOCH),
            kind="survey_completed",
            severity="info",
            summary="Survey: 2 own AP(s), 14 foreign",
        ),
    ]


def rogue_finding(ssid: str, seq: int, epoch: int) -> WireFinding:
    """Build a rogue-AP finding for a live spoof seen on the survey stream."""
    return WireFinding(
        id=f"rogue-{seq}",
        at=_iso(epoch),
        kind="rogue_ap",
        severity="high",
        summary=f"Foreign AP broadcasting own SSID {ssid!r}",
    )
