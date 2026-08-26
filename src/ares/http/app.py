"""The ASGI app — ``/health``, ``/scope``, and the SSE ``/stream``.

Built with Starlette + sse-starlette. Bound to loopback by ``ares serve``; the
console's server tier (its BFF) is the only intended client. CORS is deliberately
absent — nothing browser-side talks to this directly.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable

from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ares import __version__
from ares.config import ScopeConfig
from ares.http.findings import FindingsStore, rogue_finding, seed_mock_findings
from ares.http.source import SurveySource
from ares.http.wire import HealthBody, ScopeBody
from ares.scope import ScopeGuard

_ROGUE_BASE_EPOCH = 1_787_734_800  # match the survey/findings mock timeline


def _json(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _rogue_ssids(event: dict[str, object]) -> list[str]:
    """The own SSIDs a foreign.update event reports as spoofed (else empty)."""
    if event.get("type") != "foreign.update":
        return []
    foreign = event.get("foreign")
    if isinstance(foreign, dict):
        spoof = foreign.get("spoofingOwnSsid")
        if isinstance(spoof, list):
            return [str(s) for s in spoof]
    return []


async def stream_events(
    source: SurveySource,
    is_disconnected: Callable[[], Awaitable[bool]],
    tick_seconds: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    findings: FindingsStore | None = None,
) -> AsyncIterator[dict[str, str]]:
    """The SSE body: one snapshot, then deltas until the client disconnects.

    Extracted from the route so it is driven directly in tests (a fake
    ``is_disconnected`` + ``sleep``) without standing up a server — an infinite
    SSE stream is otherwise fragile to test through a live client. A rogue seen on
    the stream is also recorded as a finding, so the Findings board reflects live
    survey activity, not just the seeded set.
    """
    seq = 0
    yield {"data": _json(source.snapshot().dump())}
    while True:
        if await is_disconnected():
            return
        await sleep(tick_seconds)
        for event in source.tick():
            if findings is not None:
                for ssid in _rogue_ssids(event):
                    seq += 1
                    findings.add(rogue_finding(ssid, seq, _ROGUE_BASE_EPOCH + seq))
            yield {"data": _json(event)}


def create_app(
    source: SurveySource,
    config: ScopeConfig,
    tick_seconds: float = 1.5,
    findings: FindingsStore | None = None,
) -> Starlette:
    """Build the app around a survey ``source`` and a loaded scope ``config``.

    ``findings`` defaults to a store seeded with a representative set so the board
    is never empty during bring-up; the live stream appends real rogues to it.
    """
    guard = ScopeGuard(config)
    if findings is None:
        findings = FindingsStore()
        # seed_mock_findings() is newest-first; add() prepends, so add the oldest
        # first to leave the newest at the front of the list.
        for f in reversed(seed_mock_findings()):
            findings.add(f)
    store = findings

    async def health(_request: Request) -> JSONResponse:
        # Always UP when the process is answering — liveness, not a dependency roll-up.
        return JSONResponse(HealthBody(status="UP", version=__version__).dump())

    async def scope(_request: Request) -> JSONResponse:
        body = ScopeBody(
            own_ssids=config.own_ssids,
            own_bssid_count=len(guard.own_bssids),
            active_enabled=config.active.enabled,
        )
        return JSONResponse(body.dump())

    async def findings_route(_request: Request) -> JSONResponse:
        return JSONResponse([f.dump() for f in store.list()])

    async def stream(request: Request) -> EventSourceResponse:
        return EventSourceResponse(
            stream_events(source, request.is_disconnected, tick_seconds, findings=store)
        )

    return Starlette(
        routes=[
            Route("/health", health),
            Route("/scope", scope),
            Route("/findings", findings_route),
            Route("/stream", stream),
        ]
    )
