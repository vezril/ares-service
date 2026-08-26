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
from ares.http.source import SurveySource
from ares.http.wire import HealthBody, ScopeBody
from ares.scope import ScopeGuard


def _json(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"))


async def stream_events(
    source: SurveySource,
    is_disconnected: Callable[[], Awaitable[bool]],
    tick_seconds: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> AsyncIterator[dict[str, str]]:
    """The SSE body: one snapshot, then deltas until the client disconnects.

    Extracted from the route so it is driven directly in tests (a fake
    ``is_disconnected`` + ``sleep``) without standing up a server — an infinite
    SSE stream is otherwise fragile to test through a live client.
    """
    yield {"data": _json(source.snapshot().dump())}
    while True:
        if await is_disconnected():
            return
        await sleep(tick_seconds)
        for event in source.tick():
            yield {"data": _json(event)}


def create_app(source: SurveySource, config: ScopeConfig, tick_seconds: float = 1.5) -> Starlette:
    """Build the app around a survey ``source`` and a loaded scope ``config``."""
    guard = ScopeGuard(config)

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

    async def stream(request: Request) -> EventSourceResponse:
        return EventSourceResponse(stream_events(source, request.is_disconnected, tick_seconds))

    return Starlette(
        routes=[
            Route("/health", health),
            Route("/scope", scope),
            Route("/stream", stream),
        ]
    )
