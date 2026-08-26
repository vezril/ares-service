"""Ares HTTP surface — the same-origin BFF upstream the console reads.

A small ASGI app (``ares serve``) exposing ``/health``, ``/scope``, and an SSE
``/stream`` that emits the ares-ui wire contract (:mod:`ares.http.wire`): one
snapshot on connect, then survey deltas. Bound to loopback by default — an
internal service the console's server tier reaches, never exposed directly.
"""
