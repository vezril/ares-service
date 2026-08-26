"""The /findings endpoint and its store — what the console's board reads."""

from __future__ import annotations

from starlette.testclient import TestClient

from ares.config import ScopeConfig
from ares.http.app import create_app, stream_events
from ares.http.findings import FindingsStore, seed_mock_findings
from ares.http.source import MockSurveySource


class TestFindingsRoute:
    def test_findings_seeded_and_camelcase(self) -> None:
        body = TestClient(create_app(MockSurveySource(), ScopeConfig())).get("/findings").json()
        assert len(body) == len(seed_mock_findings())
        first = body[0]
        assert {"id", "at", "kind", "severity", "summary"} <= set(first)
        assert "captureRef" in first  # camelCase, not capture_ref
        assert "capture_ref" not in first

    def test_findings_newest_first(self) -> None:
        body = TestClient(create_app(MockSurveySource(), ScopeConfig())).get("/findings").json()
        ats = [f["at"] for f in body]
        assert ats == sorted(ats, reverse=True)

    def test_no_secret_in_any_finding(self) -> None:
        # Belt-and-braces: the board's payload must not carry a plaintext key.
        import json

        body = TestClient(create_app(MockSurveySource(), ScopeConfig())).get("/findings").text
        assert "hunter2" not in json.loads(json.dumps(body))


class TestStoreFedByStream:
    async def test_rogue_on_stream_becomes_a_finding(self) -> None:
        # Drive the stream generator until a rogue foreign.update fires; it must
        # land in the findings store as a rogue_ap finding.
        store = FindingsStore()
        calls = {"n": 0}

        async def is_disconnected() -> bool:
            calls["n"] += 1
            return calls["n"] > 6  # let several ticks run

        async def no_sleep(_s: float) -> None:
            return None

        async for _frame in stream_events(
            MockSurveySource(), is_disconnected, 0.0, sleep=no_sleep, findings=store
        ):
            pass

        rogues = [f for f in store.list() if f.kind == "rogue_ap"]
        assert rogues, "a rogue spoof within the first ticks should record a finding"
        assert rogues[0].severity == "high"
