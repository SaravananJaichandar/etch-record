"""Tests for Wave 2 #10 stop-condition CLI flags."""

from __future__ import annotations

import json
from unittest.mock import patch

import click
import httpx
import pytest
from click.testing import CliRunner

from etch_record import cli as etch_cli
from etch_record.cli import _prepare_stop_condition
from etch_record.config import Config
from etch_record.stop_condition_client import (
    StopConditionError,
    StopConditionResult,
    record_stop_condition,
)


CFG = Config(project_id="p", app_token="wm_t", base_url="https://etch.test")


def _mock(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# _prepare_stop_condition helper
# ---------------------------------------------------------------------------


def test_prepare_returns_none_when_no_flags():
    assert _prepare_stop_condition(None, None, None) is None


def test_prepare_requires_reason_alongside_id():
    with pytest.raises(click.UsageError, match="--stop-condition-reason"):
        _prepare_stop_condition("c", None, None)


def test_prepare_requires_id_alongside_reason():
    with pytest.raises(click.UsageError, match="--stop-condition-id"):
        _prepare_stop_condition(None, "why", None)


def test_prepare_happy_minimal():
    p = _prepare_stop_condition("kill-switch-1", "PII leak", None)
    assert p["condition_id"] == "kill-switch-1"
    assert p["halt_reason"] == "PII leak"
    assert "session_scope" not in p
    assert "attested_at" in p


def test_prepare_happy_with_scope():
    p = _prepare_stop_condition("c", "why", "session-abc")
    assert p["session_scope"] == "session-abc"


def test_prepare_scope_alone_requires_id_and_reason():
    with pytest.raises(click.UsageError):
        _prepare_stop_condition(None, None, "session-abc")


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def test_client_happy_path():
    def handler(req):
        body = json.loads(req.content)
        assert body["stop_condition"]["condition_id"] == "c"
        return httpx.Response(200, json={
            "status": "recorded", "etch_chain_seq": 5,
            "etch_row_id": "r5", "stop_condition_hash": "sha256:aa",
            "oss_event_id_ref": "oss-x", "recorded_at": "t",
        })
    with _mock(handler) as c:
        r = record_stop_condition(
            CFG, "oss-x",
            {"condition_id": "c", "halt_reason": "why",
             "attested_at": "t"},
            client=c,
        )
    assert isinstance(r, StopConditionResult)
    assert r.stop_condition_hash == "sha256:aa"


def test_client_omits_oss_event_id_when_none():
    """Chain-only halt: request body must NOT include oss_event_id
    when caller passes None (rather than sending JSON null which would
    still be accepted server-side; explicit-omission is cleaner)."""
    captured = {}
    def handler(req):
        captured["body"] = json.loads(req.content)
        return httpx.Response(200, json={
            "status": "recorded", "etch_chain_seq": 1,
            "etch_row_id": "r", "stop_condition_hash": "sha256:aa",
            "oss_event_id_ref": None, "recorded_at": "t",
        })
    with _mock(handler) as c:
        record_stop_condition(
            CFG, None,
            {"condition_id": "c", "halt_reason": "why",
             "attested_at": "t"},
            client=c,
        )
    assert "oss_event_id" not in captured["body"]


def test_client_bubbles_400():
    def handler(req):
        return httpx.Response(400, json={"error": "validation_failed"})
    with _mock(handler) as c:
        with pytest.raises(StopConditionError, match="validation_failed"):
            record_stop_condition(
                CFG, "oss",
                {"condition_id": "c", "halt_reason": "w",
                 "attested_at": "t"},
                client=c,
            )


# ---------------------------------------------------------------------------
# CLI end-to-end
# ---------------------------------------------------------------------------


def _mcp_response(event_id):
    return {"result": {"content": [{
        "type": "text", "text": '{"event_id": "' + event_id + '"}'}]}}


def test_cli_stop_condition_only_reaches_call(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")
    fake = StopConditionResult(1, "r", "sha256:aa", "oss-x", "t")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-x")):
        with patch.object(etch_cli, "record_stop_condition",
                          return_value=fake) as mock:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, [
                "hello",
                "--stop-condition-id", "kill-switch-1",
                "--stop-condition-reason", "PII leak",
            ])
            assert r.exit_code == 0, r.output
            assert "stop_condition_seq=1" in r.output
            mock.assert_called_once()


def test_cli_stop_condition_failure_exits_13(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-x")):
        with patch.object(etch_cli, "record_stop_condition",
                          side_effect=StopConditionError("mock: down")):
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, [
                "hello",
                "--stop-condition-id", "c",
                "--stop-condition-reason", "why",
            ])
            assert r.exit_code == 13


def test_cli_no_stop_flags_skips_call(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-x")):
        with patch.object(etch_cli, "record_stop_condition") as mock:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, ["hello"])
            assert r.exit_code == 0
            mock.assert_not_called()
