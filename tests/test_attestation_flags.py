"""
Tests for the Wave 1 #3 model-card attestation flags on etch-record CLI.

Covers:
- attestation_client happy path + error paths (mocked httpx).
- _assemble_attestation_from_flags: all-or-nothing validation, optional
  field passthrough, model_id required alongside model_card_hash.
- CLI end-to-end: attestation-only invocation reaches the fourth call
  even when governance and authority flags are absent.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner

from etch_record import cli as etch_cli
from etch_record.attestation_client import (
    AttestationError,
    AttestationResult,
    record_model_card_attestation,
)
from etch_record.cli import _assemble_attestation_from_flags
from etch_record.config import Config


CFG = Config(
    project_id="proj_alpha",
    app_token="wm_test_token",
    base_url="https://etch.test",
)


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


def test_client_happy_path():
    def handler(request):
        body = json.loads(request.content)
        assert body["oss_event_id"] == "oss-abc"
        assert body["attestation"]["model_id"] == "claude-opus-4-7"
        assert body["attestation"]["model_card_hash"].startswith("sha256:")
        return httpx.Response(200, json={
            "status": "recorded",
            "etch_chain_seq": 3,
            "etch_row_id": "row-uuid-3",
            "attestation_hash": "sha256:" + "cc" * 32,
            "oss_event_id_ref": "oss-abc",
            "recorded_at": "2026-08-01T20:35:00.000Z",
        })

    with _mock_client(handler) as client:
        result = record_model_card_attestation(
            CFG, "oss-abc",
            {
                "model_card_hash": "sha256:" + "aa" * 32,
                "model_id": "claude-opus-4-7",
                "attested_at": "2026-08-01T20:35:00.000Z",
            },
            client=client,
        )
    assert isinstance(result, AttestationResult)
    assert result.etch_chain_seq == 3
    assert result.attestation_hash == "sha256:" + "cc" * 32


def test_client_bubbles_400():
    def handler(request):
        return httpx.Response(400, json={
            "error": "validation_failed",
            "details": [{"loc": ["attestation", "model_card_hash"],
                         "msg": "sha256:..."}],
        })
    with _mock_client(handler) as client:
        with pytest.raises(AttestationError, match="validation_failed"):
            record_model_card_attestation(
                CFG, "oss-x",
                {"model_card_hash": "bad", "model_id": "x",
                 "attested_at": "..."},
                client=client,
            )


def test_client_bubbles_403():
    def handler(request):
        return httpx.Response(403, json={
            "error": "insufficient_scope",
            "required_scope": "mcp:write",
            "token_scopes": ["mcp:read"],
        })
    with _mock_client(handler) as client:
        with pytest.raises(AttestationError, match="insufficient_scope"):
            record_model_card_attestation(
                CFG, "oss-x",
                {"model_card_hash": "sha256:" + "aa" * 32,
                 "model_id": "claude-opus-4-7",
                 "attested_at": "..."},
                client=client,
            )


def test_client_bubbles_500():
    def handler(request):
        return httpx.Response(500, json={"error": "internal_error"})
    with _mock_client(handler) as client:
        with pytest.raises(AttestationError, match="internal_error"):
            record_model_card_attestation(
                CFG, "oss-x",
                {"model_card_hash": "sha256:" + "aa" * 32,
                 "model_id": "claude-opus-4-7",
                 "attested_at": "..."},
                client=client,
            )


# ---------------------------------------------------------------------------
# _assemble_attestation_from_flags (CLI helper)
# ---------------------------------------------------------------------------


def test_assemble_returns_none_when_no_flags_set():
    assert _assemble_attestation_from_flags(
        model_card_hash=None,
        system_prompt_hash=None,
        attestation_policy_hash=None,
        model_id=None,
    ) is None


def test_assemble_requires_model_id_alongside_hash():
    import click
    with pytest.raises(click.UsageError, match="--model-id"):
        _assemble_attestation_from_flags(
            model_card_hash="sha256:" + "aa" * 32,
            system_prompt_hash=None,
            attestation_policy_hash=None,
            model_id=None,
        )


def test_assemble_requires_hash_alongside_model_id():
    import click
    with pytest.raises(click.UsageError, match="--model-card-hash"):
        _assemble_attestation_from_flags(
            model_card_hash=None,
            system_prompt_hash=None,
            attestation_policy_hash=None,
            model_id="claude-opus-4-7",
        )


def test_assemble_happy_path_minimal():
    attestation = _assemble_attestation_from_flags(
        model_card_hash="sha256:" + "aa" * 32,
        system_prompt_hash=None,
        attestation_policy_hash=None,
        model_id="claude-opus-4-7",
    )
    assert attestation["model_card_hash"] == "sha256:" + "aa" * 32
    assert attestation["model_id"] == "claude-opus-4-7"
    assert "system_prompt_hash" not in attestation
    assert "policy_hash" not in attestation
    assert "attested_at" in attestation


def test_assemble_happy_path_all_hashes():
    attestation = _assemble_attestation_from_flags(
        model_card_hash="sha256:" + "aa" * 32,
        system_prompt_hash="sha256:" + "bb" * 32,
        attestation_policy_hash="sha256:" + "cc" * 32,
        model_id="claude-opus-4-7",
    )
    assert attestation["system_prompt_hash"] == "sha256:" + "bb" * 32
    assert attestation["policy_hash"] == "sha256:" + "cc" * 32


def test_assemble_partial_optional_only_includes_the_set_one():
    a = _assemble_attestation_from_flags(
        model_card_hash="sha256:" + "aa" * 32,
        system_prompt_hash="sha256:" + "bb" * 32,
        attestation_policy_hash=None,
        model_id="claude-opus-4-7",
    )
    assert "system_prompt_hash" in a
    assert "policy_hash" not in a


def test_assemble_partial_flags_only_prompt_still_errors():
    """Providing --system-prompt-hash but not model-card-hash or
    model-id is a usage error, not a silent no-op."""
    import click
    with pytest.raises(click.UsageError):
        _assemble_attestation_from_flags(
            model_card_hash=None,
            system_prompt_hash="sha256:" + "bb" * 32,
            attestation_policy_hash=None,
            model_id=None,
        )


# ---------------------------------------------------------------------------
# CLI end-to-end — attestation reaches its endpoint independently
# of governance / authority (regression: v0.4.0 short-circuited past
# attestation when no authority flags were set)
# ---------------------------------------------------------------------------


def test_cli_attestation_only_makes_second_call(monkeypatch):
    """Only --model-card-hash + --model-id set (no governance, no
    authority). CLI must still POST the attestation. This is the exact
    regression from v0.4.0 — the authority block had `if authority_claim
    is None: return` which skipped the attestation call downstream.
    """
    monkeypatch.setenv("ETCH_PROJECT_ID", "proj_alpha")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_test")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    fake_att_result = AttestationResult(
        etch_chain_seq=7,
        etch_row_id="row-uuid-att",
        attestation_hash="sha256:" + "aa" * 32,
        oss_event_id_ref="oss-attest-1",
        recorded_at="2026-08-01T20:35:00.000Z",
    )

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text",
                           "text": '{"event_id": "oss-attest-1"}'}]}}):
        with patch.object(etch_cli, "record_model_card_attestation",
                          return_value=fake_att_result) as att_mock:
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, [
                "hello",
                "--model-card-hash", "sha256:" + "aa" * 32,
                "--model-id", "claude-opus-4-7",
            ])
            assert result.exit_code == 0, result.output
            assert "event_id=oss-attest-1" in result.output
            assert "attestation_seq=7" in result.output
            att_mock.assert_called_once()
            call = att_mock.call_args
            assert call.kwargs["oss_event_id"] == "oss-attest-1"
            assert call.kwargs["attestation"]["model_id"] == "claude-opus-4-7"


def test_cli_attestation_failure_exits_7(monkeypatch):
    """Attestation call failing after base event succeeds → exit 7."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "proj_alpha")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_test")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text",
                           "text": '{"event_id": "oss-attest-2"}'}]}}):
        with patch.object(etch_cli, "record_model_card_attestation",
                          side_effect=AttestationError("mock: chain down")):
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, [
                "hello",
                "--model-card-hash", "sha256:" + "aa" * 32,
                "--model-id", "claude-opus-4-7",
            ])
            assert result.exit_code == 7
            assert "event_id=oss-attest-2" in result.output


def test_cli_no_attestation_flags_skips_the_fourth_call(monkeypatch):
    """No attestation flags → the fourth call is not made. Existing
    invocations without any Wave 1 #3 flag behave identically to
    v0.3.0."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "proj_alpha")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_test")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text", "text": '{"event_id": "oss-1"}'}]}}):
        with patch.object(etch_cli,
                          "record_model_card_attestation") as att_mock:
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, ["hello"])
            assert result.exit_code == 0, result.output
            att_mock.assert_not_called()
