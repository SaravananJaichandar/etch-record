"""
Regression tests for Wave 1 #1 governance CLI flags + HTTP client.

Locks:

1. --uncertainty inline parses valid 'confidence:basis'.
2. --uncertainty rejects missing colon, non-float confidence,
   out-of-range confidence, empty basis.
3. --uncertainty + --uncertainty-file both set → UsageError.
4. Governance assembly returns None when no governance flags set
   (unchanged CLI behavior).
5. Governance assembly picks up policy_hash + authority_file combo.
6. Governance assembly picks up all 5 shapes when all flags set.
7. _read_json_object rejects non-dict JSON.
8. _read_json_list rejects non-list JSON.
9. governance_client.record_governance happy path returns a
   GovernanceResult with the server's fields.
10. governance_client surfaces `insufficient_scope` as a
    GovernanceError with a hint about mcp:write.
11. governance_client surfaces `validation_failed` details.
12. CLI end-to-end: when a governance flag is set, both record_event
    AND record_governance are called (record_event first, then the
    HTTP call).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import click
import httpx
import pytest
from click.testing import CliRunner

from etch_record import cli as etch_cli
from etch_record.cli import (
    _assemble_governance_from_flags,
    _parse_uncertainty_inline,
    _read_json_list,
    _read_json_object,
)
from etch_record.config import Config
from etch_record.governance_client import (
    GovernanceError,
    GovernanceResult,
    record_governance,
)


# ---------------------------------------------------------------------------
# _parse_uncertainty_inline
# ---------------------------------------------------------------------------


def test_uncertainty_inline_valid():
    result = _parse_uncertainty_inline("0.87:evidence-hash-match-rate")
    assert result == {
        "confidence": 0.87,
        "basis": "evidence-hash-match-rate",
    }


def test_uncertainty_inline_zero_and_one_boundary():
    assert _parse_uncertainty_inline("0.0:x")["confidence"] == 0.0
    assert _parse_uncertainty_inline("1.0:y")["confidence"] == 1.0


def test_uncertainty_inline_missing_colon_rejected():
    with pytest.raises(click.UsageError, match="confidence:basis"):
        _parse_uncertainty_inline("0.87 no colon here")


def test_uncertainty_inline_non_float_confidence_rejected():
    with pytest.raises(click.UsageError, match="must be a float"):
        _parse_uncertainty_inline("high:some-basis")


def test_uncertainty_inline_confidence_out_of_range_rejected():
    with pytest.raises(click.UsageError, match=r"\[0\.0, 1\.0\]"):
        _parse_uncertainty_inline("1.5:basis")
    with pytest.raises(click.UsageError, match=r"\[0\.0, 1\.0\]"):
        _parse_uncertainty_inline("-0.1:basis")


def test_uncertainty_inline_empty_basis_rejected():
    with pytest.raises(click.UsageError, match="basis must be non-empty"):
        _parse_uncertainty_inline("0.5:")


# ---------------------------------------------------------------------------
# JSON file readers
# ---------------------------------------------------------------------------


def test_read_json_object_rejects_list(tmp_path):
    p = tmp_path / "arr.json"
    p.write_text('["not", "an", "object"]')
    with pytest.raises(click.UsageError, match="must be a JSON object"):
        _read_json_object(p, "--authority-file")


def test_read_json_object_rejects_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not: valid}")
    with pytest.raises(click.UsageError, match="could not be loaded"):
        _read_json_object(p, "--authority-file")


def test_read_json_list_rejects_object(tmp_path):
    p = tmp_path / "obj.json"
    p.write_text('{"not": "a list"}')
    with pytest.raises(click.UsageError, match="must be a JSON array"):
        _read_json_list(p, "--assumptions-file")


# ---------------------------------------------------------------------------
# Governance assembly
# ---------------------------------------------------------------------------


def test_assemble_returns_none_when_no_flags_set():
    result = _assemble_governance_from_flags(
        policy_hash=None,
        authority_file=None,
        assumptions_file=None,
        uncertainty=None,
        uncertainty_file=None,
        invalidation_file=None,
    )
    assert result is None


def test_assemble_with_only_policy_hash():
    result = _assemble_governance_from_flags(
        policy_hash="sha256:" + "aa" * 32,
        authority_file=None,
        assumptions_file=None,
        uncertainty=None,
        uncertainty_file=None,
        invalidation_file=None,
    )
    assert result == {"policy_hash": "sha256:" + "aa" * 32}


def test_assemble_with_authority_and_uncertainty(tmp_path):
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({
        "identity": "compliance@acme.example",
        "scope": ["kyc"],
        "expires_at": "2026-12-31T23:59:59Z",
    }))
    result = _assemble_governance_from_flags(
        policy_hash="sha256:" + "bb" * 32,
        authority_file=auth,
        assumptions_file=None,
        uncertainty="0.9:matched-baseline",
        uncertainty_file=None,
        invalidation_file=None,
    )
    assert result["policy_hash"] == "sha256:" + "bb" * 32
    assert result["authority"]["identity"] == "compliance@acme.example"
    assert result["uncertainty"] == {
        "confidence": 0.9, "basis": "matched-baseline",
    }
    assert "assumptions" not in result
    assert "invalidation_conditions" not in result


def test_assemble_with_all_five_fields(tmp_path):
    (tmp_path / "auth.json").write_text(json.dumps({
        "identity": "a", "scope": [], "expires_at": None,
    }))
    (tmp_path / "assum.json").write_text(json.dumps([
        {"claim": "SOP v3 is current", "source_ref": "doc:xyz"},
    ]))
    (tmp_path / "unc.json").write_text(json.dumps({
        "confidence": 0.5, "basis": "coin-flip-baseline",
    }))
    (tmp_path / "inv.json").write_text(json.dumps([
        {"if": "SOP changes", "then": "re-approve required"},
    ]))
    result = _assemble_governance_from_flags(
        policy_hash="sha256:" + "cc" * 32,
        authority_file=tmp_path / "auth.json",
        assumptions_file=tmp_path / "assum.json",
        uncertainty=None,
        uncertainty_file=tmp_path / "unc.json",
        invalidation_file=tmp_path / "inv.json",
    )
    assert set(result.keys()) == {
        "policy_hash", "authority", "assumptions",
        "uncertainty", "invalidation_conditions",
    }


def test_assemble_rejects_both_uncertainty_forms(tmp_path):
    unc_file = tmp_path / "unc.json"
    unc_file.write_text('{"confidence": 0.5, "basis": "b"}')
    with pytest.raises(click.UsageError, match="not both"):
        _assemble_governance_from_flags(
            policy_hash=None,
            authority_file=None,
            assumptions_file=None,
            uncertainty="0.7:x",
            uncertainty_file=unc_file,
            invalidation_file=None,
        )


# ---------------------------------------------------------------------------
# governance_client HTTP paths (mocked)
# ---------------------------------------------------------------------------


CFG = Config(
    project_id="proj_alpha",
    app_token="wm_test_token",
    base_url="https://etch.test",
)


def _mock_client_from(handler) -> httpx.Client:
    """Build an httpx.Client whose transport is a MockTransport driven
    by `handler`. Tests pass this into record_governance() directly."""
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_governance_client_happy_path():
    def handler(request):
        body = json.loads(request.content)
        assert body["oss_event_id"] == "oss-abc"
        assert body["governance"]["policy_hash"] == "sha256:" + "aa" * 32
        return httpx.Response(200, json={
            "status": "recorded",
            "etch_chain_seq": 1,
            "etch_row_id": "row-uuid",
            "governance_hash": "sha256:" + "hh" * 32,
            "oss_event_id_ref": "oss-abc",
            "recorded_at": "2026-08-01T10:00:00.000Z",
        })

    with _mock_client_from(handler) as client:
        result = record_governance(
            CFG, "oss-abc",
            {"policy_hash": "sha256:" + "aa" * 32},
            client=client,
        )
    assert isinstance(result, GovernanceResult)
    assert result.etch_chain_seq == 1
    assert result.oss_event_id_ref == "oss-abc"


def test_governance_client_insufficient_scope_error():
    def handler(request):
        return httpx.Response(403, json={
            "error": "insufficient_scope",
            "required_scope": "mcp:write",
            "token_scopes": ["mcp:read"],
        })

    with _mock_client_from(handler) as client:
        with pytest.raises(GovernanceError, match="mcp:write"):
            record_governance(
                CFG, "oss-abc",
                {"policy_hash": "sha256:" + "aa" * 32},
                client=client,
            )


def test_governance_client_validation_failed_surfaces_details():
    def handler(request):
        return httpx.Response(400, json={
            "error": "validation_failed",
            "details": [
                {"type": "value_error", "loc": ["governance"],
                 "msg": "empty object", "input": {}},
            ],
        })

    with _mock_client_from(handler) as client:
        with pytest.raises(GovernanceError, match="empty object"):
            record_governance(CFG, "oss-abc", {}, client=client)


def test_governance_client_transport_failure_wrapped():
    def handler(request):
        raise httpx.ConnectError("simulated")

    with _mock_client_from(handler) as client:
        with pytest.raises(GovernanceError, match="transport failed"):
            record_governance(
                CFG, "oss-abc",
                {"policy_hash": "sha256:" + "aa" * 32},
                client=client,
            )


# ---------------------------------------------------------------------------
# CLI end-to-end: two-call sequence when governance flag is set
# ---------------------------------------------------------------------------


def test_cli_without_governance_flags_makes_one_call(tmp_path, monkeypatch):
    """No governance flags → only record_event is called (existing
    behavior preserved). CLI exits 0."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "proj_alpha")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_test")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text", "text": '{"event_id": "oss-1"}'}]}}):
        with patch.object(etch_cli, "record_governance") as gov_mock:
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, ["hello world"])
            assert result.exit_code == 0
            assert "event_id=oss-1" in result.output
            gov_mock.assert_not_called()


def test_cli_with_policy_hash_calls_governance(tmp_path, monkeypatch):
    """A single governance flag triggers the second call. CLI exits 0
    and prints both event_id and governance_seq lines."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "proj_alpha")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_test")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text", "text": '{"event_id": "oss-2"}'}]}}):
        with patch.object(etch_cli, "record_governance",
                          return_value=GovernanceResult(
                              etch_chain_seq=42,
                              etch_row_id="row-2",
                              governance_hash="sha256:" + "hh" * 32,
                              oss_event_id_ref="oss-2",
                              recorded_at="2026-08-01T10:00:00.000Z",
                          )) as gov_mock:
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, [
                "hello", "--policy-hash", "sha256:" + "aa" * 32,
            ])
            assert result.exit_code == 0, result.output
            assert "event_id=oss-2" in result.output
            assert "governance_seq=42" in result.output
            # Governance was called with the OSS event_id
            call = gov_mock.call_args
            assert call.args[1] == "oss-2"
            assert call.args[2]["policy_hash"] == "sha256:" + "aa" * 32


def test_cli_governance_failure_exits_5(tmp_path, monkeypatch):
    """When governance fails, exit code is 5 (distinguishable from
    record_event failure = 2). Base event was already recorded, so the
    caller has the event_id to retry against."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "proj_alpha")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_test")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text", "text": '{"event_id": "oss-3"}'}]}}):
        with patch.object(etch_cli, "record_governance",
                          side_effect=GovernanceError("mock: rekor down")):
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, [
                "hello", "--policy-hash", "sha256:" + "aa" * 32,
            ])
            assert result.exit_code == 5
            assert "event_id=oss-3" in result.output
            assert "mock: rekor down" in result.output
