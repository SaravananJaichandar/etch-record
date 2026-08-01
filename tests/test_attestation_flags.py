"""
Tests for the Wave 1 #3 model-card attestation flags on etch-record CLI.

Covers:
- attestation_client happy path + error paths (mocked httpx).
- _assemble_attestation_from_flags: all-or-nothing validation, optional
  field passthrough, model_id required alongside model_card_hash.
"""

from __future__ import annotations

import json

import httpx
import pytest

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
