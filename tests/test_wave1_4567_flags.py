"""
Tests for Wave 1 #4-#7 flags on the etch-record CLI.

Locks the per-item helpers + the four HTTP client shims. The full
"all layers independent" property is regression-covered by the Wave
1 #3 tests already; here we add per-item CLI end-to-end coverage.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from etch_record import cli as etch_cli
from etch_record.cli import (
    _prepare_autonomy_level,
    _prepare_risk_score,
    _prepare_signed_dissent,
    _prepare_supersession_edge,
)
from etch_record.config import Config
from etch_record.wave1_4567_clients import (
    AutonomyError,
    AutonomyResult,
    DissentError,
    DissentResult,
    RiskScoreError,
    RiskScoreResult,
    SupersessionError,
    SupersessionResult,
    record_autonomy_level,
    record_session_risk_score,
    record_signed_dissent,
    record_supersession_edge,
)


CFG = Config(
    project_id="proj_alpha",
    app_token="wm_test",
    base_url="https://etch.test",
)


def _mock(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _write_ed25519_pem(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey]:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "dissent.pem"
    p.write_bytes(pem)
    return p, priv


# ---------------------------------------------------------------------------
# _prepare_* helpers
# ---------------------------------------------------------------------------


class TestPrepareRiskScore:
    def test_returns_none_when_no_flags(self):
        assert _prepare_risk_score(None, None, None) is None

    def test_requires_all_three(self):
        with pytest.raises(Exception, match="--risk-vendor"):
            _prepare_risk_score(0.5, None, "basis")

    def test_rejects_out_of_range(self):
        with pytest.raises(Exception, match=r"\[0.0, 1.0\]"):
            _prepare_risk_score(1.5, "v", "b")

    def test_happy(self):
        p = _prepare_risk_score(0.73, "assury-enforce", "policy_v3")
        assert p["score"] == 0.73
        assert p["vendor"] == "assury-enforce"
        assert "attested_at" in p


class TestPrepareAutonomyLevel:
    def test_returns_none_when_no_level(self):
        assert _prepare_autonomy_level(None, "standard-L0-L3", None) is None

    def test_happy_standard(self):
        p = _prepare_autonomy_level("L2", "standard-L0-L3", "why")
        assert p["level"] == "L2"
        assert p["level_scheme"] == "standard-L0-L3"
        assert p["rationale"] == "why"

    def test_happy_custom(self):
        p = _prepare_autonomy_level("CUSTOM_X", "buyer-custom", None)
        assert p["level"] == "CUSTOM_X"
        assert p["level_scheme"] == "buyer-custom"
        assert "rationale" not in p


class TestPrepareSupersession:
    def test_returns_none_when_no_flags(self):
        assert _prepare_supersession_edge(None, None, "", None) is None

    def test_requires_intent(self):
        with pytest.raises(Exception, match="--supersession-intent"):
            _prepare_supersession_edge("oss-old", None, "", None)

    def test_happy_with_depends_on(self):
        e = _prepare_supersession_edge(
            "oss-old", "correction", "a,b,c", "why",
        )
        assert e["superseded_oss_event_id"] == "oss-old"
        assert e["intent"] == "correction"
        assert e["depends_on"] == ["a", "b", "c"]
        assert e["rationale"] == "why"


class TestPrepareSignedDissent:
    def test_returns_none_when_no_flags(self):
        assert _prepare_signed_dissent(None, None, None) is None

    def test_requires_all_three(self, tmp_path):
        p, _ = _write_ed25519_pem(tmp_path)
        with pytest.raises(Exception, match="--dissent-rationale"):
            _prepare_signed_dissent(p, "someone", None)

    def test_happy(self, tmp_path):
        p, _ = _write_ed25519_pem(tmp_path)
        result = _prepare_signed_dissent(
            p, "ombudsman-1", "PII risk",
        )
        dissent, priv, pubkey_ref = result
        assert dissent["dissenter_id"] == "ombudsman-1"
        assert dissent["rationale"] == "PII risk"
        assert pubkey_ref.startswith("sha256:")


# ---------------------------------------------------------------------------
# HTTP client shims
# ---------------------------------------------------------------------------


def test_risk_score_client_happy():
    def handler(req):
        body = json.loads(req.content)
        assert body["oss_event_id"] == "oss-1"
        assert body["risk_score"]["score"] == 0.73
        return httpx.Response(200, json={
            "status": "recorded", "etch_chain_seq": 1,
            "etch_row_id": "r1", "risk_hash": "sha256:aa",
            "oss_event_id_ref": "oss-1", "recorded_at": "t"})
    with _mock(handler) as c:
        r = record_session_risk_score(
            CFG, "oss-1",
            {"score": 0.73, "vendor": "v", "basis": "b",
             "attested_at": "t"},
            client=c,
        )
    assert isinstance(r, RiskScoreResult)
    assert r.risk_hash == "sha256:aa"


def test_autonomy_client_happy():
    def handler(req):
        return httpx.Response(200, json={
            "status": "recorded", "etch_chain_seq": 2,
            "etch_row_id": "r2", "autonomy_hash": "sha256:bb",
            "oss_event_id_ref": "oss-2", "recorded_at": "t"})
    with _mock(handler) as c:
        r = record_autonomy_level(
            CFG, "oss-2",
            {"level": "L2", "level_scheme": "standard-L0-L3",
             "attested_at": "t"},
            client=c,
        )
    assert isinstance(r, AutonomyResult)
    assert r.autonomy_hash == "sha256:bb"


def test_supersession_client_happy():
    def handler(req):
        body = json.loads(req.content)
        assert body["superseding_oss_event_id"] == "oss-new"
        return httpx.Response(200, json={
            "status": "recorded", "etch_chain_seq": 3,
            "etch_row_id": "r3", "edge_hash": "sha256:cc",
            "superseding_oss_event_id": "oss-new",
            "superseded_oss_event_id": "oss-old",
            "recorded_at": "t"})
    with _mock(handler) as c:
        r = record_supersession_edge(
            CFG, "oss-new",
            {"superseded_oss_event_id": "oss-old",
             "intent": "correction", "depends_on": [],
             "attested_at": "t"},
            client=c,
        )
    assert isinstance(r, SupersessionResult)
    assert r.edge_hash == "sha256:cc"


def test_dissent_client_happy():
    def handler(req):
        body = json.loads(req.content)
        assert body["dissent"]["dissenter_id"] == "ombudsman-1"
        assert body["signature_hex"] == "aa" * 64
        return httpx.Response(200, json={
            "status": "recorded", "etch_chain_seq": 4,
            "etch_row_id": "r4", "dissent_hash": "sha256:dd",
            "oss_event_id_ref": "oss-4", "recorded_at": "t"})
    with _mock(handler) as c:
        r = record_signed_dissent(
            CFG, "oss-4",
            dissent={"dissenter_id": "ombudsman-1",
                     "rationale": "why", "attested_at": "t"},
            signature_hex="aa" * 64,
            pubkey_ref="sha256:" + "00" * 32,
            client=c,
        )
    assert isinstance(r, DissentResult)
    assert r.dissent_hash == "sha256:dd"


def test_risk_client_bubbles_errors():
    def handler(req):
        return httpx.Response(400, json={"error": "validation_failed"})
    with _mock(handler) as c:
        with pytest.raises(RiskScoreError, match="validation_failed"):
            record_session_risk_score(
                CFG, "oss", {"score": 0.5, "vendor": "v", "basis": "b",
                             "attested_at": "t"}, client=c,
            )


# ---------------------------------------------------------------------------
# CLI end-to-end — each new layer reaches its endpoint independently
# ---------------------------------------------------------------------------


def _mcp_response(event_id: str) -> dict:
    return {"result": {"content": [{
        "type": "text", "text": '{"event_id": "' + event_id + '"}'}]}}


def test_cli_risk_only_reaches_fourth_call(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    fake = RiskScoreResult(1, "r", "sha256:aa", "oss-r", "t")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-r")):
        with patch.object(etch_cli, "record_session_risk_score",
                          return_value=fake) as mock:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, [
                "hello",
                "--risk-score", "0.73",
                "--risk-vendor", "assury-enforce",
                "--risk-basis", "policy_v3",
            ])
            assert r.exit_code == 0, r.output
            assert "risk_seq=1" in r.output
            mock.assert_called_once()


def test_cli_autonomy_only_reaches_call(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    fake = AutonomyResult(1, "r", "sha256:aa", "oss-a", "t")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-a")):
        with patch.object(etch_cli, "record_autonomy_level",
                          return_value=fake) as mock:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, [
                "hello", "--autonomy-level", "L2",
            ])
            assert r.exit_code == 0, r.output
            assert "autonomy_seq=1" in r.output
            mock.assert_called_once()


def test_cli_supersession_only_reaches_call(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    fake = SupersessionResult(1, "r", "sha256:cc",
                              "oss-new", "oss-old", "t")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-new")):
        with patch.object(etch_cli, "record_supersession_edge",
                          return_value=fake) as mock:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, [
                "hello",
                "--supersedes", "oss-old",
                "--supersession-intent", "correction",
            ])
            assert r.exit_code == 0, r.output
            assert "supersession_seq=1" in r.output
            mock.assert_called_once()


def test_cli_dissent_only_reaches_call(monkeypatch, tmp_path):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    p, _ = _write_ed25519_pem(tmp_path)
    fake = DissentResult(1, "r", "sha256:dd", "oss-d", "t")
    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-d")):
        with patch.object(etch_cli, "record_signed_dissent",
                          return_value=fake) as mock:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, [
                "hello",
                "--dissent-privkey-file", str(p),
                "--dissenter-id", "ombudsman-1",
                "--dissent-rationale", "PII risk",
            ])
            assert r.exit_code == 0, r.output
            assert "dissent_seq=1" in r.output
            mock.assert_called_once()


def test_cli_no_wave_flags_makes_only_base_call(monkeypatch):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value=_mcp_response("oss-z")):
        with patch.object(etch_cli, "record_session_risk_score") as m1, \
             patch.object(etch_cli, "record_autonomy_level") as m2, \
             patch.object(etch_cli, "record_supersession_edge") as m3, \
             patch.object(etch_cli, "record_signed_dissent") as m4:
            runner = CliRunner()
            r = runner.invoke(etch_cli.main, ["hello"])
            assert r.exit_code == 0
            m1.assert_not_called()
            m2.assert_not_called()
            m3.assert_not_called()
            m4.assert_not_called()
