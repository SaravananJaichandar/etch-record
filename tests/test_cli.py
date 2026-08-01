"""Smoke tests for etch-record CLI.

Uses --dry-run so tests don't require live Etch credentials or network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from etch_record.cli import _load_evidence, _parse_tags, main
from etch_record.config import ConfigError, load


def _invoke(*args: str):
    runner = CliRunner()
    return runner.invoke(main, list(args))


class TestParseTags:
    def test_empty(self):
        assert _parse_tags(None) == []
        assert _parse_tags("") == []

    def test_single(self):
        assert _parse_tags("research") == ["research"]

    def test_multi_with_whitespace(self):
        assert _parse_tags("research, x , launch") == ["research", "x", "launch"]

    def test_drops_empty_tokens(self):
        assert _parse_tags("a,,b, ,c") == ["a", "b", "c"]


class TestLoadEvidence:
    def test_no_evidence(self):
        assert _load_evidence(None, None) == {}

    def test_json_object(self):
        assert _load_evidence('{"k": 1}', None) == {"k": 1}

    def test_json_non_object_rejected(self):
        import click
        with pytest.raises(click.UsageError):
            _load_evidence("[1, 2, 3]", None)

    def test_invalid_json_rejected(self):
        import click
        with pytest.raises(click.UsageError):
            _load_evidence("{bad", None)

    def test_both_paths_rejected(self, tmp_path: Path):
        import click
        f = tmp_path / "e.json"
        f.write_text("{}")
        with pytest.raises(click.UsageError):
            _load_evidence('{"k":1}', f)

    def test_file_load(self, tmp_path: Path):
        f = tmp_path / "e.json"
        f.write_text('{"contact": "alice"}')
        assert _load_evidence(None, f) == {"contact": "alice"}


class TestDryRunNoConfigRequired:
    """Dry-run path must NOT require ETCH env vars, since it never
    calls the API. Otherwise we couldn't test the CLI without live creds."""

    def test_dry_run_prints_payload_without_env(self, monkeypatch):
        monkeypatch.delenv("ETCH_PROJECT_ID", raising=False)
        monkeypatch.delenv("ETCH_APP_TOKEN", raising=False)
        r = _invoke("some description", "--dry-run", "--tags", "a,b")
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        assert payload["name"] == "record_event"
        assert payload["arguments"]["description"] == "some description"
        assert payload["arguments"]["entities"] == ["a", "b"]
        assert payload["arguments"]["event_type"] == "tool_call"
        assert payload["arguments"]["success"] is True

    def test_dry_run_with_failed_flag(self):
        r = _invoke("boom", "--dry-run", "--failed")
        assert r.exit_code == 0
        payload = json.loads(r.output)
        assert payload["arguments"]["success"] is False

    def test_dry_run_default_session_is_dated(self, monkeypatch):
        monkeypatch.delenv("ETCH_PROJECT_ID", raising=False)
        r = _invoke("x", "--dry-run")
        payload = json.loads(r.output)
        assert payload["arguments"]["session_id"].startswith("etch-record-")

    def test_dry_run_custom_session(self):
        r = _invoke("x", "--dry-run", "--session-id", "custom-session-1")
        payload = json.loads(r.output)
        assert payload["arguments"]["session_id"] == "custom-session-1"

    def test_dry_run_evidence_json(self):
        r = _invoke(
            "posted",
            "--dry-run",
            "--evidence-json",
            '{"url": "https://x.com/foo"}',
        )
        payload = json.loads(r.output)
        assert payload["arguments"]["evidence"] == {"url": "https://x.com/foo"}


class TestLoadConfigStrict:
    def test_missing_env_raises(self, monkeypatch):
        monkeypatch.delenv("ETCH_PROJECT_ID", raising=False)
        monkeypatch.delenv("ETCH_APP_TOKEN", raising=False)
        with pytest.raises(ConfigError) as exc:
            load()
        msg = str(exc.value)
        assert "ETCH_PROJECT_ID" in msg
        assert "ETCH_APP_TOKEN" in msg

    def test_base_url_default(self, monkeypatch):
        monkeypatch.setenv("ETCH_PROJECT_ID", "p")
        monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
        monkeypatch.delenv("ETCH_BASE_URL", raising=False)
        cfg = load()
        assert cfg.base_url == "https://etch.systems"

    def test_base_url_override(self, monkeypatch):
        monkeypatch.setenv("ETCH_PROJECT_ID", "p")
        monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
        monkeypatch.setenv("ETCH_BASE_URL", "http://localhost:8000")
        cfg = load()
        assert cfg.base_url == "http://localhost:8000"

    def test_missing_env_exit_1_via_cli(self, monkeypatch):
        monkeypatch.delenv("ETCH_PROJECT_ID", raising=False)
        monkeypatch.delenv("ETCH_APP_TOKEN", raising=False)
        # No --dry-run this time; forces config load
        r = _invoke("would fail")
        assert r.exit_code == 1
        assert "ETCH_PROJECT_ID" in r.output
