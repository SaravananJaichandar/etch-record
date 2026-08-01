"""
Tests for the Wave 2 #8 bulk import mode on etch-record CLI.

Covers:
- read_events_from_file: .jsonl, .json array, .json {events:...},
  size limits, malformed input.
- import_events HTTP client: happy path + error bubbling.
- CLI end-to-end: import mode runs, single-event flow is skipped.
- --import-format alone or --import-file alone is a usage error.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner

from etch_record import cli as etch_cli
from etch_record.config import Config
from etch_record.import_client import (
    ImportError,
    ImportResult,
    import_events,
    read_events_from_file,
)


CFG = Config(
    project_id="p",
    app_token="wm_t",
    base_url="https://etch.test",
)


# ---------------------------------------------------------------------------
# read_events_from_file
# ---------------------------------------------------------------------------


def test_read_jsonl(tmp_path):
    p = tmp_path / "in.jsonl"
    p.write_text('{"a":1}\n{"b":2}\n\n{"c":3}\n')
    events = read_events_from_file(p)
    assert events == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_read_ndjson_alias(tmp_path):
    p = tmp_path / "in.ndjson"
    p.write_text('{"a":1}\n{"b":2}\n')
    assert read_events_from_file(p) == [{"a": 1}, {"b": 2}]


def test_read_json_array(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps([{"a": 1}, {"b": 2}]))
    assert read_events_from_file(p) == [{"a": 1}, {"b": 2}]


def test_read_json_events_key(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps({"events": [{"a": 1}], "trailing_meta": 42}))
    assert read_events_from_file(p) == [{"a": 1}]


def test_read_missing_file(tmp_path):
    with pytest.raises(ImportError, match="cannot read"):
        read_events_from_file(tmp_path / "no_such")


def test_read_bad_jsonl_line(tmp_path):
    p = tmp_path / "in.jsonl"
    p.write_text('{"a":1}\nnot valid\n')
    with pytest.raises(ImportError, match="line 2"):
        read_events_from_file(p)


def test_read_bad_json_body(tmp_path):
    p = tmp_path / "in.json"
    p.write_text("{oops")
    with pytest.raises(ImportError, match="not valid JSON"):
        read_events_from_file(p)


def test_read_unexpected_json_shape(tmp_path):
    p = tmp_path / "in.json"
    p.write_text('"just a string"')
    with pytest.raises(ImportError, match="must be a JSON array"):
        read_events_from_file(p)


def test_read_empty_events_rejected(tmp_path):
    p = tmp_path / "in.jsonl"
    p.write_text("\n\n")
    with pytest.raises(ImportError, match="zero events"):
        read_events_from_file(p)


def test_read_over_batch_max_rejected(tmp_path):
    p = tmp_path / "in.jsonl"
    p.write_text(("\n".join('{"a":1}' for _ in range(501))) + "\n")
    with pytest.raises(ImportError, match="exceeding batch max"):
        read_events_from_file(p)


def test_read_non_object_event_rejected(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps([{"a": 1}, "string-not-object"]))
    with pytest.raises(ImportError, match="index 1"):
        read_events_from_file(p)


# ---------------------------------------------------------------------------
# import_events HTTP client
# ---------------------------------------------------------------------------


def _mock(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_import_client_happy_path():
    def handler(req):
        body = json.loads(req.content)
        assert body["format"] == "custom"
        assert len(body["events"]) == 2
        return httpx.Response(200, json={
            "status": "imported", "count": 2,
            "kinds": {"governance_record": 2},
            "first_etch_chain_seq": 1, "last_etch_chain_seq": 2,
            "skipped": [],
        })
    with _mock(handler) as c:
        r = import_events(
            CFG, "custom",
            [{"kind": "governance_record", "payload": {"a": 1}},
             {"kind": "governance_record", "payload": {"a": 2}}],
            client=c,
        )
    assert isinstance(r, ImportResult)
    assert r.count == 2
    assert r.kinds == {"governance_record": 2}


def test_import_client_bubbles_400():
    def handler(req):
        return httpx.Response(400, json={
            "error": "unknown_format",
            "format": "invented",
            "supported": ["custom", "otel-gen-ai"],
        })
    with _mock(handler) as c:
        with pytest.raises(ImportError, match="unknown_format"):
            import_events(CFG, "invented", [{"a": 1}], client=c)


# ---------------------------------------------------------------------------
# CLI end-to-end
# ---------------------------------------------------------------------------


def test_cli_import_mode_reaches_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    input_file = tmp_path / "spans.jsonl"
    input_file.write_text('{"kind":"governance_record","payload":{"a":1}}\n')

    fake = ImportResult(
        count=1, kinds={"governance_record": 1},
        first_etch_chain_seq=1, last_etch_chain_seq=1,
        skipped=[],
    )
    with patch.object(etch_cli, "import_events",
                      return_value=fake) as mock:
        with patch.object(etch_cli, "record_event") as base_mock:
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, [
                "unused-description",
                "--import-format", "custom",
                "--import-file", str(input_file),
            ])
            assert result.exit_code == 0, result.output
            assert "imported=1" in result.output
            assert "governance_record" in result.output
            mock.assert_called_once()
            # Single-event flow was SKIPPED — no base MCP call.
            base_mock.assert_not_called()


def test_cli_import_file_without_format_errors(tmp_path, monkeypatch):
    """--import-file alone is a usage error, not silent single-event mode."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    f = tmp_path / "x.jsonl"
    f.write_text('{"a":1}\n')
    runner = CliRunner()
    result = runner.invoke(etch_cli.main, [
        "hello",
        "--import-file", str(f),
    ])
    assert result.exit_code == 2
    assert "--import-format" in result.output


def test_cli_import_format_without_file_errors(monkeypatch):
    """--import-format alone is a usage error."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    runner = CliRunner()
    result = runner.invoke(etch_cli.main, [
        "hello",
        "--import-format", "custom",
    ])
    assert result.exit_code == 2
    assert "--import-file" in result.output


def test_cli_no_import_flags_stays_in_single_event_mode(monkeypatch):
    """No import flags → main() proceeds through the normal single-
    event flow. Confirmed by patching record_event and observing it
    is called."""
    monkeypatch.setenv("ETCH_PROJECT_ID", "p")
    monkeypatch.setenv("ETCH_APP_TOKEN", "wm_t")
    monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")

    with patch.object(etch_cli, "record_event",
                      return_value={"result": {"content": [
                          {"type": "text",
                           "text": '{"event_id":"oss-single"}'}]}}):
        with patch.object(etch_cli, "import_events") as import_mock:
            runner = CliRunner()
            result = runner.invoke(etch_cli.main, ["hello"])
            assert result.exit_code == 0, result.output
            assert "event_id=oss-single" in result.output
            import_mock.assert_not_called()
