"""CLI tests for the 2026-07-28 hardening: sensitive-arg guard,
--from-hook two-layer bind, --force-no-rate-limit bypass.

All tests use --dry-run so no live Etch call is made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from etch_record.cli import main


def _invoke(*args: str, env: dict[str, str] | None = None):
    runner = CliRunner()
    return runner.invoke(main, list(args), env=env or {})


class TestReasoningFile:
    def test_reasoning_file_replaces_reasoning(self, tmp_path: Path):
        f = tmp_path / "reasoning.txt"
        f.write_text("multi-line\nreasoning content")
        r = _invoke("desc", "--dry-run", "--reasoning-file", str(f))
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["reasoning"] == "multi-line\nreasoning content"
        )

    def test_reasoning_file_trailing_newline_stripped(self, tmp_path: Path):
        f = tmp_path / "reasoning.txt"
        f.write_text("just this\n")
        r = _invoke("desc", "--dry-run", "--reasoning-file", str(f))
        payload = json.loads(r.output)
        assert payload["arguments"]["reasoning"] == "just this"

    def test_reasoning_and_reasoning_file_together_rejected(
        self, tmp_path: Path,
    ):
        f = tmp_path / "reasoning.txt"
        f.write_text("from file")
        r = _invoke(
            "desc",
            "--dry-run",
            "--reasoning", "inline",
            "--reasoning-file", str(f),
        )
        assert r.exit_code != 0
        assert "only one of" in r.output.lower() or "usage" in r.output.lower()

    def test_reasoning_file_missing_rejected_by_click(self, tmp_path: Path):
        r = _invoke(
            "desc",
            "--dry-run",
            "--reasoning-file", str(tmp_path / "nope.txt"),
        )
        assert r.exit_code != 0


class TestDescriptionFile:
    def test_description_file_replaces_positional(self, tmp_path: Path):
        f = tmp_path / "desc.txt"
        f.write_text("real description here")
        # positional description still required by click; short label OK
        r = _invoke("from-file", "--dry-run", "--description-file", str(f))
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["description"] == "real description here"
        )

    def test_description_and_description_file_both_ok_file_wins(
        self, tmp_path: Path,
    ):
        """When both are set, file content becomes the recorded
        description. The positional is a short human label captured
        in shell history + the Layer A Bash-hook event, keeping the
        sensitive payload off argv - which is the whole point of
        --description-file."""
        f = tmp_path / "desc.txt"
        f.write_text("full description from file")
        r = _invoke(
            "short-label",
            "--dry-run",
            "--description-file", str(f),
        )
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["description"]
            == "full description from file"
        )


class TestLargeArgWarning:
    def test_large_reasoning_via_cli_warns(self):
        long_reasoning = "x" * 5000
        r = _invoke(
            "desc", "--dry-run",
            "--reasoning", long_reasoning,
        )
        assert r.exit_code == 0
        # click.echo(err=True) still goes to r.output for CliRunner by default
        # so we scan for the warning marker:
        assert "warning" in r.output.lower()
        assert "reasoning" in r.output.lower()

    def test_small_reasoning_no_warning(self):
        r = _invoke("desc", "--dry-run", "--reasoning", "short reason")
        assert r.exit_code == 0
        assert "warning" not in r.output.lower()

    def test_large_description_warns(self):
        long_desc = "d" * 5000
        r = _invoke(long_desc, "--dry-run")
        assert r.exit_code == 0
        assert "warning" in r.output.lower()

    def test_reasoning_file_bypasses_warning(self, tmp_path: Path):
        """When --reasoning-file is used the warning must not fire even
        if the resolved content is large: the file bypasses the argv path."""
        f = tmp_path / "big.txt"
        f.write_text("x" * 10000)
        r = _invoke("desc", "--dry-run", "--reasoning-file", str(f))
        assert r.exit_code == 0
        assert "warning" not in r.output.lower()


class TestFromHook:
    def test_from_hook_adds_layer_a_ref_and_tag(self):
        r = _invoke(
            "desc", "--dry-run",
            "--from-hook", "tool-use-abc-123",
        )
        assert r.exit_code == 0
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["evidence"]["layer_a_ref"]
            == "tool-use-abc-123"
        )
        assert "hook_bound" in payload["arguments"]["entities"]

    def test_from_hook_composes_with_existing_tags(self):
        r = _invoke(
            "desc", "--dry-run",
            "--tags", "research,x",
            "--from-hook", "abc",
        )
        payload = json.loads(r.output)
        assert set(payload["arguments"]["entities"]) == {
            "research", "x", "hook_bound",
        }

    def test_from_hook_composes_with_existing_evidence(self):
        r = _invoke(
            "desc", "--dry-run",
            "--evidence-json", '{"other": "field"}',
            "--from-hook", "abc",
        )
        payload = json.loads(r.output)
        assert payload["arguments"]["evidence"] == {
            "other": "field",
            "layer_a_ref": "abc",
        }

    def test_env_fallback_used_when_flag_absent(self):
        r = _invoke(
            "desc", "--dry-run",
            env={"ETCH_HOOK_TOOL_USE_ID": "from-env-999"},
        )
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["evidence"]["layer_a_ref"]
            == "from-env-999"
        )
        assert "hook_bound" in payload["arguments"]["entities"]

    def test_flag_overrides_env(self):
        r = _invoke(
            "desc", "--dry-run",
            "--from-hook", "flag-wins",
            env={"ETCH_HOOK_TOOL_USE_ID": "env-loses"},
        )
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["evidence"]["layer_a_ref"] == "flag-wins"
        )

    def test_env_empty_string_not_treated_as_ref(self):
        r = _invoke(
            "desc", "--dry-run",
            env={"ETCH_HOOK_TOOL_USE_ID": "   "},
        )
        payload = json.loads(r.output)
        assert "layer_a_ref" not in payload["arguments"]["evidence"]
        assert "hook_bound" not in payload["arguments"]["entities"]

    def test_hook_bound_not_duplicated_if_already_tagged(self):
        r = _invoke(
            "desc", "--dry-run",
            "--tags", "hook_bound,research",
            "--from-hook", "abc",
        )
        payload = json.loads(r.output)
        assert payload["arguments"]["entities"].count("hook_bound") == 1


class TestActionTime:
    """Tests for --action-time / --action-time-now (shipped 2026-07-28).

    Closes the drift between when the action happened in the world and
    when I signed it into the chain. Adds `action_time_utc` to evidence
    as an ISO-8601 UTC string. Everything else is unchanged.
    """

    def test_utc_z_suffix_accepted(self):
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "2026-07-28T14:03:00Z",
        )
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["evidence"]["action_time_utc"]
            == "2026-07-28T14:03:00Z"
        )

    def test_offset_timezone_converted_to_utc(self):
        """+05:30 IST 19:33 should normalize to 14:03 UTC on the same day."""
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "2026-07-28T19:33:00+05:30",
        )
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["evidence"]["action_time_utc"]
            == "2026-07-28T14:03:00Z"
        )

    def test_negative_offset_converted_to_utc(self):
        """-08:00 PST 06:03 should normalize to 14:03 UTC same day."""
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "2026-07-28T06:03:00-08:00",
        )
        payload = json.loads(r.output)
        assert (
            payload["arguments"]["evidence"]["action_time_utc"]
            == "2026-07-28T14:03:00Z"
        )

    def test_naive_datetime_rejected(self):
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "2026-07-28T14:03:00",
        )
        assert r.exit_code != 0
        assert "timezone" in r.output.lower()

    def test_garbage_rejected(self):
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "not-a-timestamp",
        )
        assert r.exit_code != 0
        assert "iso" in r.output.lower() or "action-time" in r.output.lower()

    def test_empty_rejected(self):
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "   ",
        )
        assert r.exit_code != 0

    def test_action_time_now_stamps_current_utc(self):
        """--action-time-now should stamp the invocation moment.
        We check shape + rough plausibility (year >= 2026)."""
        r = _invoke(
            "desc", "--dry-run",
            "--action-time-now",
        )
        assert r.exit_code == 0, r.output
        payload = json.loads(r.output)
        stamped = payload["arguments"]["evidence"]["action_time_utc"]
        # Shape: YYYY-MM-DDTHH:MM:SSZ
        assert len(stamped) == 20
        assert stamped.endswith("Z")
        assert stamped[4] == "-" and stamped[7] == "-" and stamped[10] == "T"
        # Rough sanity - year must be 2026 or later.
        year = int(stamped[:4])
        assert year >= 2026

    def test_both_action_time_flags_rejected(self):
        r = _invoke(
            "desc", "--dry-run",
            "--action-time", "2026-07-28T14:03:00Z",
            "--action-time-now",
        )
        assert r.exit_code != 0

    def test_action_time_composes_with_evidence_json(self):
        r = _invoke(
            "desc", "--dry-run",
            "--evidence-json", '{"other": "field"}',
            "--action-time", "2026-07-28T14:03:00Z",
        )
        payload = json.loads(r.output)
        assert payload["arguments"]["evidence"] == {
            "other": "field",
            "action_time_utc": "2026-07-28T14:03:00Z",
        }

    def test_action_time_composes_with_from_hook(self):
        r = _invoke(
            "desc", "--dry-run",
            "--from-hook", "tool-use-abc",
            "--action-time", "2026-07-28T14:03:00Z",
        )
        payload = json.loads(r.output)
        ev = payload["arguments"]["evidence"]
        assert ev["layer_a_ref"] == "tool-use-abc"
        assert ev["action_time_utc"] == "2026-07-28T14:03:00Z"

    def test_omitting_action_time_leaves_evidence_untouched(self):
        """No --action-time and no --action-time-now: no field added."""
        r = _invoke(
            "desc", "--dry-run",
            "--evidence-json", '{"k": "v"}',
        )
        payload = json.loads(r.output)
        assert payload["arguments"]["evidence"] == {"k": "v"}
        assert "action_time_utc" not in payload["arguments"]["evidence"]


class TestRateLimitBypass:
    def test_dry_run_never_hits_rate_limit(self, monkeypatch, tmp_path: Path):
        """Dry-run must not consume rate-limit slots - it does not
        produce a chain event and users may run many dry-runs."""
        # Force a tiny limit; call many dry-runs; none should exit 4.
        monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "1")
        # Point state file at a tmp path so real ~/.etch-record is untouched.
        monkeypatch.setattr(
            "etch_record.rate_limit._STATE_FILE",
            tmp_path / "rate_state.json",
        )
        for _ in range(10):
            r = _invoke("x", "--dry-run")
            assert r.exit_code == 0, r.output

    def test_force_no_rate_limit_flag_present(self):
        """The flag exists and does not break dry-run."""
        r = _invoke(
            "x", "--dry-run",
            "--force-no-rate-limit",
        )
        assert r.exit_code == 0


class TestBackwardCompatibility:
    """Every legacy invocation shape used in the 2026-07-27 and 2026-07-28
    marketing motion (dozens of signed events) must continue to work
    without changes."""

    def test_legacy_positional_only(self):
        r = _invoke("Just a description", "--dry-run")
        assert r.exit_code == 0
        payload = json.loads(r.output)
        assert payload["arguments"]["description"] == "Just a description"
        assert payload["arguments"]["reasoning"] == ""
        assert payload["arguments"]["evidence"] == {}
        assert payload["arguments"]["entities"] == []
        assert payload["arguments"]["success"] is True

    def test_legacy_full_shape(self):
        r = _invoke(
            "Real event description",
            "--tags", "a,b,c",
            "--reasoning", "why we did it",
            "--evidence-json", '{"k": "v"}',
            "--session-id", "custom",
            "--dry-run",
        )
        assert r.exit_code == 0
        payload = json.loads(r.output)
        assert payload["arguments"]["description"] == "Real event description"
        assert payload["arguments"]["reasoning"] == "why we did it"
        assert payload["arguments"]["evidence"] == {"k": "v"}
        assert payload["arguments"]["entities"] == ["a", "b", "c"]
        assert payload["arguments"]["session_id"] == "custom"

    def test_legacy_failed_flag(self):
        r = _invoke("x", "--failed", "--dry-run")
        payload = json.loads(r.output)
        assert payload["arguments"]["success"] is False
