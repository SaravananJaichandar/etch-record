"""Tests for the client-side sliding-window rate limit.

Locks the guard shipped 2026-07-28 against the tight-loop double-log
footgun (Claude Code Bash-hook auto-signs Layer A + explicit etch-record
Layer B; a runaway loop would double the chain volume with duplicate
content). Rate limit exists to catch accidental hot loops, not to be
an authoritative security control, so all failure modes fail OPEN.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from etch_record.rate_limit import (
    _DEFAULT_LIMIT_PER_MINUTE,
    _WINDOW_SECONDS,
    check_and_record,
)


@pytest.fixture()
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "rate_state.json"


class TestUnderLimit:
    def test_first_call_is_allowed(self, state_file):
        allowed, count, limit = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=5,
        )
        assert allowed is True
        assert count == 1
        assert limit == 5

    def test_state_file_created_after_first_call(self, state_file):
        assert not state_file.exists()
        check_and_record(now=1000.0, state_file=state_file, limit_per_minute=5)
        assert state_file.exists()
        data = json.loads(state_file.read_text())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0] == 1000.0

    def test_repeated_calls_accumulate_up_to_limit(self, state_file):
        for i in range(4):
            allowed, count, limit = check_and_record(
                now=1000.0 + i, state_file=state_file, limit_per_minute=5,
            )
            assert allowed, f"call {i} should be allowed"
        allowed, count, _ = check_and_record(
            now=1004.0, state_file=state_file, limit_per_minute=5,
        )
        assert allowed
        assert count == 5


class TestOverLimit:
    def test_at_limit_refuses_next(self, state_file):
        for i in range(5):
            check_and_record(
                now=1000.0 + i, state_file=state_file, limit_per_minute=5,
            )
        allowed, count, limit = check_and_record(
            now=1005.0, state_file=state_file, limit_per_minute=5,
        )
        assert allowed is False
        assert count == 5
        assert limit == 5

    def test_refused_call_does_not_consume_slot(self, state_file):
        """A refused call must NOT append to the state; otherwise
        repeated rate-limited calls could keep extending the window."""
        for i in range(5):
            check_and_record(
                now=1000.0 + i, state_file=state_file, limit_per_minute=5,
            )
        check_and_record(
            now=1005.0, state_file=state_file, limit_per_minute=5,
        )
        data = json.loads(state_file.read_text())
        assert len(data) == 5

    def test_window_slide_re_allows(self, state_file):
        """After the window slides past old events they no longer count."""
        for i in range(5):
            check_and_record(
                now=1000.0 + i, state_file=state_file, limit_per_minute=5,
            )
        # Jump forward past the whole window; all prior events drop off.
        allowed, count, _ = check_and_record(
            now=1000.0 + _WINDOW_SECONDS + 10.0,
            state_file=state_file,
            limit_per_minute=5,
        )
        assert allowed
        assert count == 1


class TestDisabledLimit:
    def test_zero_limit_disables(self, state_file):
        for _ in range(1000):
            allowed, count, limit = check_and_record(
                now=1000.0, state_file=state_file, limit_per_minute=0,
            )
            assert allowed
            assert count == 0
            assert limit == 0
        assert not state_file.exists(), (
            "disabled limit must not create state file"
        )

    def test_negative_limit_disables(self, state_file):
        allowed, _, _ = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=-1,
        )
        assert allowed


class TestFailOpen:
    """State-file failures must never block a legitimate event."""

    def test_corrupt_state_file_fails_open(self, state_file):
        state_file.write_text("{not json")
        allowed, count, _ = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=5,
        )
        assert allowed
        assert count == 1

    def test_state_file_wrong_shape_fails_open(self, state_file):
        state_file.write_text('{"unexpected": "shape"}')
        allowed, count, _ = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=5,
        )
        assert allowed
        assert count == 1

    def test_state_with_non_numeric_entries_skipped(self, state_file):
        """Bad entries mixed with good ones: keep the good, drop the bad."""
        state_file.write_text(json.dumps([1000.0, "bogus", None, 1001.0]))
        allowed, count, _ = check_and_record(
            now=1002.0, state_file=state_file, limit_per_minute=5,
        )
        assert allowed
        # 2 valid prior + 1 new = 3
        assert count == 3


class TestEnvOverride:
    def test_env_limit_read_from_environment(self, state_file, monkeypatch):
        """When limit_per_minute is None the value comes from env."""
        monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "2")
        for _ in range(2):
            allowed, _, limit = check_and_record(
                now=1000.0, state_file=state_file, limit_per_minute=None,
            )
            assert allowed
            assert limit == 2
        allowed, _, _ = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=None,
        )
        assert allowed is False

    def test_env_zero_disables(self, state_file, monkeypatch):
        monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "0")
        for _ in range(500):
            allowed, _, _ = check_and_record(
                now=1000.0, state_file=state_file, limit_per_minute=None,
            )
            assert allowed

    def test_env_unset_uses_default(self, state_file, monkeypatch):
        monkeypatch.delenv("ETCH_RATE_LIMIT_PER_MINUTE", raising=False)
        _, _, limit = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=None,
        )
        assert limit == _DEFAULT_LIMIT_PER_MINUTE

    def test_env_non_int_falls_back_to_default(self, state_file, monkeypatch):
        monkeypatch.setenv("ETCH_RATE_LIMIT_PER_MINUTE", "not-a-number")
        _, _, limit = check_and_record(
            now=1000.0, state_file=state_file, limit_per_minute=None,
        )
        assert limit == _DEFAULT_LIMIT_PER_MINUTE
