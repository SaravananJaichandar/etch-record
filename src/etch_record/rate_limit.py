"""Client-side sliding-window rate limit for etch-record.

Guards against tight-loop misuse (dev accidentally emits a hot loop) that
would double-log through both the Claude Code Bash-invocation hook and
the etch-record semantic event.

Design choices:
  - Sliding window, 60 seconds, event-count based.
  - State persisted at ~/.etch-record/rate_state.json as a list of unix
    timestamps. Prune older-than-window on every read.
  - Fails OPEN: any state-file corruption or FS error is logged to
    stderr and treated as "no prior events". Rate limit exists to catch
    an accidental hot loop, not to be an authoritative security control;
    a broken state file must never block a legitimate event.
  - Default limit is 100 events/minute. Override via env
    ETCH_RATE_LIMIT_PER_MINUTE (int; set to 0 to disable entirely).
  - No inter-process locking. Concurrent invocations may double-count
    slightly; the goal is order-of-magnitude protection, not exactness.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

_STATE_DIR = Path.home() / ".etch-record"
_STATE_FILE = _STATE_DIR / "rate_state.json"
_WINDOW_SECONDS = 60.0
_DEFAULT_LIMIT_PER_MINUTE = 100


def _resolve_limit() -> int:
    """Return current per-minute limit. 0 or negative disables the check."""
    raw = os.environ.get("ETCH_RATE_LIMIT_PER_MINUTE", "").strip()
    if not raw:
        return _DEFAULT_LIMIT_PER_MINUTE
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_LIMIT_PER_MINUTE


def _load_timestamps(state_file: Path, now: float) -> list[float]:
    """Load and prune stale timestamps. Fails open on any error."""
    if not state_file.exists():
        return []
    try:
        raw = json.loads(state_file.read_text())
    except (OSError, json.JSONDecodeError):
        # Corrupt or unreadable state file: treat as empty. Rate limit
        # is best-effort; a broken state must never block a caller.
        return []
    if not isinstance(raw, list):
        return []
    cutoff = now - _WINDOW_SECONDS
    result: list[float] = []
    for item in raw:
        try:
            ts = float(item)
        except (TypeError, ValueError):
            continue
        if ts >= cutoff:
            result.append(ts)
    return result


def _write_timestamps(state_file: Path, timestamps: list[float]) -> None:
    """Persist pruned timestamps. Fails silently if the FS refuses."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(timestamps))
    except OSError as exc:
        # Never crash on rate-limit state persistence failure.
        print(
            f"etch-record: warning: could not persist rate-limit state "
            f"({exc}). Rate limiting may be inaccurate.",
            file=sys.stderr,
        )


def check_and_record(
    now: float | None = None,
    state_file: Path | None = None,
    limit_per_minute: int | None = None,
) -> tuple[bool, int, int]:
    """Consume one slot from the sliding window.

    Returns (allowed, count_in_window, limit). If allowed=False the
    caller should refuse to submit the event. If limit<=0 the check is
    disabled and this returns (True, 0, 0) without touching state.

    Args exist for tests; production callers pass nothing.
    """
    limit = _resolve_limit() if limit_per_minute is None else limit_per_minute
    if limit <= 0:
        return True, 0, 0
    now = time.time() if now is None else now
    sf = state_file if state_file is not None else _STATE_FILE

    timestamps = _load_timestamps(sf, now)
    count_before = len(timestamps)
    if count_before >= limit:
        # At or over the limit; refuse. Do NOT write this timestamp,
        # so the caller can retry after the window slides.
        return False, count_before, limit
    timestamps.append(now)
    _write_timestamps(sf, timestamps)
    return True, count_before + 1, limit
