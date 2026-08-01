"""HTTP client for Wave 2 #8 ingest-adapter endpoint (2026-08-02).

Companion to governance_client / authority_client / attestation_client
/ wave1_4567_clients. Where those clients POST one sub-record per
call, this module POSTs a BATCH of events from a JSONL / JSON file
translated by a named format adapter server-side.

Usage from the CLI:
  etch-record --import-format otel-gen-ai --import-file spans.jsonl

The import mode is mutually exclusive with the single-event mode:
when --import-file is set, the positional description arg is ignored
and no MCP record_event call is made.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 60.0
_MAX_EVENTS_PER_BATCH = 500


class ImportError(RuntimeError):
    """Raised when the import call fails in a way the CLI should
    surface with a friendly stderr message + exit code 12."""


@dataclass(frozen=True)
class ImportResult:
    count: int
    kinds: dict
    first_etch_chain_seq: Optional[int]
    last_etch_chain_seq: Optional[int]
    skipped: list


def read_events_from_file(path: Path) -> list[dict]:
    """Read events from a file.

    Supported formats:
    - `.jsonl` (or `.ndjson`) — one JSON object per line
    - `.json` — either a top-level array of objects OR a single
      object with an `events` key holding the array

    Returns the list of event dicts. Raises ImportError on parse
    failure or shape mismatch.
    """
    try:
        raw = path.read_text()
    except OSError as exc:
        raise ImportError(f"cannot read import file: {exc}") from exc

    events: list[dict]
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        events = []
        for i, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ImportError(
                    f"import file line {i} is not valid JSON: {exc}",
                ) from exc
    else:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ImportError(
                f"import file is not valid JSON: {exc}",
            ) from exc
        if isinstance(parsed, list):
            events = parsed
        elif isinstance(parsed, dict) and isinstance(parsed.get("events"), list):
            events = parsed["events"]
        else:
            raise ImportError(
                "import file must be a JSON array, "
                "a JSON object with an 'events' key, "
                "or JSONL (one object per line)",
            )

    if len(events) == 0:
        raise ImportError("import file has zero events")
    if len(events) > _MAX_EVENTS_PER_BATCH:
        raise ImportError(
            f"import file has {len(events)} events, "
            f"exceeding batch max {_MAX_EVENTS_PER_BATCH}. "
            "Split into multiple files.",
        )
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise ImportError(
                f"import file event at index {i} is not a JSON object",
            )
    return events


def import_events(
    cfg: Config,
    format: str,
    events: list[dict],
    client: Optional[httpx.Client] = None,
) -> ImportResult:
    """POST /v1/import."""
    url = f"{cfg.base_url}/v1/import"
    body = {"format": format, "events": events}
    headers = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
    }

    _client = client if client is not None else httpx.Client(timeout=_TIMEOUT_S)
    try:
        try:
            r = _client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise ImportError(f"transport failed: {exc}") from exc
    finally:
        if client is None:
            _client.close()

    if r.status_code != 200:
        try:
            envelope = r.json()
        except Exception:
            envelope = {"error": "non_json_response", "raw": r.text[:200]}
        err = envelope.get("error", "unknown")
        detail = {k: v for k, v in envelope.items() if k != "error"}
        raise ImportError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return ImportResult(
        count=data["count"],
        kinds=data.get("kinds", {}),
        first_etch_chain_seq=data.get("first_etch_chain_seq"),
        last_etch_chain_seq=data.get("last_etch_chain_seq"),
        skipped=data.get("skipped", []),
    )
