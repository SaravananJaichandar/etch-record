"""HTTP client for Wave 2 #10 stop-condition endpoint (2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class StopConditionError(RuntimeError):
    """Raised when the stop-condition call fails. CLI exit code 13."""


@dataclass(frozen=True)
class StopConditionResult:
    etch_chain_seq: int
    etch_row_id: str
    stop_condition_hash: str
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_stop_condition(
    cfg: Config,
    oss_event_id: Optional[str],
    stop_condition: dict,
    client: Optional[httpx.Client] = None,
) -> StopConditionResult:
    """POST /v1/etch-chain/stop-condition."""
    url = f"{cfg.base_url}/v1/etch-chain/stop-condition"
    body: dict = {"stop_condition": stop_condition}
    if oss_event_id is not None:
        body["oss_event_id"] = oss_event_id
    headers = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
    }

    _client = client if client is not None else httpx.Client(timeout=_TIMEOUT_S)
    try:
        try:
            r = _client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise StopConditionError(f"transport failed: {exc}") from exc
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
        raise StopConditionError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return StopConditionResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        stop_condition_hash=data["stop_condition_hash"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
