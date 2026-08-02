"""HTTP client for Wave 6 #22 idempotency-collapse endpoint
(2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class IdempotencyCollapseError(RuntimeError):
    """Raised when the idempotency-collapse call fails.
    CLI exit code 19."""


@dataclass(frozen=True)
class IdempotencyCollapseResult:
    etch_chain_seq: int
    etch_row_id: str
    collapse_row_hash: str
    idempotency_key: str
    collapse_count: int
    previous_seq: Optional[int]
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_idempotency_collapse(
    cfg: Config,
    oss_event_id: str,
    collapse: dict,
    client: Optional[httpx.Client] = None,
) -> IdempotencyCollapseResult:
    """POST /v1/etch-chain/idempotency-collapse."""
    url = f"{cfg.base_url}/v1/etch-chain/idempotency-collapse"
    body = {"oss_event_id": oss_event_id, "collapse": collapse}
    headers = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
    }
    _client = client if client is not None else httpx.Client(
        timeout=_TIMEOUT_S,
    )
    try:
        try:
            r = _client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise IdempotencyCollapseError(
                f"transport failed: {exc}",
            ) from exc
    finally:
        if client is None:
            _client.close()

    if r.status_code != 200:
        try:
            env = r.json()
        except Exception:
            env = {"error": "non_json_response", "raw": r.text[:200]}
        err = env.get("error", "unknown")
        detail = {k: v for k, v in env.items() if k != "error"}
        raise IdempotencyCollapseError(
            f"{r.status_code} {err}"
            + (f" - {detail}" if detail else ""),
        )
    data = r.json()
    return IdempotencyCollapseResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        collapse_row_hash=data["collapse_row_hash"],
        idempotency_key=data["idempotency_key"],
        collapse_count=data["collapse_count"],
        previous_seq=data.get("previous_seq"),
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
