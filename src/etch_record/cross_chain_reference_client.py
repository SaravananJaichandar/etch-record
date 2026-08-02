"""HTTP client for Wave 5 #18 cross-chain reference endpoint
(2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class CrossChainReferenceError(RuntimeError):
    """Raised when the cross-chain-reference call fails.
    CLI exit code 15."""


@dataclass(frozen=True)
class CrossChainReferenceResult:
    etch_chain_seq: int
    etch_row_id: str
    cross_ref_hash: str
    target_chain_id: str
    target_epoch_seq: int
    target_event_hash: str
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_cross_chain_reference(
    cfg: Config,
    oss_event_id: str,
    cross_ref: dict,
    client: Optional[httpx.Client] = None,
) -> CrossChainReferenceResult:
    """POST /v1/etch-chain/cross-chain-reference."""
    url = f"{cfg.base_url}/v1/etch-chain/cross-chain-reference"
    body = {"oss_event_id": oss_event_id, "cross_ref": cross_ref}
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
            raise CrossChainReferenceError(
                f"transport failed: {exc}",
            ) from exc
    finally:
        if client is None:
            _client.close()

    if r.status_code != 200:
        try:
            envelope = r.json()
        except Exception:
            envelope = {
                "error": "non_json_response", "raw": r.text[:200],
            }
        err = envelope.get("error", "unknown")
        detail = {k: v for k, v in envelope.items() if k != "error"}
        raise CrossChainReferenceError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return CrossChainReferenceResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        cross_ref_hash=data["cross_ref_hash"],
        target_chain_id=data["target_chain_id"],
        target_epoch_seq=data["target_epoch_seq"],
        target_event_hash=data["target_event_hash"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
