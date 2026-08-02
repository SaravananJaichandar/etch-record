"""HTTP client for Wave 5 #20 signed postmortem endpoint (2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class PostmortemError(RuntimeError):
    """Raised when the postmortem call fails. CLI exit code 14."""


@dataclass(frozen=True)
class PostmortemResult:
    etch_chain_seq: int
    etch_row_id: str
    postmortem_hash: str
    about_event_id: str
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_postmortem(
    cfg: Config,
    oss_event_id: str,
    postmortem: dict,
    client: Optional[httpx.Client] = None,
) -> PostmortemResult:
    """POST /v1/etch-chain/postmortem."""
    url = f"{cfg.base_url}/v1/etch-chain/postmortem"
    body = {"oss_event_id": oss_event_id, "postmortem": postmortem}
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
            raise PostmortemError(
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
        raise PostmortemError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return PostmortemResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        postmortem_hash=data["postmortem_hash"],
        about_event_id=data["about_event_id"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
