"""HTTP client for Wave 6 #23 learning-persistence endpoint
(2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class LearningPersistenceError(RuntimeError):
    """Raised when the learning-persistence call fails.
    CLI exit code 20."""


@dataclass(frozen=True)
class LearningPersistenceResult:
    etch_chain_seq: int
    etch_row_id: str
    learning_row_hash: str
    propagation_semantics: str
    learned_from_event_id: str
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_learning_persistence(
    cfg: Config,
    oss_event_id: str,
    learning: dict,
    client: Optional[httpx.Client] = None,
) -> LearningPersistenceResult:
    """POST /v1/etch-chain/learning-persistence."""
    url = f"{cfg.base_url}/v1/etch-chain/learning-persistence"
    body = {"oss_event_id": oss_event_id, "learning": learning}
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
            raise LearningPersistenceError(
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
        raise LearningPersistenceError(
            f"{r.status_code} {err}"
            + (f" - {detail}" if detail else ""),
        )
    data = r.json()
    return LearningPersistenceResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        learning_row_hash=data["learning_row_hash"],
        propagation_semantics=data["propagation_semantics"],
        learned_from_event_id=data["learned_from_event_id"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
