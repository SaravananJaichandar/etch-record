"""HTTP client for Wave 6 #21 artifact-hash endpoint (2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class ArtifactHashError(RuntimeError):
    """Raised when the artifact-hash call fails. CLI exit code 18."""


@dataclass(frozen=True)
class ArtifactHashResult:
    etch_chain_seq: int
    etch_row_id: str
    artifact_row_hash: str
    artifact_sha256_hex: str
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_artifact_hash(
    cfg: Config,
    oss_event_id: str,
    artifact: dict,
    client: Optional[httpx.Client] = None,
) -> ArtifactHashResult:
    """POST /v1/etch-chain/artifact-hash."""
    url = f"{cfg.base_url}/v1/etch-chain/artifact-hash"
    body = {"oss_event_id": oss_event_id, "artifact": artifact}
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
            raise ArtifactHashError(
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
        raise ArtifactHashError(
            f"{r.status_code} {err}"
            + (f" - {detail}" if detail else ""),
        )
    data = r.json()
    return ArtifactHashResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        artifact_row_hash=data["artifact_row_hash"],
        artifact_sha256_hex=data["artifact_sha256_hex"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
