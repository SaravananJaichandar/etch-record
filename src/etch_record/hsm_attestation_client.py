"""HTTP client for Wave 5 #17 HSM/TPM/enclave attestation endpoint
(2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class HsmAttestationError(RuntimeError):
    """Raised when the hsm-attestation call fails.
    CLI exit code 16."""


@dataclass(frozen=True)
class HsmAttestationResult:
    etch_chain_seq: int
    etch_row_id: str
    hsm_attestation_hash: str
    vendor: str
    attestation_format: str
    oss_event_id_ref: Optional[str]
    recorded_at: str


def record_hsm_attestation(
    cfg: Config,
    oss_event_id: str,
    hsm_attestation: dict,
    client: Optional[httpx.Client] = None,
) -> HsmAttestationResult:
    """POST /v1/etch-chain/hsm-attestation."""
    url = f"{cfg.base_url}/v1/etch-chain/hsm-attestation"
    body = {
        "oss_event_id": oss_event_id,
        "hsm_attestation": hsm_attestation,
    }
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
            raise HsmAttestationError(
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
        raise HsmAttestationError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return HsmAttestationResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        hsm_attestation_hash=data["hsm_attestation_hash"],
        vendor=data["vendor"],
        attestation_format=data["attestation_format"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        recorded_at=data["recorded_at"],
    )
