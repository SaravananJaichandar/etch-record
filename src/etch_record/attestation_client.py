"""HTTP client for Wave 1 #3 model-card / system-card attestation
endpoint (2026-08-01).

Fourth call in the etch-record CLI sequence:

  1. mcp_client.record_event(cfg, arguments)                → OSS event
  2. governance_client.record_governance(cfg, ...)          → Wave 1 #1
  3. authority_client.record_authority_receipt(cfg, ...)    → Wave 1 #2
  4. attestation_client.record_model_card_attestation(cfg,) → Wave 1 #3

Wave 1 #3 has no signing surface (unlike Wave 1 #2). Client just
posts the hash bundle; server hashes canonically and appends. That
keeps this module a small HTTP shim, symmetric with governance_client.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class AttestationError(RuntimeError):
    """Raised when the model-card-attestation call fails in a way the
    CLI should surface with a friendly stderr message + exit code 7."""


@dataclass(frozen=True)
class AttestationResult:
    """Response payload from a successful POST
    /v1/etch-chain/model-card-attestation. All fields come from the
    server; the client does not compute anything locally."""

    etch_chain_seq: int
    etch_row_id: str
    attestation_hash: str
    oss_event_id_ref: str
    recorded_at: str


def record_model_card_attestation(
    cfg: Config,
    oss_event_id: str,
    attestation: dict,
    client: Optional[httpx.Client] = None,
) -> AttestationResult:
    """POST /v1/etch-chain/model-card-attestation.

    Args:
      cfg: loaded Config (has base_url + app_token).
      oss_event_id: event_id returned by mcp_client.record_event
        (typically the session's first event).
      attestation: assembled attestation dict — validated server-side
        via Pydantic. Local validation would drift, so it's skipped.
      client: optional httpx.Client for dependency injection (tests
        pass a MockTransport-backed client).

    Returns:
      AttestationResult on 200.

    Raises:
      AttestationError on any non-200 or transport failure.
    """
    url = f"{cfg.base_url}/v1/etch-chain/model-card-attestation"
    body = {
        "oss_event_id": oss_event_id,
        "attestation": attestation,
    }
    headers = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
    }

    _client = client if client is not None else httpx.Client(timeout=_TIMEOUT_S)
    try:
        try:
            r = _client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise AttestationError(f"transport failed: {exc}") from exc
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
        raise AttestationError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return AttestationResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        attestation_hash=data["attestation_hash"],
        oss_event_id_ref=data["oss_event_id_ref"],
        recorded_at=data["recorded_at"],
    )
