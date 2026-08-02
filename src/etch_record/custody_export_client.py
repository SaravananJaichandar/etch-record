"""HTTP client for Wave 5 #19 chain-of-custody export endpoint
(2026-08-02)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import Config


_TIMEOUT_S = 60.0  # bundle assembly can walk many rows


class CustodyExportError(RuntimeError):
    """Raised when the custody-export call fails. CLI exit code 17."""


@dataclass(frozen=True)
class CustodyExportResult:
    custody_export_marker_seq: int
    custody_export_marker_row_id: str
    manifest_bundle_hash: str
    oss_event_id_ref: Optional[str]
    bundle: dict  # the full self-authenticating JSON bundle


def record_custody_export(
    cfg: Config,
    oss_event_id: str,
    session_id: str,
    declaration_regime: str,
    client: Optional[httpx.Client] = None,
) -> CustodyExportResult:
    """POST /v1/etch-chain/custody-export."""
    url = f"{cfg.base_url}/v1/etch-chain/custody-export"
    body = {
        "oss_event_id": oss_event_id,
        "scope": {"session_id": session_id},
        "declaration_regime": declaration_regime,
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
            raise CustodyExportError(
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
        raise CustodyExportError(
            f"{r.status_code} {err}"
            + (f" - {detail}" if detail else ""),
        )

    data = r.json()
    return CustodyExportResult(
        custody_export_marker_seq=data["custody_export_marker_seq"],
        custody_export_marker_row_id=(
            data["custody_export_marker_row_id"]
        ),
        manifest_bundle_hash=data["manifest_bundle_hash"],
        oss_event_id_ref=data.get("oss_event_id_ref"),
        bundle=data["bundle"],
    )
