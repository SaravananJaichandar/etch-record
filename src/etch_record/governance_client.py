"""HTTP client for Wave 1 #1 governance-record endpoint (2026-08-01).

Companion to mcp_client.py. Where mcp_client speaks MCP StreamableHTTP
to invoke tools like record_event, this module speaks plain HTTP to
Etch's own compliance surface (currently: POST
/v1/etch-chain/governance-record).

Kept as a separate module so the CLI can compose:
  1. mcp_client.record_event(...) → get OSS event_id
  2. governance_client.record_governance(cfg, event_id, gov) → attach
     signed compliance metadata to the Etch parallel chain

Both calls hit etch.systems with the same Bearer token, so a client
that can call one can call the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


class GovernanceError(RuntimeError):
    """Raised when the governance-record HTTP call fails in a way the
    CLI should surface with a friendly stderr message + exit code."""


@dataclass(frozen=True)
class GovernanceResult:
    """Response payload from a successful POST
    /v1/etch-chain/governance-record. All fields come from the server;
    the client does not compute anything locally."""

    etch_chain_seq: int
    etch_row_id: str
    governance_hash: str
    oss_event_id_ref: str
    recorded_at: str


def record_governance(
    cfg: Config,
    oss_event_id: str,
    governance: dict,
    client: Optional[httpx.Client] = None,
) -> GovernanceResult:
    """POST /v1/etch-chain/governance-record.

    Args:
      cfg: loaded Config (has base_url + app_token).
      oss_event_id: the event_id returned by mcp_client.record_event.
      governance: assembled governance object (validated server-side
        via Pydantic; local validation would drift and is skipped).
      client: optional httpx.Client for dependency injection. Tests
        pass a MockTransport-backed client. Prod passes None; the
        function creates a default client bounded by _TIMEOUT_S.

    Returns:
      GovernanceResult on 200.

    Raises:
      GovernanceError on any non-200 or transport failure. Message
      surfaces the server's error code + hint when the response body
      is a valid JSON error envelope.
    """
    url = f"{cfg.base_url}/v1/etch-chain/governance-record"
    body = {
        "oss_event_id": oss_event_id,
        "governance": governance,
    }
    headers = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    owned_client = client is None
    if owned_client:
        client = httpx.Client(timeout=_TIMEOUT_S)

    try:
        try:
            resp = client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise GovernanceError(
                f"transport failed while calling {url}: {exc}",
            ) from exc
    finally:
        if owned_client:
            client.close()

    if resp.status_code == 200:
        try:
            payload = resp.json()
        except ValueError as exc:
            raise GovernanceError(
                f"200 response was not valid JSON: {exc}",
            ) from exc
        return GovernanceResult(
            etch_chain_seq=int(payload["etch_chain_seq"]),
            etch_row_id=str(payload["etch_row_id"]),
            governance_hash=str(payload["governance_hash"]),
            oss_event_id_ref=str(payload["oss_event_id_ref"]),
            recorded_at=str(payload["recorded_at"]),
        )

    # Non-200 — try to parse the server's JSON error envelope.
    try:
        err_payload = resp.json()
    except ValueError:
        raise GovernanceError(
            f"HTTP {resp.status_code} with non-JSON body: "
            f"{resp.text[:200]!r}",
        )

    err_code = err_payload.get("error", "unknown_error")
    if err_code == "insufficient_scope":
        raise GovernanceError(
            f"insufficient_scope: your app token needs "
            f"{err_payload.get('required_scope')!r} but has "
            f"{err_payload.get('token_scopes')}. Mint a new token "
            f"with mcp:write scope.",
        )
    if err_code == "validation_failed":
        details = err_payload.get("details", [])
        summary = "; ".join(
            f"{d.get('loc')}: {d.get('msg')}" for d in details
        )
        raise GovernanceError(
            f"governance object failed validation: {summary}",
        )
    if err_code == "invalid_json_body":
        raise GovernanceError(
            "server rejected the request body as invalid JSON",
        )

    raise GovernanceError(
        f"HTTP {resp.status_code}: {err_code}",
    )
