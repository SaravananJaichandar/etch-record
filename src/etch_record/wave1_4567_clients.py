"""HTTP clients for Wave 1 #4-#7 endpoints (2026-08-01).

Four small HTTP shims, one per endpoint. Batched into a single module
because each is a tight 40-line client and separating them would just
add per-file boilerplate:

  #4 record_session_risk_score      -> risk_hash
  #5 record_autonomy_level          -> autonomy_hash
  #6 record_supersession_edge       -> edge_hash
  #7 record_signed_dissent          -> dissent_hash (requires local
                                        Ed25519 signature; reuses the
                                        Wave 1 #2 pubkey registry)

Each function follows the governance_client / attestation_client
signature: (cfg, ..., client=None) -> Result. Raises the item's error
type on failure so the CLI can distinguish exit codes:
  5 = governance, 6 = authority, 7 = attestation,
  8 = risk score, 9 = autonomy, 10 = supersession, 11 = dissent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Config


_TIMEOUT_S = 30.0


def _bubble(r: httpx.Response, ExcCls) -> None:
    """Common non-200 handler: parse JSON envelope, raise the given
    error type with server's error code + detail extras."""
    try:
        envelope = r.json()
    except Exception:
        envelope = {"error": "non_json_response", "raw": r.text[:200]}
    err = envelope.get("error", "unknown")
    detail = {k: v for k, v in envelope.items() if k != "error"}
    raise ExcCls(
        f"{r.status_code} {err}"
        + (f" — {detail}" if detail else ""),
    )


def _post(cfg: Config, url_suffix: str, body: dict,
          client: Optional[httpx.Client], ExcCls):
    url = f"{cfg.base_url}{url_suffix}"
    headers = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
    }
    _client = client if client is not None else httpx.Client(timeout=_TIMEOUT_S)
    try:
        try:
            r = _client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise ExcCls(f"transport failed: {exc}") from exc
    finally:
        if client is None:
            _client.close()
    if r.status_code != 200:
        _bubble(r, ExcCls)
    return r.json()


# ---------------------------------------------------------------------------
# Wave 1 #4 session risk score
# ---------------------------------------------------------------------------


class RiskScoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class RiskScoreResult:
    etch_chain_seq: int
    etch_row_id: str
    risk_hash: str
    oss_event_id_ref: str
    recorded_at: str


def record_session_risk_score(
    cfg: Config, oss_event_id: str, risk_score: dict,
    client: Optional[httpx.Client] = None,
) -> RiskScoreResult:
    data = _post(
        cfg, "/v1/etch-chain/session-risk-score",
        {"oss_event_id": oss_event_id, "risk_score": risk_score},
        client, RiskScoreError,
    )
    return RiskScoreResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        risk_hash=data["risk_hash"],
        oss_event_id_ref=data["oss_event_id_ref"],
        recorded_at=data["recorded_at"],
    )


# ---------------------------------------------------------------------------
# Wave 1 #5 autonomy level
# ---------------------------------------------------------------------------


class AutonomyError(RuntimeError):
    pass


@dataclass(frozen=True)
class AutonomyResult:
    etch_chain_seq: int
    etch_row_id: str
    autonomy_hash: str
    oss_event_id_ref: str
    recorded_at: str


def record_autonomy_level(
    cfg: Config, oss_event_id: str, autonomy: dict,
    client: Optional[httpx.Client] = None,
) -> AutonomyResult:
    data = _post(
        cfg, "/v1/etch-chain/autonomy-level",
        {"oss_event_id": oss_event_id, "autonomy": autonomy},
        client, AutonomyError,
    )
    return AutonomyResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        autonomy_hash=data["autonomy_hash"],
        oss_event_id_ref=data["oss_event_id_ref"],
        recorded_at=data["recorded_at"],
    )


# ---------------------------------------------------------------------------
# Wave 1 #6 supersession edge
# ---------------------------------------------------------------------------


class SupersessionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SupersessionResult:
    etch_chain_seq: int
    etch_row_id: str
    edge_hash: str
    superseding_oss_event_id: str
    superseded_oss_event_id: str
    recorded_at: str


def record_supersession_edge(
    cfg: Config, superseding_oss_event_id: str, edge: dict,
    client: Optional[httpx.Client] = None,
) -> SupersessionResult:
    data = _post(
        cfg, "/v1/etch-chain/supersession-edge",
        {
            "superseding_oss_event_id": superseding_oss_event_id,
            "edge": edge,
        },
        client, SupersessionError,
    )
    return SupersessionResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        edge_hash=data["edge_hash"],
        superseding_oss_event_id=data["superseding_oss_event_id"],
        superseded_oss_event_id=data["superseded_oss_event_id"],
        recorded_at=data["recorded_at"],
    )


# ---------------------------------------------------------------------------
# Wave 1 #7 signed dissent
# ---------------------------------------------------------------------------


class DissentError(RuntimeError):
    pass


@dataclass(frozen=True)
class DissentResult:
    etch_chain_seq: int
    etch_row_id: str
    dissent_hash: str
    oss_event_id_ref: str
    recorded_at: str


def record_signed_dissent(
    cfg: Config, oss_event_id: str,
    dissent: dict, signature_hex: str, pubkey_ref: str,
    client: Optional[httpx.Client] = None,
) -> DissentResult:
    data = _post(
        cfg, "/v1/etch-chain/signed-dissent",
        {
            "oss_event_id": oss_event_id,
            "dissent": dissent,
            "signature_hex": signature_hex,
            "pubkey_ref": pubkey_ref,
        },
        client, DissentError,
    )
    return DissentResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        dissent_hash=data["dissent_hash"],
        oss_event_id_ref=data["oss_event_id_ref"],
        recorded_at=data["recorded_at"],
    )
