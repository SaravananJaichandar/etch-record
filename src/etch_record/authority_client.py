"""HTTP client for Wave 1 #2 authority-receipt endpoint (2026-08-01).

Companion to governance_client.py. Adds the third call in the
etch-record CLI sequence:

  1. mcp_client.record_event(cfg, arguments)              → OSS event
  2. governance_client.record_governance(cfg, ...)        → Wave 1 #1
  3. authority_client.record_authority_receipt(cfg, ...)  → Wave 1 #2

Wave 1 #2 differs from Wave 1 #1 in that the client SIGNS the claim
locally with an Ed25519 private key before sending. The server verifies
the signature against a pubkey registered in advance (via the operator
CLI `etch add-authority-key`). If verification fails the server
returns 400 signature_invalid and this module raises AuthorityError.

Canonical JSON rules are duplicated here rather than imported from the
hosted repo — etch-record must be independently installable from PyPI
with no reference to the server codebase.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import Config


_TIMEOUT_S = 30.0


class AuthorityError(RuntimeError):
    """Raised when the authority-receipt call fails in a way the CLI
    should surface with a friendly stderr message + exit code 6."""


@dataclass(frozen=True)
class AuthorityResult:
    """Response payload from a successful POST
    /v1/etch-chain/authority-receipt. All fields come from the server."""

    etch_chain_seq: int
    etch_row_id: str
    authority_hash: str
    oss_event_id_ref: str
    recorded_at: str


# ---------------------------------------------------------------------------
# Canonical JSON — duplicated from etch_chain.canonical_json. Rules:
#   - Keys sorted alphabetically at every level.
#   - Separators: (",", ":") — no whitespace.
#   - Non-ASCII passes through as UTF-8 (no escaping).
#   - None -> null, booleans + numeric types pass through.
#
# If we ever import from the hosted repo, etch-record's install profile
# changes. Duplicate + regression-test byte-parity in Day 3 tests.
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def load_ed25519_privkey(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file. Raises AuthorityError
    on parse failure with a message that names the flag."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuthorityError(f"cannot read privkey file: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except Exception as exc:  # cryptography raises many types here
        raise AuthorityError(
            f"privkey file is not a valid PEM: {exc}",
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AuthorityError(
            f"expected Ed25519 private key, got "
            f"{type(key).__name__} — regenerate with "
            f"`openssl genpkey -algorithm ed25519 -out <path>`",
        )
    return key


def derive_pubkey_hex(priv: Ed25519PrivateKey) -> str:
    """Return the raw 32-byte pubkey as lowercase hex (64 chars)."""
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pub_bytes.hex()


def compute_key_ref(pubkey_hex: str) -> str:
    """Mirror etch_chain.compute_key_ref. Client computes locally to
    know which pubkey_ref to send; server recomputes and looks up."""
    return "sha256:" + hashlib.sha256(
        bytes.fromhex(pubkey_hex),
    ).hexdigest()


def utc_iso_ms_now() -> str:
    """Millisecond-precision UTC timestamp — matches the server's
    canonical timestamp shape so ordering + hashing agree."""
    return (
        datetime.now(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )


def sign_claim(
    priv: Ed25519PrivateKey, claim: dict,
) -> str:
    """Sign the canonical JSON of the claim dict with the given
    Ed25519 private key. Returns hex-encoded 64-byte signature."""
    return priv.sign(canonical_json(claim)).hex()


def record_authority_receipt(
    cfg: Config,
    oss_event_id: str,
    claim: dict,
    signature_hex: str,
    pubkey_ref: str,
    client: Optional[httpx.Client] = None,
) -> AuthorityResult:
    """POST /v1/etch-chain/authority-receipt.

    Args:
      cfg: loaded Config (has base_url + app_token).
      oss_event_id: event_id returned by mcp_client.record_event.
      claim: assembled AuthorityClaim dict (validated server-side).
      signature_hex: hex-encoded Ed25519 signature over
        canonical_json(claim).
      pubkey_ref: sha256:<hex> of the pubkey that signed. Server must
        have this pubkey registered (via `etch add-authority-key`).
      client: optional httpx.Client for dependency injection (tests
        pass a MockTransport-backed client).

    Returns:
      AuthorityResult on 200.

    Raises:
      AuthorityError on any non-200 or transport failure.
    """
    url = f"{cfg.base_url}/v1/etch-chain/authority-receipt"
    body = {
        "oss_event_id": oss_event_id,
        "claim": claim,
        "signature_hex": signature_hex,
        "pubkey_ref": pubkey_ref,
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
            raise AuthorityError(f"transport failed: {exc}") from exc
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
        raise AuthorityError(
            f"{r.status_code} {err}"
            + (f" — {detail}" if detail else ""),
        )

    data = r.json()
    return AuthorityResult(
        etch_chain_seq=data["etch_chain_seq"],
        etch_row_id=data["etch_row_id"],
        authority_hash=data["authority_hash"],
        oss_event_id_ref=data["oss_event_id_ref"],
        recorded_at=data["recorded_at"],
    )
