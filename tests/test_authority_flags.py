"""
Tests for the Wave 1 #2 authority-receipt flags on the etch-record CLI.

Covers:
- authority_client canonical_json byte-parity with the server's rules.
- Key loading + pubkey derivation + key_ref computation.
- sign_claim produces a signature the server-side rule set verifies.
- record_authority_receipt handles the full request/response envelope,
  including error paths.
- _prepare_authority_receipt: all-or-nothing flag validation, claim
  assembly with + without expires_at, scope splitting.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from etch_record.authority_client import (
    AuthorityError,
    AuthorityResult,
    canonical_json,
    compute_key_ref,
    derive_pubkey_hex,
    load_ed25519_privkey,
    record_authority_receipt,
    sign_claim,
    utc_iso_ms_now,
)
from etch_record.cli import _prepare_authority_receipt
from etch_record.config import Config


CFG = Config(
    project_id="proj_alpha",
    app_token="wm_test_token",
    base_url="https://etch.test",
)


# ---------------------------------------------------------------------------
# canonical_json byte-parity with server-side rules
# ---------------------------------------------------------------------------


def test_canonical_json_sorts_keys():
    a = canonical_json({"b": 1, "a": 2})
    assert a == b'{"a":2,"b":1}'


def test_canonical_json_no_whitespace():
    a = canonical_json({"a": 1, "b": 2})
    assert b" " not in a


def test_canonical_json_utf8_passthrough():
    """Non-ASCII passes through as UTF-8, not \\uXXXX escaped."""
    a = canonical_json({"name": "élise"})
    assert "élise".encode("utf-8") in a


def test_canonical_json_nested_sorts_recursively():
    a = canonical_json({"outer": {"z": 1, "a": 2}})
    assert a == b'{"outer":{"a":2,"z":1}}'


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def _write_ed25519_pem(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey]:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "auth.pem"
    p.write_bytes(pem)
    return p, priv


def test_load_ed25519_privkey_from_pem(tmp_path):
    p, priv = _write_ed25519_pem(tmp_path)
    loaded = load_ed25519_privkey(p)
    # Public bytes agree — same key round-tripped through PEM.
    assert loaded.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_load_ed25519_privkey_rejects_non_pem(tmp_path):
    p = tmp_path / "junk.pem"
    p.write_bytes(b"not a pem")
    with pytest.raises(AuthorityError, match="not a valid PEM"):
        load_ed25519_privkey(p)


def test_load_ed25519_privkey_rejects_non_ed25519(tmp_path):
    """RSA key should raise a clear error, not silently proceed."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = tmp_path / "rsa.pem"
    p.write_bytes(pem)
    with pytest.raises(AuthorityError, match="expected Ed25519"):
        load_ed25519_privkey(p)


def test_derive_pubkey_hex_length(tmp_path):
    _, priv = _write_ed25519_pem(tmp_path)
    assert len(derive_pubkey_hex(priv)) == 64


def test_compute_key_ref_matches_server_rule(tmp_path):
    _, priv = _write_ed25519_pem(tmp_path)
    pubkey_hex = derive_pubkey_hex(priv)
    expected = "sha256:" + hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
    assert compute_key_ref(pubkey_hex) == expected


# ---------------------------------------------------------------------------
# sign_claim
# ---------------------------------------------------------------------------


def test_sign_claim_produces_hex_signature(tmp_path):
    _, priv = _write_ed25519_pem(tmp_path)
    sig = sign_claim(priv, {"a": 1, "b": 2})
    assert len(sig) == 128
    int(sig, 16)  # confirms it's valid hex


def test_sign_claim_verifies_against_derived_pubkey(tmp_path):
    _, priv = _write_ed25519_pem(tmp_path)
    claim = {"authority_id": "x", "attested_at": "2026-08-01T00:00:00Z",
             "receipt_type": "hitl_approval", "scope": []}
    sig_hex = sign_claim(priv, claim)

    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    # No exception → valid signature over canonical claim.
    pub.verify(bytes.fromhex(sig_hex), canonical_json(claim))


def test_sign_claim_signs_canonical_form(tmp_path):
    """Reordering the input dict must not change the signature — the
    canonical serialization sorts keys first."""
    _, priv = _write_ed25519_pem(tmp_path)
    claim_a = {"a": 1, "b": 2}
    claim_b = {"b": 2, "a": 1}
    assert sign_claim(priv, claim_a) == sign_claim(priv, claim_b)


# ---------------------------------------------------------------------------
# record_authority_receipt HTTP client
# ---------------------------------------------------------------------------


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_record_authority_receipt_happy_path():
    def handler(request):
        body = json.loads(request.content)
        assert body["oss_event_id"] == "oss-abc"
        assert body["claim"]["authority_id"] == "alice"
        assert body["signature_hex"] == "aa" * 64
        assert body["pubkey_ref"].startswith("sha256:")
        return httpx.Response(200, json={
            "status": "recorded",
            "etch_chain_seq": 7,
            "etch_row_id": "row-uuid-1",
            "authority_hash": "sha256:" + "bb" * 32,
            "oss_event_id_ref": "oss-abc",
            "recorded_at": "2026-08-01T20:35:00.000Z",
        })

    with _mock_client(handler) as client:
        result = record_authority_receipt(
            CFG, "oss-abc",
            claim={"authority_id": "alice", "receipt_type": "hitl_approval",
                   "attested_at": "2026-08-01T20:35:00.000Z", "scope": []},
            signature_hex="aa" * 64,
            pubkey_ref="sha256:" + "cc" * 32,
            client=client,
        )
    assert isinstance(result, AuthorityResult)
    assert result.etch_chain_seq == 7
    assert result.authority_hash == "sha256:" + "bb" * 32


def test_record_authority_receipt_bubbles_404():
    def handler(request):
        return httpx.Response(404, json={
            "error": "unknown_pubkey_ref",
            "pubkey_ref": "sha256:" + "00" * 32,
        })
    with _mock_client(handler) as client:
        with pytest.raises(AuthorityError, match="unknown_pubkey_ref"):
            record_authority_receipt(
                CFG, "oss-x",
                claim={"authority_id": "x", "receipt_type": "hitl_approval",
                       "attested_at": "2026-08-01T20:35:00.000Z", "scope": []},
                signature_hex="aa" * 64,
                pubkey_ref="sha256:" + "00" * 32,
                client=client,
            )


def test_record_authority_receipt_bubbles_revoked():
    def handler(request):
        return httpx.Response(400, json={
            "error": "pubkey_revoked",
            "pubkey_ref": "sha256:" + "cc" * 32,
            "revoked_at": "2026-08-01T00:00:00.000Z",
        })
    with _mock_client(handler) as client:
        with pytest.raises(AuthorityError, match="pubkey_revoked"):
            record_authority_receipt(
                CFG, "oss-x",
                claim={"authority_id": "x", "receipt_type": "hitl_approval",
                       "attested_at": "2026-08-01T20:35:00.000Z", "scope": []},
                signature_hex="aa" * 64,
                pubkey_ref="sha256:" + "cc" * 32,
                client=client,
            )


def test_record_authority_receipt_bubbles_signature_invalid():
    def handler(request):
        return httpx.Response(400, json={"error": "signature_invalid"})
    with _mock_client(handler) as client:
        with pytest.raises(AuthorityError, match="signature_invalid"):
            record_authority_receipt(
                CFG, "oss-x",
                claim={"authority_id": "x", "receipt_type": "hitl_approval",
                       "attested_at": "2026-08-01T20:35:00.000Z", "scope": []},
                signature_hex="aa" * 64,
                pubkey_ref="sha256:" + "cc" * 32,
                client=client,
            )


# ---------------------------------------------------------------------------
# _prepare_authority_receipt (CLI helper)
# ---------------------------------------------------------------------------


def test_prepare_returns_nothing_when_no_flags_set():
    claim, priv, ref = _prepare_authority_receipt(
        authority_privkey_file=None,
        authority_id=None,
        authority_scope="",
        authority_expires_at=None,
        receipt_type=None,
    )
    assert claim is None
    assert priv is None
    assert ref is None


def test_prepare_requires_all_flags_together(tmp_path):
    """Partial invocation must surface as a usage error, not silently
    drop the receipt."""
    import click
    p, _ = _write_ed25519_pem(tmp_path)
    with pytest.raises(click.UsageError, match="requires"):
        _prepare_authority_receipt(
            authority_privkey_file=p,
            authority_id=None,          # <-- missing
            authority_scope="",
            authority_expires_at=None,
            receipt_type="hitl_approval",
        )


def test_prepare_happy_path_no_expires_at(tmp_path):
    p, priv = _write_ed25519_pem(tmp_path)
    claim, loaded_priv, ref = _prepare_authority_receipt(
        authority_privkey_file=p,
        authority_id="alice",
        authority_scope="kyc-decisions,pii-approvals",
        authority_expires_at=None,
        receipt_type="hitl_approval",
    )
    assert claim["authority_id"] == "alice"
    assert claim["scope"] == ["kyc-decisions", "pii-approvals"]
    assert claim["receipt_type"] == "hitl_approval"
    assert "expires_at" not in claim  # optional, omitted here
    assert "attested_at" in claim
    assert ref == compute_key_ref(derive_pubkey_hex(priv))


def test_prepare_includes_expires_at_when_set(tmp_path):
    p, _ = _write_ed25519_pem(tmp_path)
    claim, _, _ = _prepare_authority_receipt(
        authority_privkey_file=p,
        authority_id="alice",
        authority_scope="",
        authority_expires_at="2026-12-31T23:59:59Z",
        receipt_type="vested_authority",
    )
    assert claim["expires_at"] == "2026-12-31T23:59:59Z"


def test_prepare_empty_scope_becomes_empty_list(tmp_path):
    p, _ = _write_ed25519_pem(tmp_path)
    claim, _, _ = _prepare_authority_receipt(
        authority_privkey_file=p,
        authority_id="alice",
        authority_scope="   ",
        authority_expires_at=None,
        receipt_type="automated_by_policy",
    )
    assert claim["scope"] == []


def test_prepare_signable_output_matches_server_verifies(tmp_path):
    """End-to-end signing loop: prepare -> sign -> verify against
    the derived pubkey. Prevents any client/server serialization drift."""
    p, priv = _write_ed25519_pem(tmp_path)
    claim, loaded_priv, ref = _prepare_authority_receipt(
        authority_privkey_file=p,
        authority_id="alice",
        authority_scope="",
        authority_expires_at=None,
        receipt_type="hitl_approval",
    )
    sig_hex = sign_claim(loaded_priv, claim)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    pub.verify(bytes.fromhex(sig_hex), canonical_json(claim))


# ---------------------------------------------------------------------------
# utc_iso_ms_now shape
# ---------------------------------------------------------------------------


def test_utc_iso_ms_now_shape():
    ts = utc_iso_ms_now()
    assert ts.endswith("Z")
    assert "T" in ts
    # YYYY-MM-DDTHH:MM:SS.mmmZ = 24 chars
    assert len(ts) == 24
