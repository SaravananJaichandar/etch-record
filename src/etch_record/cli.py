"""CLI entry point for etch-record.

Usage:
  etch-record "description of the event" [OPTIONS]

Only one event_type value is accepted by the Etch server enum today for
arbitrary user-recorded events: "tool_call". Anything else silently
drops server-side (this is the exact bug the /docs/quickstart Common
Gotchas section warns about). So we hardcode "tool_call" and let
callers differentiate via --tags + --evidence-json.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from . import __version__
from .attestation_client import (
    AttestationError,
    record_model_card_attestation,
)
from .authority_client import (
    AuthorityError,
    compute_key_ref,
    derive_pubkey_hex,
    load_ed25519_privkey,
    record_authority_receipt,
    sign_claim,
    utc_iso_ms_now,
)
from .config import ConfigError, load
from .governance_client import GovernanceError, record_governance
from .import_client import (
    ImportError as BulkImportError,
    import_events,
    read_events_from_file,
)
from .stop_condition_client import (
    StopConditionError,
    record_stop_condition,
)
from .mcp_client import McpError, extract_event_id, record_event
from .rate_limit import check_and_record
from .wave1_4567_clients import (
    AutonomyError,
    DissentError,
    RiskScoreError,
    SupersessionError,
    record_autonomy_level,
    record_session_risk_score,
    record_signed_dissent,
    record_supersession_edge,
)


_RECEIPT_TYPES = ("vested_authority", "hitl_approval", "automated_by_policy")
_AUTONOMY_SCHEMES = ("standard-L0-L3", "buyer-custom")
_SUPERSESSION_INTENTS = (
    "compat", "breaking", "deprecation", "correction", "refinement",
)


_LARGE_ARG_THRESHOLD_CHARS = 4096


def _default_session_id() -> str:
    """Group events emitted on the same UTC calendar day into one session."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"etch-record-{today}"


def _parse_tags(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def _load_evidence(
    evidence_json: str | None,
    evidence_file: Path | None,
) -> dict:
    if evidence_json and evidence_file:
        raise click.UsageError(
            "Pass only one of --evidence-json or --evidence-file, not both.",
        )
    if evidence_json:
        try:
            parsed = json.loads(evidence_json)
        except json.JSONDecodeError as exc:
            raise click.UsageError(
                f"--evidence-json is not valid JSON: {exc}",
            ) from exc
        if not isinstance(parsed, dict):
            raise click.UsageError("--evidence-json must be a JSON object.")
        return parsed
    if evidence_file:
        try:
            parsed = json.loads(evidence_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise click.UsageError(
                f"--evidence-file could not be loaded: {exc}",
            ) from exc
        if not isinstance(parsed, dict):
            raise click.UsageError("--evidence-file must contain a JSON object.")
        return parsed
    return {}


def _resolve_text_source(
    inline_value: str | None,
    file_path: Path | None,
    field_name: str,
) -> str:
    """Load a text field from either an inline CLI arg or a file.

    Symmetric with _load_evidence: exactly one may be set.
    File contents are stripped of ONE trailing newline (a common editor
    artifact) and otherwise passed through verbatim.
    """
    if inline_value and file_path:
        raise click.UsageError(
            f"Pass only one of --{field_name} or --{field_name}-file, not both.",
        )
    if file_path is not None:
        try:
            text = file_path.read_text()
        except OSError as exc:
            raise click.UsageError(
                f"--{field_name}-file could not be loaded: {exc}",
            ) from exc
        if text.endswith("\n"):
            text = text[:-1]
        return text
    return inline_value or ""


def _resolve_description(positional: str, file_path: Path | None) -> str:
    """Description resolution with click's required-positional in mind.

    - No file: positional is the description (legacy behavior).
    - With file: file content becomes the description; positional stays
      as a short human label captured in the Layer A Bash-hook trace
      but is NOT the recorded payload.
    """
    if file_path is None:
        return positional
    try:
        text = file_path.read_text()
    except OSError as exc:
        raise click.UsageError(
            f"--description-file could not be loaded: {exc}",
        ) from exc
    if text.endswith("\n"):
        text = text[:-1]
    return text


def _resolve_action_time(
    action_time: str | None,
    action_time_now: bool,
) -> str | None:
    """Normalize the real-world action timestamp for the evidence dict.

    Returns an ISO-8601 UTC string ("YYYY-MM-DDTHH:MM:SSZ") or None
    when neither flag is set. Rejects passing both at once.

    Accepts any ISO-8601 form recognized by datetime.fromisoformat
    (Python 3.10+ compatible - Z suffix is normalized to +00:00 first).
    A timezone MUST be present; a naive datetime is rejected because
    "action_time_utc without a timezone" is ambiguous and worse than
    no action_time at all.
    """
    if action_time and action_time_now:
        raise click.UsageError(
            "Pass only one of --action-time or --action-time-now, not both.",
        )
    if action_time_now:
        now_utc = datetime.now(timezone.utc)
        return now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    if action_time is None:
        return None
    raw = action_time.strip()
    if not raw:
        raise click.UsageError("--action-time was empty.")
    # Python 3.10 fromisoformat does NOT recognize the Z suffix. Normalize.
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise click.UsageError(
            f"--action-time is not a valid ISO-8601 timestamp: {exc}. "
            "Examples: 2026-07-28T14:03:00Z, 2026-07-28T19:33:00+05:30.",
        ) from exc
    if dt.tzinfo is None:
        raise click.UsageError(
            "--action-time must include a timezone (e.g. 'Z' suffix or "
            "+HH:MM offset). Naive timestamps are ambiguous.",
        )
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _maybe_warn_large_arg(name: str, value: str) -> None:
    """Print a stderr warning when a text arg passed via CLI is large.

    Large CLI args are a footgun: Claude Code's Bash-hook records the
    invocation with its arguments hashed into an audit event, which
    doubles the payload on the chain and (in multi-tenant deploys)
    can cross tenant boundaries. --reasoning-file / --description-file
    bypass this. This warning nudges users toward those flags for
    sensitive content without blocking legitimate use.
    """
    if len(value) > _LARGE_ARG_THRESHOLD_CHARS:
        click.echo(
            f"etch-record: warning: --{name} is {len(value)} chars via CLI "
            f"argv. Consider --{name}-file for large or sensitive content; "
            f"CLI args are captured verbatim by shell-hook auditors.",
            err=True,
        )


@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Sign one event into your Etch chain from the command line.\n\n"
        "Every call becomes a signed record_event on your Etch project."
        " Requires ETCH_PROJECT_ID and ETCH_APP_TOKEN in the environment."
    ),
)
@click.argument("description", type=str)
@click.option(
    "--tags",
    "tags_raw",
    type=str,
    default=None,
    help="Comma-separated tags (e.g. research,x,launch). Become the event's entities.",
)
@click.option(
    "--evidence-json",
    type=str,
    default=None,
    help="Inline JSON object with extra structured evidence.",
)
@click.option(
    "--evidence-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a JSON file containing an evidence object.",
)
@click.option(
    "--session-id",
    type=str,
    default=None,
    help=(
        "Group this event with others under the same session id. "
        "Default: etch-record-YYYY-MM-DD (current UTC date)."
    ),
)
@click.option(
    "--reasoning",
    type=str,
    default=None,
    help="Optional freeform reasoning string.",
)
@click.option(
    "--reasoning-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Path to a text file whose contents become the reasoning field. "
        "Use this instead of --reasoning for large or sensitive content: "
        "CLI args are captured verbatim by shell-hook auditors."
    ),
)
@click.option(
    "--description-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Path to a text file whose contents OVERRIDE the description "
        "positional argument. When set, the description positional "
        "argument may be a short label like 'from-file'; the file "
        "contents become the actual description in the event. Same "
        "safety motivation as --reasoning-file."
    ),
)
@click.option(
    "--from-hook",
    "from_hook",
    type=str,
    default=None,
    help=(
        "Reference id of the Claude Code hook (Layer A) event this "
        "semantic event corresponds to. Adds `layer_a_ref` to evidence "
        "and the `hook_bound` tag for explicit two-layer bind. Env "
        "fallback: ETCH_HOOK_TOOL_USE_ID."
    ),
)
@click.option(
    "--action-time",
    "action_time",
    type=str,
    default=None,
    help=(
        "Real-world timestamp of the action being recorded, ISO-8601 "
        "with timezone (e.g. 2026-07-28T14:03:00Z). Adds "
        "`action_time_utc` to evidence so downstream audit reconstructs "
        "when the action HAPPENED, not just when it was signed. Use for "
        "after-the-fact signing where signing-time and action-time differ."
    ),
)
@click.option(
    "--action-time-now",
    is_flag=True,
    default=False,
    help=(
        "Shortcut for --action-time set to the current UTC. Useful when "
        "signing immediately after the action."
    ),
)
@click.option(
    "--force-no-rate-limit",
    is_flag=True,
    default=False,
    help=(
        "Bypass the client-side sliding-window rate limit for this "
        "invocation. Use only for legitimate batch or backfill flows."
    ),
)
@click.option(
    "--failed",
    is_flag=True,
    default=False,
    help="Mark the event as unsuccessful (success=false).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the payload that would be sent, do not call Etch.",
)
# ---------------------------------------------------------------------------
# Wave 1 #1 (2026-08-01) — extended governance schema flags.
# When any of these is set, the CLI makes TWO calls:
#   1. mcp_client.record_event → creates the base OSS event (unchanged)
#   2. governance_client.record_governance → attaches a signed
#      governance sub-record to the Etch parallel chain, cross-
#      referencing the OSS event by id
# When none are set, the CLI behaves exactly as before (single
# record_event call). Zero behavior change for callers that don't
# opt in.
# ---------------------------------------------------------------------------
@click.option(
    "--policy-hash",
    "policy_hash",
    type=str,
    default=None,
    help=(
        "Wave 1 #1 governance: SHA-256 hash of the governance policy "
        "under which this decision was evaluated. Must be 'sha256:<64-hex>' "
        "shape. Triggers a second call to /v1/etch-chain/governance-record "
        "on the Etch chain."
    ),
)
@click.option(
    "--authority-file",
    "authority_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 1 #1 governance: path to a JSON file describing the "
        "approving authority: {identity, scope, expires_at}. See "
        "docs/wave-1-1.md for the schema."
    ),
)
@click.option(
    "--assumptions-file",
    "assumptions_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 1 #1 governance: path to a JSON file listing assumptions "
        "accepted when reaching the decision. Each entry is "
        "{claim, source_ref}."
    ),
)
@click.option(
    "--uncertainty",
    "uncertainty",
    type=str,
    default=None,
    help=(
        "Wave 1 #1 governance: uncertainty attached to the decision, "
        "given as 'confidence:basis' (e.g. "
        "'0.87:evidence-hash-lookup-match-rate'). Confidence must be "
        "[0.0, 1.0]. For richer shapes use --uncertainty-file."
    ),
)
@click.option(
    "--uncertainty-file",
    "uncertainty_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 1 #1 governance: path to a JSON file with the full "
        "uncertainty object: {confidence, basis}."
    ),
)
@click.option(
    "--invalidation-file",
    "invalidation_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 1 #1 governance: path to a JSON file listing conditions "
        "under which the approval would have been invalidated. Each "
        "entry is {\"if\": ..., \"then\": ...}."
    ),
)
# ---------------------------------------------------------------------------
# Wave 4 #15 (2026-08-02) — 8-category governance schema extension.
# Adds mission / terminology / context fields. Extraction is server-
# side; drift detection runs via etch-chain-verify's dimensional
# check. Any of these flags being set (alone or with the legacy
# governance fields) triggers the second call and populates the
# multi-dim projection index.
# ---------------------------------------------------------------------------
@click.option(
    "--mission", "mission", type=str, default=None,
    help=(
        "Wave 4 #15 governance: mission statement string (e.g. "
        "'customer KYC compliance decisions'). Hashed server-side "
        "for drift detection."
    ),
)
@click.option(
    "--terminology", "terminology_raw", type=str, default=None,
    help=(
        "Wave 4 #15 governance: comma-separated key terms (e.g. "
        "'KYC,PII,customer identity'). Set-hashed server-side."
    ),
)
@click.option(
    "--context-file", "context_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 4 #15 governance: JSON object describing the operating "
        "context (e.g. {model, prompt_hash, policy_context}). Any "
        "shape accepted; canonical-json-hashed server-side."
    ),
)
# ---------------------------------------------------------------------------
# Wave 1 #2 (2026-08-01) — bounded authority receipts.
# When --authority-privkey-file + --authority-id + --receipt-type are all
# set, the CLI adds a THIRD call:
#   3. authority_client.record_authority_receipt → attaches a signed
#      authority receipt to the Etch chain, cross-referencing the OSS
#      event by id, signed with the local Ed25519 privkey.
# Server verifies the signature against a pubkey the operator registered
# via `etch add-authority-key`. Exit code 6 on receipt failure (base +
# governance succeeded).
# ---------------------------------------------------------------------------
@click.option(
    "--authority-privkey-file",
    "authority_privkey_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 1 #2 authority receipt: path to an Ed25519 private key in "
        "PEM format. Generate with `openssl genpkey -algorithm ed25519 "
        "-out authority.pem`. The corresponding pubkey must be "
        "registered on the project via `etch add-authority-key`."
    ),
)
@click.option(
    "--authority-id",
    "authority_id",
    type=str,
    default=None,
    help=(
        "Wave 1 #2 authority receipt: human-readable authority identity "
        "(e.g. 'compliance-officer-2'). Must match the authority_id used "
        "when the pubkey was registered server-side."
    ),
)
@click.option(
    "--authority-scope",
    "authority_scope",
    type=str,
    default="",
    help=(
        "Wave 1 #2 authority receipt: comma-separated scope tags this "
        "authority was bounded to (e.g. 'kyc-decisions,pii-approvals'). "
        "Empty = any."
    ),
)
@click.option(
    "--authority-expires-at",
    "authority_expires_at",
    type=str,
    default=None,
    help=(
        "Wave 1 #2 authority receipt: ISO 8601 UTC when the authority "
        "itself expires. Optional — omit for standing authority."
    ),
)
@click.option(
    "--receipt-type",
    "receipt_type",
    type=click.Choice(_RECEIPT_TYPES),
    default=None,
    help=(
        "Wave 1 #2 authority receipt: which flavor of authority was "
        "invoked. Required whenever --authority-privkey-file is set."
    ),
)
# ---------------------------------------------------------------------------
# Wave 1 #3 (2026-08-01) — model-card / system-card attestation.
# When --model-card-hash + --model-id are set, the CLI adds a FOURTH
# call attaching a signed bundle of session-scoped content hashes to
# the Etch chain. Cryptographic specificity for "which AI made this
# decision." Exit code 7 on failure (base + governance + authority
# still succeeded).
# ---------------------------------------------------------------------------
@click.option(
    "--model-card-hash",
    "model_card_hash",
    type=str,
    default=None,
    help=(
        "Wave 1 #3 attestation: SHA-256 hash of the model card document "
        "governing this session. 'sha256:<64-hex>' shape. Triggers a "
        "fourth call to /v1/etch-chain/model-card-attestation."
    ),
)
@click.option(
    "--system-prompt-hash",
    "system_prompt_hash",
    type=str,
    default=None,
    help=(
        "Wave 1 #3 attestation: SHA-256 hash of the system prompt in "
        "force at session start. Optional — omit if the session has no "
        "distinct system prompt beyond what the model card already "
        "commits to."
    ),
)
@click.option(
    "--attestation-policy-hash",
    "attestation_policy_hash",
    type=str,
    default=None,
    help=(
        "Wave 1 #3 attestation: SHA-256 hash of the session-scoped "
        "policy (distinct from the per-event --policy-hash on Wave 1 "
        "#1 governance). Optional."
    ),
)
@click.option(
    "--model-id",
    "model_id",
    type=str,
    default=None,
    help=(
        "Wave 1 #3 attestation: human-readable model label "
        "('claude-opus-4-7', 'gpt-4o-2024-05-13'). Not authoritative — "
        "the hash is — but auditors want the label for triage. Required "
        "whenever --model-card-hash is set."
    ),
)
# ---------------------------------------------------------------------------
# Wave 1 #4 (2026-08-01) — session risk score
# ---------------------------------------------------------------------------
@click.option(
    "--risk-score",
    "risk_score",
    type=float,
    default=None,
    help=(
        "Wave 1 #4 session risk score: bounded [0.0, 1.0]. Triggers "
        "POST /v1/etch-chain/session-risk-score. Requires --risk-vendor "
        "+ --risk-basis."
    ),
)
@click.option(
    "--risk-vendor", "risk_vendor", type=str, default=None,
    help="Wave 1 #4: upstream vendor slug (e.g. 'assury-enforce').",
)
@click.option(
    "--risk-basis", "risk_basis", type=str, default=None,
    help=(
        "Wave 1 #4: which rule/model/policy version produced the "
        "score (e.g. 'policy_v3_rule_12_pii_regex')."
    ),
)
# ---------------------------------------------------------------------------
# Wave 1 #5 (2026-08-01) — autonomy level
# ---------------------------------------------------------------------------
@click.option(
    "--autonomy-level", "autonomy_level", type=str, default=None,
    help=(
        "Wave 1 #5 autonomy level. Triggers POST "
        "/v1/etch-chain/autonomy-level. Value must be in the L0-L3 set "
        "unless --autonomy-scheme=buyer-custom."
    ),
)
@click.option(
    "--autonomy-scheme", "autonomy_scheme",
    type=click.Choice(_AUTONOMY_SCHEMES),
    default="standard-L0-L3",
    help=(
        "Wave 1 #5: 'standard-L0-L3' (default) or 'buyer-custom'. "
        "Only meaningful when --autonomy-level is set."
    ),
)
@click.option(
    "--autonomy-rationale", "autonomy_rationale", type=str, default=None,
    help="Wave 1 #5: optional free-text rationale for the autonomy level.",
)
# ---------------------------------------------------------------------------
# Wave 1 #6 (2026-08-01) — supersession edge
# ---------------------------------------------------------------------------
@click.option(
    "--supersedes", "supersedes_event_id", type=str, default=None,
    help=(
        "Wave 1 #6 supersession edge: OSS event ID that THIS event "
        "supersedes. Triggers POST /v1/etch-chain/supersession-edge. "
        "Requires --supersession-intent."
    ),
)
@click.option(
    "--supersession-intent", "supersession_intent",
    type=click.Choice(_SUPERSESSION_INTENTS),
    default=None,
    help="Wave 1 #6: intent enum. Required whenever --supersedes is set.",
)
@click.option(
    "--supersession-depends-on", "supersession_depends_on",
    type=str, default="",
    help=(
        "Wave 1 #6: comma-separated OSS event IDs this event depends "
        "on. Empty = no dependencies. The superseding event's own ID "
        "is filtered out server-side."
    ),
)
@click.option(
    "--supersession-rationale", "supersession_rationale",
    type=str, default=None,
    help="Wave 1 #6: optional free-text rationale for the supersession.",
)
# ---------------------------------------------------------------------------
# Wave 1 #7 (2026-08-01) — signed dissent
# ---------------------------------------------------------------------------
@click.option(
    "--dissent-privkey-file", "dissent_privkey_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 1 #7 signed dissent: Ed25519 private key (PEM). Reuses "
        "the Wave 1 #2 pubkey registry; register with `etch "
        "add-authority-key` under the dissenter_id first. Triggers "
        "POST /v1/etch-chain/signed-dissent."
    ),
)
@click.option(
    "--dissenter-id", "dissenter_id", type=str, default=None,
    help=(
        "Wave 1 #7: human-readable dissenter identity. Must match the "
        "authority_id used when the pubkey was registered."
    ),
)
@click.option(
    "--dissent-rationale", "dissent_rationale", type=str, default=None,
    help=(
        "Wave 1 #7: rationale for the dissent (non-empty). Required "
        "whenever --dissent-privkey-file is set."
    ),
)
# ---------------------------------------------------------------------------
# Wave 2 #8 (2026-08-02) — bulk import mode
# ---------------------------------------------------------------------------
@click.option(
    "--import-format", "import_format",
    type=click.Choice((
        "otel-gen-ai", "langsmith", "cloudtrail", "vercel-ai", "custom",
    )),
    default=None,
    help=(
        "Wave 2 #8 ingest-adapter: format of the events in the file "
        "passed via --import-file. Switches etch-record into bulk "
        "import mode; the positional description arg and every Wave 1 "
        "sub-record flag are ignored when import mode is active."
    ),
)
@click.option(
    "--import-file", "import_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Wave 2 #8: path to a file containing events. Accepts .jsonl "
        "(one JSON object per line), .json array, or .json object "
        "with an 'events' key. Max 500 events per file."
    ),
)
# ---------------------------------------------------------------------------
# Wave 2 #10 (2026-08-02) — explicit stop conditions
# ---------------------------------------------------------------------------
@click.option(
    "--stop-condition-id", "stop_condition_id", type=str, default=None,
    help=(
        "Wave 2 #10: human-readable halt label. Triggers POST "
        "/v1/etch-chain/stop-condition. Requires --stop-condition-reason."
    ),
)
@click.option(
    "--stop-condition-reason", "stop_condition_reason",
    type=str, default=None,
    help=(
        "Wave 2 #10: free-text explanation. Required whenever "
        "--stop-condition-id is set."
    ),
)
@click.option(
    "--stop-condition-scope", "stop_condition_scope",
    type=str, default=None,
    help=(
        "Wave 2 #10: optional session_id to constrain the halt. Omit "
        "for a project-wide halt. Used by the verifier to distinguish "
        "session-scoped vs global halts."
    ),
)
@click.version_option(__version__, prog_name="etch-record")
def main(
    description: str,
    tags_raw: str | None,
    evidence_json: str | None,
    evidence_file: Path | None,
    session_id: str | None,
    reasoning: str | None,
    reasoning_file: Path | None,
    description_file: Path | None,
    from_hook: str | None,
    action_time: str | None,
    action_time_now: bool,
    force_no_rate_limit: bool,
    failed: bool,
    dry_run: bool,
    policy_hash: str | None,
    authority_file: Path | None,
    assumptions_file: Path | None,
    uncertainty: str | None,
    uncertainty_file: Path | None,
    invalidation_file: Path | None,
    mission: str | None,
    terminology_raw: str | None,
    context_file: Path | None,
    authority_privkey_file: Path | None,
    authority_id: str | None,
    authority_scope: str,
    authority_expires_at: str | None,
    receipt_type: str | None,
    model_card_hash: str | None,
    system_prompt_hash: str | None,
    attestation_policy_hash: str | None,
    model_id: str | None,
    risk_score: float | None,
    risk_vendor: str | None,
    risk_basis: str | None,
    autonomy_level: str | None,
    autonomy_scheme: str,
    autonomy_rationale: str | None,
    supersedes_event_id: str | None,
    supersession_intent: str | None,
    supersession_depends_on: str,
    supersession_rationale: str | None,
    dissent_privkey_file: Path | None,
    dissenter_id: str | None,
    dissent_rationale: str | None,
    import_format: str | None,
    import_file: Path | None,
    stop_condition_id: str | None,
    stop_condition_reason: str | None,
    stop_condition_scope: str | None,
) -> None:
    # Wave 2 #8 — bulk import mode. Runs the file through the format
    # adapter server-side; single-event flow is completely skipped
    # when this branch runs. All Wave 1 sub-record flags are ignored.
    if import_format is not None or import_file is not None:
        _run_import_mode(import_format, import_file)
        return

    tags = _parse_tags(tags_raw)
    evidence = _load_evidence(evidence_json, evidence_file)
    session = session_id or _default_session_id()

    # Resolve reasoning from either inline arg or file (symmetric with
    # --evidence-json / --evidence-file split; both flags are optional).
    resolved_reasoning = _resolve_text_source(
        reasoning, reasoning_file, "reasoning",
    )
    # Description is special: the positional CLI arg is REQUIRED by click,
    # so users cannot omit it. When --description-file is passed, the file
    # content becomes the actual event description; the positional serves
    # as a short human label the user sees in shell history + the Layer A
    # Bash-hook event, keeping the sensitive payload off argv.
    resolved_description = _resolve_description(description, description_file)

    # Sensitive-arg guard: warn (do not block) on oversized inline
    # text passed via CLI argv. Skipped when the file variant was used.
    if reasoning and not reasoning_file:
        _maybe_warn_large_arg("reasoning", reasoning)
    if description and not description_file:
        _maybe_warn_large_arg("description", description)

    # Two-layer bind: --from-hook (or env fallback) adds an explicit
    # cross-reference to the Layer A (mechanical) hook event.
    hook_ref = from_hook or os.environ.get("ETCH_HOOK_TOOL_USE_ID", "").strip()
    if hook_ref:
        evidence = {**evidence, "layer_a_ref": hook_ref}
        if "hook_bound" not in tags:
            tags = [*tags, "hook_bound"]

    # Real-world action timestamp (--action-time / --action-time-now):
    # closes the drift between "when it happened" and "when I signed it".
    resolved_action_time = _resolve_action_time(action_time, action_time_now)
    if resolved_action_time is not None:
        evidence = {**evidence, "action_time_utc": resolved_action_time}

    arguments = {
        "event_type": "tool_call",
        "session_id": session,
        "entities": tags,
        "description": resolved_description,
        "reasoning": resolved_reasoning,
        "evidence": evidence,
        "success": not failed,
    }

    if dry_run:
        click.echo(
            json.dumps(
                {"method": "tools/call", "name": "record_event", "arguments": arguments},
                indent=2,
                sort_keys=True,
            ),
        )
        return

    # Client-side rate limit BEFORE config load: a rate-limited caller
    # should get a clear message, not a config error, when their env
    # is not yet set up. Disabled by --force-no-rate-limit or by
    # ETCH_RATE_LIMIT_PER_MINUTE=0.
    if not force_no_rate_limit:
        allowed, count, limit = check_and_record()
        if not allowed:
            click.echo(
                f"etch-record: rate limit hit ({count}/{limit} events in "
                f"the last 60s). Wait a few seconds and retry, or pass "
                f"--force-no-rate-limit for legitimate batch use. Adjust "
                f"the ceiling with ETCH_RATE_LIMIT_PER_MINUTE.",
                err=True,
            )
            sys.exit(4)

    try:
        cfg = load()
    except ConfigError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    try:
        body = record_event(cfg, arguments)
    except McpError as exc:
        click.echo(f"etch-record: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"etch-record: unexpected error: {exc}", err=True)
        sys.exit(3)

    event_id = extract_event_id(body) or "?"
    click.echo(f"OK  session={session}  event_id={event_id}")

    # Wave 1 #1 — if any governance flag was set, assemble the
    # governance object and POST it to the Etch chain endpoint.
    governance = _assemble_governance_from_flags(
        policy_hash=policy_hash,
        authority_file=authority_file,
        assumptions_file=assumptions_file,
        uncertainty=uncertainty,
        uncertainty_file=uncertainty_file,
        invalidation_file=invalidation_file,
        mission=mission,
        terminology_raw=terminology_raw,
        context_file=context_file,
    )
    if governance is not None:
        try:
            result = record_governance(cfg, event_id, governance)
        except GovernanceError as exc:
            click.echo(f"etch-record: governance-record: {exc}", err=True)
            # Base event was recorded successfully; the governance
            # sub-record failed. Exit non-zero so shell callers can
            # catch it, but keep the earlier OK line above so the
            # caller has the event_id to retry against.
            sys.exit(5)
        click.echo(
            f"OK  governance_seq={result.etch_chain_seq}  "
            f"governance_hash={result.governance_hash}",
        )

    # Wave 1 #2 — if the authority-receipt flags were set, sign the
    # claim locally with the Ed25519 privkey and POST to the Etch
    # chain authority-receipt endpoint. Independent of Wave 1 #1;
    # callers can attach a receipt without a governance object and
    # vice versa.
    authority_claim, priv, pubkey_ref = _prepare_authority_receipt(
        authority_privkey_file=authority_privkey_file,
        authority_id=authority_id,
        authority_scope=authority_scope,
        authority_expires_at=authority_expires_at,
        receipt_type=receipt_type,
    )
    if authority_claim is not None:
        signature_hex = sign_claim(priv, authority_claim)
        try:
            auth_result = record_authority_receipt(
                cfg=cfg,
                oss_event_id=event_id,
                claim=authority_claim,
                signature_hex=signature_hex,
                pubkey_ref=pubkey_ref,
            )
        except AuthorityError as exc:
            click.echo(f"etch-record: authority-receipt: {exc}", err=True)
            # Base event (and governance, if requested) succeeded. Exit 6
            # so shell callers can distinguish a receipt failure from a
            # governance failure (exit 5) or an MCP-layer failure (exit 2).
            sys.exit(6)
        click.echo(
            f"OK  authority_seq={auth_result.etch_chain_seq}  "
            f"authority_hash={auth_result.authority_hash}",
        )

    # Wave 1 #3 — if attestation flags are set, POST the model-card
    # attestation bundle to the Etch chain. Independent of the three
    # earlier calls; can be attached without governance or authority.
    attestation = _assemble_attestation_from_flags(
        model_card_hash=model_card_hash,
        system_prompt_hash=system_prompt_hash,
        attestation_policy_hash=attestation_policy_hash,
        model_id=model_id,
    )
    if attestation is not None:
        try:
            att_result = record_model_card_attestation(
                cfg=cfg,
                oss_event_id=event_id,
                attestation=attestation,
            )
        except AttestationError as exc:
            click.echo(f"etch-record: model-card-attestation: {exc}", err=True)
            # Everything upstream succeeded; only the attestation failed.
            # Exit 7 lets shell callers distinguish this from the earlier
            # sub-record failures (5 = governance, 6 = authority).
            sys.exit(7)
        click.echo(
            f"OK  attestation_seq={att_result.etch_chain_seq}  "
            f"attestation_hash={att_result.attestation_hash}",
        )

    # Wave 1 #4 — session risk score
    risk_payload = _prepare_risk_score(risk_score, risk_vendor, risk_basis)
    if risk_payload is not None:
        try:
            r = record_session_risk_score(cfg, event_id, risk_payload)
        except RiskScoreError as exc:
            click.echo(f"etch-record: session-risk-score: {exc}", err=True)
            sys.exit(8)
        click.echo(
            f"OK  risk_seq={r.etch_chain_seq}  risk_hash={r.risk_hash}",
        )

    # Wave 1 #5 — autonomy level
    autonomy_payload = _prepare_autonomy_level(
        autonomy_level, autonomy_scheme, autonomy_rationale,
    )
    if autonomy_payload is not None:
        try:
            r = record_autonomy_level(cfg, event_id, autonomy_payload)
        except AutonomyError as exc:
            click.echo(f"etch-record: autonomy-level: {exc}", err=True)
            sys.exit(9)
        click.echo(
            f"OK  autonomy_seq={r.etch_chain_seq}  "
            f"autonomy_hash={r.autonomy_hash}",
        )

    # Wave 1 #6 — supersession edge
    supersession_edge = _prepare_supersession_edge(
        supersedes_event_id, supersession_intent,
        supersession_depends_on, supersession_rationale,
    )
    if supersession_edge is not None:
        try:
            r = record_supersession_edge(cfg, event_id, supersession_edge)
        except SupersessionError as exc:
            click.echo(f"etch-record: supersession-edge: {exc}", err=True)
            sys.exit(10)
        click.echo(
            f"OK  supersession_seq={r.etch_chain_seq}  "
            f"edge_hash={r.edge_hash}",
        )

    # Wave 1 #7 — signed dissent
    dissent_prepared = _prepare_signed_dissent(
        dissent_privkey_file, dissenter_id, dissent_rationale,
    )
    if dissent_prepared is not None:
        dissent_payload, dissent_priv, dissent_pubkey_ref = dissent_prepared
        signature_hex = sign_claim(dissent_priv, dissent_payload)
        try:
            r = record_signed_dissent(
                cfg=cfg, oss_event_id=event_id,
                dissent=dissent_payload,
                signature_hex=signature_hex,
                pubkey_ref=dissent_pubkey_ref,
            )
        except DissentError as exc:
            click.echo(f"etch-record: signed-dissent: {exc}", err=True)
            sys.exit(11)
        click.echo(
            f"OK  dissent_seq={r.etch_chain_seq}  "
            f"dissent_hash={r.dissent_hash}",
        )

    # Wave 2 #10 — stop condition. Independent of every prior layer.
    # Follows the same "if X is not None: ..." pattern locked in
    # memory after the v0.4.0 short-circuit incident.
    stop_condition_payload = _prepare_stop_condition(
        stop_condition_id, stop_condition_reason, stop_condition_scope,
    )
    if stop_condition_payload is not None:
        try:
            r = record_stop_condition(
                cfg, event_id, stop_condition_payload,
            )
        except StopConditionError as exc:
            click.echo(f"etch-record: stop-condition: {exc}", err=True)
            sys.exit(13)
        click.echo(
            f"OK  stop_condition_seq={r.etch_chain_seq}  "
            f"stop_condition_hash={r.stop_condition_hash}",
        )


def _prepare_stop_condition(
    stop_condition_id: str | None,
    stop_condition_reason: str | None,
    stop_condition_scope: str | None,
) -> dict | None:
    """Wave 2 #10: assemble the stop-condition payload if the flags
    are set, else return None. --stop-condition-id and
    --stop-condition-reason are required together; --scope is
    optional."""
    provided = any((stop_condition_id, stop_condition_reason,
                    stop_condition_scope))
    if not provided:
        return None
    missing = []
    if stop_condition_id is None:
        missing.append("--stop-condition-id")
    if stop_condition_reason is None:
        missing.append("--stop-condition-reason")
    if missing:
        raise click.UsageError(
            "Wave 2 #10 stop condition requires: " + ", ".join(missing),
        )
    payload = {
        "condition_id": stop_condition_id,
        "halt_reason": stop_condition_reason,
        "attested_at": utc_iso_ms_now(),
    }
    if stop_condition_scope is not None:
        payload["session_scope"] = stop_condition_scope
    return payload


def _assemble_governance_from_flags(
    policy_hash: str | None,
    authority_file: Path | None,
    assumptions_file: Path | None,
    uncertainty: str | None,
    uncertainty_file: Path | None,
    invalidation_file: Path | None,
    mission: str | None = None,
    terminology_raw: str | None = None,
    context_file: Path | None = None,
) -> dict | None:
    """Compose the governance object from CLI flags, or return None if
    none of them are set (signals: skip the second API call).

    Wave 4 #15 additions: `mission` string, `terminology` list,
    `context` dict. Any of these plus the legacy 5 fields triggers
    the second call."""
    if not any((
        policy_hash, authority_file, assumptions_file,
        uncertainty, uncertainty_file, invalidation_file,
        mission, terminology_raw, context_file,
    )):
        return None

    if uncertainty and uncertainty_file:
        raise click.UsageError(
            "Pass only one of --uncertainty or --uncertainty-file, "
            "not both.",
        )

    gov: dict = {}
    if policy_hash:
        gov["policy_hash"] = policy_hash
    if authority_file is not None:
        gov["authority"] = _read_json_object(authority_file, "--authority-file")
    if assumptions_file is not None:
        gov["assumptions"] = _read_json_list(
            assumptions_file, "--assumptions-file",
        )
    if uncertainty is not None:
        gov["uncertainty"] = _parse_uncertainty_inline(uncertainty)
    elif uncertainty_file is not None:
        gov["uncertainty"] = _read_json_object(
            uncertainty_file, "--uncertainty-file",
        )
    if invalidation_file is not None:
        gov["invalidation_conditions"] = _read_json_list(
            invalidation_file, "--invalidation-file",
        )
    if mission:
        gov["mission"] = mission
    if terminology_raw:
        gov["terminology"] = [
            t.strip() for t in terminology_raw.split(",") if t.strip()
        ]
    if context_file is not None:
        gov["context"] = _read_json_object(context_file, "--context-file")
    return gov


def _read_json_object(path: Path, flag_name: str) -> dict:
    try:
        parsed = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise click.UsageError(
            f"{flag_name} could not be loaded: {exc}",
        ) from exc
    if not isinstance(parsed, dict):
        raise click.UsageError(f"{flag_name} must be a JSON object.")
    return parsed


def _read_json_list(path: Path, flag_name: str) -> list:
    try:
        parsed = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise click.UsageError(
            f"{flag_name} could not be loaded: {exc}",
        ) from exc
    if not isinstance(parsed, list):
        raise click.UsageError(f"{flag_name} must be a JSON array.")
    return parsed


def _parse_uncertainty_inline(raw: str) -> dict:
    """Parse '<confidence>:<basis>' into {confidence, basis}."""
    if ":" not in raw:
        raise click.UsageError(
            "--uncertainty must be 'confidence:basis' (e.g. "
            "'0.87:evidence-hash-match-rate').",
        )
    conf_str, basis = raw.split(":", 1)
    try:
        confidence = float(conf_str)
    except ValueError as exc:
        raise click.UsageError(
            f"--uncertainty confidence must be a float: {exc}",
        ) from exc
    if not (0.0 <= confidence <= 1.0):
        raise click.UsageError(
            "--uncertainty confidence must be in [0.0, 1.0].",
        )
    basis = basis.strip()
    if not basis:
        raise click.UsageError("--uncertainty basis must be non-empty.")
    return {"confidence": confidence, "basis": basis}


# ---------------------------------------------------------------------------
# Wave 2 #8 bulk import mode
# ---------------------------------------------------------------------------


def _run_import_mode(
    import_format: str | None,
    import_file: Path | None,
) -> None:
    """Read the events file, POST to /v1/import, print the summary.
    Exits directly on any error via click / sys.exit — never returns
    to the single-event flow."""
    if import_format is None:
        raise click.UsageError(
            "--import-file requires --import-format "
            "(otel-gen-ai | custom).",
        )
    if import_file is None:
        raise click.UsageError(
            "--import-format requires --import-file <path>.",
        )
    try:
        events = read_events_from_file(import_file)
    except BulkImportError as exc:
        click.echo(f"etch-record: import: {exc}", err=True)
        sys.exit(12)

    try:
        cfg = load()
    except ConfigError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    try:
        result = import_events(cfg, import_format, events)
    except BulkImportError as exc:
        click.echo(f"etch-record: import: {exc}", err=True)
        sys.exit(12)

    click.echo(
        f"OK  imported={result.count}  "
        f"kinds={dict(sorted(result.kinds.items()))}  "
        f"seq_range=[{result.first_etch_chain_seq}, "
        f"{result.last_etch_chain_seq}]",
    )
    if result.skipped:
        click.echo(
            f"    skipped={len(result.skipped)} events "
            f"(first={result.skipped[0] if result.skipped else None})",
            err=True,
        )


# ---------------------------------------------------------------------------
# Wave 1 #4/#5/#6/#7 helpers
# ---------------------------------------------------------------------------


def _prepare_risk_score(
    risk_score: float | None,
    risk_vendor: str | None,
    risk_basis: str | None,
) -> dict | None:
    provided = any((risk_score is not None, risk_vendor, risk_basis))
    if not provided:
        return None
    missing = []
    if risk_score is None:
        missing.append("--risk-score")
    if risk_vendor is None:
        missing.append("--risk-vendor")
    if risk_basis is None:
        missing.append("--risk-basis")
    if missing:
        raise click.UsageError(
            "Wave 1 #4 risk score requires: " + ", ".join(missing),
        )
    if not (0.0 <= risk_score <= 1.0):
        raise click.UsageError(
            "--risk-score must be in [0.0, 1.0]",
        )
    return {
        "score": risk_score,
        "vendor": risk_vendor,
        "basis": risk_basis,
        "attested_at": utc_iso_ms_now(),
    }


def _prepare_autonomy_level(
    autonomy_level: str | None,
    autonomy_scheme: str,
    autonomy_rationale: str | None,
) -> dict | None:
    if autonomy_level is None:
        return None
    payload = {
        "level": autonomy_level,
        "level_scheme": autonomy_scheme,
        "attested_at": utc_iso_ms_now(),
    }
    if autonomy_rationale is not None:
        payload["rationale"] = autonomy_rationale
    return payload


def _prepare_supersession_edge(
    supersedes_event_id: str | None,
    supersession_intent: str | None,
    supersession_depends_on: str,
    supersession_rationale: str | None,
) -> dict | None:
    provided = any((
        supersedes_event_id, supersession_intent,
        supersession_depends_on, supersession_rationale,
    ))
    if not provided:
        return None
    missing = []
    if supersedes_event_id is None:
        missing.append("--supersedes")
    if supersession_intent is None:
        missing.append("--supersession-intent")
    if missing:
        raise click.UsageError(
            "Wave 1 #6 supersession requires: " + ", ".join(missing),
        )
    depends = [
        s.strip() for s in supersession_depends_on.split(",") if s.strip()
    ] if supersession_depends_on else []
    edge = {
        "superseded_oss_event_id": supersedes_event_id,
        "intent": supersession_intent,
        "depends_on": depends,
        "attested_at": utc_iso_ms_now(),
    }
    if supersession_rationale is not None:
        edge["rationale"] = supersession_rationale
    return edge


def _prepare_signed_dissent(
    dissent_privkey_file: Path | None,
    dissenter_id: str | None,
    dissent_rationale: str | None,
):
    """Return (dissent_dict, priv, pubkey_ref) or None if no dissent
    flags were set."""
    provided = any((
        dissent_privkey_file, dissenter_id, dissent_rationale,
    ))
    if not provided:
        return None
    missing = []
    if dissent_privkey_file is None:
        missing.append("--dissent-privkey-file")
    if dissenter_id is None:
        missing.append("--dissenter-id")
    if dissent_rationale is None:
        missing.append("--dissent-rationale")
    if missing:
        raise click.UsageError(
            "Wave 1 #7 signed dissent requires: " + ", ".join(missing),
        )
    try:
        priv = load_ed25519_privkey(dissent_privkey_file)
    except Exception as exc:  # noqa: BLE001
        raise click.UsageError(str(exc)) from exc
    pubkey_hex = derive_pubkey_hex(priv)
    pubkey_ref = compute_key_ref(pubkey_hex)
    dissent = {
        "dissenter_id": dissenter_id,
        "rationale": dissent_rationale,
        "attested_at": utc_iso_ms_now(),
    }
    return dissent, priv, pubkey_ref


# ---------------------------------------------------------------------------
# Wave 1 #3 attestation helpers
# ---------------------------------------------------------------------------


def _assemble_attestation_from_flags(
    model_card_hash: str | None,
    system_prompt_hash: str | None,
    attestation_policy_hash: str | None,
    model_id: str | None,
) -> dict | None:
    """Compose the model-card attestation object from CLI flags, or
    return None if none of them are set (signals: skip the fourth API
    call).

    All-or-nothing on the required pair (model_card_hash + model_id):
    a partial invocation is a usage error, not a silently-dropped
    attestation.
    """
    provided = any((
        model_card_hash, system_prompt_hash,
        attestation_policy_hash, model_id,
    ))
    if not provided:
        return None

    missing = []
    if model_card_hash is None:
        missing.append("--model-card-hash")
    if model_id is None:
        missing.append("--model-id")
    if missing:
        raise click.UsageError(
            "Wave 1 #3 attestation requires: "
            + ", ".join(missing)
            + " (any attestation flag triggers all-required validation)",
        )

    attestation: dict = {
        "model_card_hash": model_card_hash,
        "model_id": model_id,
        "attested_at": utc_iso_ms_now(),
    }
    if system_prompt_hash is not None:
        attestation["system_prompt_hash"] = system_prompt_hash
    if attestation_policy_hash is not None:
        attestation["policy_hash"] = attestation_policy_hash
    return attestation


# ---------------------------------------------------------------------------
# Wave 1 #2 authority-receipt helpers
# ---------------------------------------------------------------------------


def _prepare_authority_receipt(
    authority_privkey_file: Path | None,
    authority_id: str | None,
    authority_scope: str,
    authority_expires_at: str | None,
    receipt_type: str | None,
):
    """Assemble the AuthorityClaim + load the privkey, or return
    (None, None, None) if the authority-receipt flags were not set.

    All-or-nothing: if any authority flag is set, all required ones must
    be set. Enforces the invariant that a partial invocation surfaces as
    a usage error, not a silently-dropped receipt.
    """
    provided = any((
        authority_privkey_file, authority_id, receipt_type,
        authority_scope, authority_expires_at,
    ))
    if not provided:
        return None, None, None

    missing = []
    if authority_privkey_file is None:
        missing.append("--authority-privkey-file")
    if authority_id is None:
        missing.append("--authority-id")
    if receipt_type is None:
        missing.append("--receipt-type")
    if missing:
        raise click.UsageError(
            "Wave 1 #2 authority receipt requires: "
            + ", ".join(missing)
            + " (any authority flag triggers all-required validation)",
        )

    try:
        priv = load_ed25519_privkey(authority_privkey_file)
    except Exception as exc:  # noqa: BLE001
        raise click.UsageError(str(exc)) from exc
    pubkey_hex = derive_pubkey_hex(priv)
    pubkey_ref = compute_key_ref(pubkey_hex)

    scope_list = [
        s.strip() for s in authority_scope.split(",") if s.strip()
    ] if authority_scope else []

    claim = {
        "authority_id": authority_id,
        "scope": scope_list,
        "receipt_type": receipt_type,
        "attested_at": utc_iso_ms_now(),
    }
    if authority_expires_at is not None:
        claim["expires_at"] = authority_expires_at

    return claim, priv, pubkey_ref
