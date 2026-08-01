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
from .config import ConfigError, load
from .governance_client import GovernanceError, record_governance
from .mcp_client import McpError, extract_event_id, record_event
from .rate_limit import check_and_record


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
) -> None:
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
    )
    if governance is None:
        return

    try:
        result = record_governance(cfg, event_id, governance)
    except GovernanceError as exc:
        click.echo(f"etch-record: governance-record: {exc}", err=True)
        # Base event was recorded successfully; the governance sub-record
        # failed. Exit non-zero so shell callers can catch it, but keep
        # the earlier OK line above so the caller has the event_id to
        # retry against.
        sys.exit(5)

    click.echo(
        f"OK  governance_seq={result.etch_chain_seq}  "
        f"governance_hash={result.governance_hash}",
    )


def _assemble_governance_from_flags(
    policy_hash: str | None,
    authority_file: Path | None,
    assumptions_file: Path | None,
    uncertainty: str | None,
    uncertainty_file: Path | None,
    invalidation_file: Path | None,
) -> dict | None:
    """Compose the governance object from CLI flags, or return None if
    none of them are set (signals: skip the second API call)."""
    if not any((
        policy_hash, authority_file, assumptions_file,
        uncertainty, uncertainty_file, invalidation_file,
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
