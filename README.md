# etch-record

Small CLI helper. Signs any event into your Etch audit chain from the command line.

Built for the marketing-agent workflow: every research call, draft generation, review decision, and outreach send emits a signed event. Also usable standalone for any local activity you want notarized.

**Latest: v0.11.0** — Wave 6 COMPLETE. MASTER PLAN 23 OF 23 SHIPPED (100%). Adds artifact-hash (`--artifact <path>` for chain-signing the SHA-256 of any file), idempotency-collapse (`--idempotency-principal` + `--idempotency-scope` + `--idempotency-tool-version` + `--idempotency-argument-hash` for retry-storm dedup), and learning-persistence (`--learning-from-event` + `--learning-content-hash` + `--learning-propagation` for cross-session signed knowledge updates). Sixteen endpoints total now available on your Etch chain across Waves 1-6. See [CHANGELOG.md](CHANGELOG.md).

## Install

```bash
pip install etch-record
```

Or from a local checkout during development:

```bash
cd ~/etch-marketing/etch-record
pip install -e .
```

## Configure

Set three env vars in your shell rc (`~/.zshrc` or `~/.bashrc`):

```bash
export ETCH_PROJECT_ID="your_project_id"
export ETCH_APP_TOKEN="wm_your_app_token"
export ETCH_BASE_URL="https://etch.systems"   # default; override for local dev
```

Get `project_id` + `app_token` from your Etch signup provisioning page. `ETCH_BASE_URL` defaults to `https://etch.systems` if unset.

## Use

```bash
# Simple event
etch-record "posted X thread about Etch's audit chain"

# With tags + evidence
etch-record "researched contact via Gemini" \
  --tags research,marketing \
  --evidence-json '{"contact":"...","dossier_lines":247}'

# Load evidence from a file
etch-record "drafted 3 message variants" \
  --tags draft,claude \
  --evidence-file drafts_evidence.json

# Group events under a session (default = today's ISO date)
etch-record "approved draft v2" --session-id outreach-2026-07-26 --tags review,approved

# Print what would be sent without hitting the API
etch-record "dry run test" --dry-run
```

## Event shape

Every call becomes a signed `record_event` MCP tool call on your Etch chain:

- `event_type`: `"tool_call"` (only enum value that works for arbitrary marketing events)
- `session_id`: `--session-id` OR auto-generated as `etch-record-YYYY-MM-DD`
- `entities`: derived from `--tags`
- `description`: your quoted string (positional arg)
- `evidence`: from `--evidence-json` or `--evidence-file`
- `success`: `true` unless `--failed`

The Etch server appends to the SHA-256 Merkle chain, closes epochs at threshold (default 1024 events), hybrid-signs (Ed25519 + SLH-DSA-SHA2-128f), and optionally anchors to Sigstore Rekor + Bitcoin OpenTimestamps.

## Verify

Every event is verifiable offline forever:

```bash
etch-verify \
  --base-url https://etch.systems \
  --project-id your_project_id
```

## Governance metadata (Wave 1 #1, v0.2.0)

Attach a signed governance sub-record to any event. Any of the five flags below triggers a second call to `POST /v1/etch-chain/governance-record` on your Etch base URL, which hashes the governance object canonically and signs it into the Etch parallel chain.

```bash
etch-record "KYC decision on customer ABC" \
  --tags kyc,fintech,decision \
  --policy-hash sha256:9f8c... \
  --authority-file authority.json \
  --uncertainty '0.87:hash-lookup-match-rate' \
  --invalidation-file invalidation_conditions.json
```

`authority.json`:

```json
{
  "identity": "compliance-officer@acme.example",
  "scope": ["fintech-kyc-decisions"],
  "expires_at": "2026-12-31T23:59:59Z"
}
```

`invalidation_conditions.json`:

```json
[
  {"if": "SOP hash changes", "then": "re-approve required"}
]
```

Assumptions file uses the same shape:

```json
[
  {"claim": "SOP v3.2 is current", "source_ref": "doc_hash:xyz"}
]
```

Output when both calls succeed:

```
OK  session=etch-record-2026-08-01  event_id=abc-def-123
OK  governance_seq=1  governance_hash=sha256:xyz...
```

The base event was recorded via the OSS chain; the governance sub-record was signed into the Etch parallel chain and cross-references the event by ID. Both chains verify offline via `etch-verify` (OSS) and `etch-chain-verify` (Etch).

## Exit codes

- `0` success (including two-call success when governance flags were set)
- `1` config error (missing env vars)
- `2` MCP `record_event` error
- `3` unexpected exception
- `4` rate limit (client-side sliding window)
- `5` governance sub-record failed — the base event was recorded successfully; use the printed `event_id` to retry the governance call
- `13` stop-condition sub-record failed
- `14` postmortem sub-record failed
- `15` cross-chain-reference sub-record failed
- `16` hsm-attestation sub-record failed
- `17` custody-export sub-record failed
- `18` artifact-hash sub-record failed
- `19` idempotency-collapse sub-record failed
- `20` learning-persistence sub-record failed
