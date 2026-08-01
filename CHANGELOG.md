# Changelog

All notable changes to `etch-record` (the CLI helper for the Etch signed
audit chain).

## v0.4.1 — 2026-08-01

Bug fix. v0.4.0 silently skipped the Wave 1 #3 attestation call
whenever the Wave 1 #2 authority-receipt flags were absent. Root
cause: the authority block had `if authority_claim is None: return`
which short-circuited past every downstream sub-record call
(including attestation) when no authority flags were set. Rewritten
as an `if authority_claim is not None: ...` block so each layer is
independent of every other.

Callers using ANY combination of Wave 1 flags now work as
documented, including attestation-only invocations. If you saw only
`OK  event_id=...` without `OK  attestation_seq=...` on v0.4.0 with
`--model-card-hash` set, this release fixes that. Base event was
already recorded — the printed `event_id` is still valid for a
manual retry.

Adds three regression tests: attestation-only reaches the fourth
call; attestation failure produces exit code 7; no-attestation-flags
skips the fourth call entirely.

## v0.4.0 — 2026-08-01

Wave 1 #3 of the Etch parallel chain roadmap. Adds four flags that
attach a signed bundle of model / system-prompt / policy content
hashes to any event, cross-referencing the OSS event by its ID.
Positioning: cryptographic specificity for "which AI made this
decision" — observability tools show model versions in a span field;
this attestation commits them to a signed chain that is externally
anchored.

Server-side dependency: the etch server MUST run commit `935cdc1` or
later (adds POST /v1/etch-chain/model-card-attestation).

### Added

- `--model-card-hash <sha256:hex>` — SHA-256 of the model card
  document governing this session. Triggers a fourth call to
  `/v1/etch-chain/model-card-attestation`.
- `--system-prompt-hash <sha256:hex>` — optional. SHA-256 of the
  system prompt in force at session start.
- `--attestation-policy-hash <sha256:hex>` — optional. SHA-256 of the
  session-scoped policy (distinct from `--policy-hash` on Wave 1 #1
  governance, which is per-event).
- `--model-id <string>` — human-readable model label
  ('claude-opus-4-7', 'gpt-4o-2024-05-13'). Required whenever
  `--model-card-hash` is set. Not authoritative — the hash is — but
  auditors want the label for triage.
- New module `etch_record.attestation_client` with
  `record_model_card_attestation`.
- New exit code `7` — model-card attestation failed. Base event (and
  governance / authority receipt, if requested) still succeeded.

### The 1-2-3-4 call sequence

etch-record now supports the full four-call sequence:

1. `record_event` (MCP)      → OSS chain base event
2. `record_governance`       → Wave 1 #1 (governance sub-record)
3. `record_authority_receipt`→ Wave 1 #2 (Ed25519-signed receipt)
4. `record_model_card_attestation` → Wave 1 #3 (session-scoped hashes)

Any subset of the four is valid; each layer is independent. Exit
codes: 5 = governance, 6 = authority, 7 = attestation.

### Example

```
etch-record "KYC decision on customer XYZ" \
  --tags kyc,fintech,decision \
  --policy-hash sha256:9f8c... \
  --authority-privkey-file ~/keys/compliance.pem \
  --authority-id compliance-officer-2 \
  --receipt-type hitl_approval \
  --model-card-hash sha256:1a2b3c... \
  --model-id claude-opus-4-7
```

Four OK lines expected:

```
OK  session=...  event_id=...
OK  governance_seq=1  governance_hash=sha256:...
OK  authority_seq=1   authority_hash=sha256:...
OK  attestation_seq=1 attestation_hash=sha256:...
```

## v0.3.0 — 2026-08-01

Wave 1 #2 of the Etch parallel chain roadmap. Adds five flags that
sign a bounded authority claim locally with an Ed25519 private key and
attach it to any event on the Etch parallel chain, cross-referencing
the OSS event by its ID.

Server-side dependency: the etch server MUST run commit `127b3f7` or
later. The pubkey MUST be registered in advance via the operator CLI:

```
etch add-authority-key <project_id> <authority_id> <pubkey_hex>
```

Generate a key on your side:

```
openssl genpkey -algorithm ed25519 -out authority.pem
openssl pkey -in authority.pem -pubout -outform DER \
  | tail -c 32 | xxd -p -c 32
```

### Added

- `--authority-privkey-file <path>` — Ed25519 private key in PEM
  format. Client signs the canonical JSON of the claim locally; the
  key never leaves your machine.
- `--authority-id <string>` — human-readable identity, must match the
  authority_id used when the pubkey was registered.
- `--authority-scope <s1,s2,...>` — comma-separated scope tags.
- `--authority-expires-at <ISO 8601>` — optional expiration.
- `--receipt-type <vested_authority | hitl_approval | automated_by_policy>`
- New module `etch_record.authority_client` with `load_ed25519_privkey`,
  `derive_pubkey_hex`, `compute_key_ref`, `sign_claim`, and
  `record_authority_receipt`.
- New exit code `6` — authority sub-record failed. Base event (and
  governance, if requested) succeeded; retry the receipt with the
  printed `event_id`.

### Changed

- Governance now runs even when authority flags are set (previously
  the CLI returned after governance; that broke the three-call
  composition). Governance-only invocations behave identically to
  v0.2.1.

### Added dependency

- `cryptography>=42` (Ed25519 signing).

### Example

```
etch-record "KYC decision on customer XYZ" \
  --tags kyc,fintech,decision \
  --policy-hash sha256:9f8c... \
  --uncertainty '0.87:hash-lookup-match-rate' \
  --authority-privkey-file ~/keys/compliance.pem \
  --authority-id compliance-officer-2 \
  --authority-scope kyc-decisions,pii-approvals \
  --receipt-type hitl_approval
```

Three OK lines expected on success:

```
OK  session=etch-record-2026-08-01  event_id=abc-def-123
OK  governance_seq=1  governance_hash=sha256:...
OK  authority_seq=1   authority_hash=sha256:...
```

## v0.2.1 — 2026-08-01

Cosmetic patch. The `etch-record --version` string and the MCP
`clientInfo.version` field in the initialize handshake now report the
actual package version (previously frozen at `0.1.0` because
`__version__` in `src/etch_record/__init__.py` was not bumped in
v0.2.0).

No behavior changes. Users on v0.2.0 who do not care about the version
banner or the client-identity string do not need to upgrade.

## v0.2.0 — 2026-08-01

Wave 1 #1 of the Etch parallel chain roadmap ships in this release. Adds
five governance flags that attach a signed governance sub-record to any
event on the Etch parallel chain, cross-referencing the OSS event by
its ID.

### Added

- `--policy-hash <hash>` — SHA-256 hash of the governance policy under
  which the decision was evaluated. Must be `sha256:<64-hex>` shape.
- `--authority-file <path>` — path to a JSON file describing the
  approving authority: `{identity, scope, expires_at}`.
- `--assumptions-file <path>` — path to a JSON array listing assumptions
  accepted when reaching the decision. Each entry is
  `{claim, source_ref}`.
- `--uncertainty '<confidence>:<basis>'` — inline uncertainty in
  `confidence:basis` shape (e.g. `'0.87:evidence-hash-match-rate'`).
  Confidence bounded to `[0.0, 1.0]`.
- `--uncertainty-file <path>` — path to a JSON object with the full
  uncertainty shape: `{confidence, basis}`.
- `--invalidation-file <path>` — path to a JSON array listing
  conditions under which the approval would have been invalidated.
  Each entry is `{"if": ..., "then": ...}`.
- New module `etch_record.governance_client` with `record_governance`
  function for programmatic use.
- New exit code `5` — governance sub-record failed. The base event
  was recorded successfully; use the printed `event_id` to retry
  the governance call against.

### How the two-call sequence works

When any governance flag is set, the CLI makes two calls in sequence:

1. `record_event` MCP call — creates the base event on the OSS chain
   (existing behavior, unchanged).
2. `record_governance` HTTP call — hashes the governance object,
   POSTs to `/v1/etch-chain/governance-record` on your Etch base URL.
   The Etch server signs it into the parallel chain and returns
   the chain seq + governance hash.

Both calls succeed → the CLI prints two OK lines. First call succeeds
and second fails → the CLI exits with code 5 after printing the
first-call OK (so callers keep the event_id to retry against).

### Requirements

The Etch server-side endpoint (`POST /v1/etch-chain/governance-record`,
shipped 2026-08-01 in etch commit `8676c87`) must be deployed for these
flags to work. If the endpoint is not yet available, calling one of
these flags will fail with a `transport failed` or `404` error surfaced
via `GovernanceError`.

### Example

```bash
etch-record "KYC decision on customer ABC" \
  --tags kyc,fintech,decision \
  --policy-hash sha256:9f8c... \
  --authority-file /tmp/authority.json \
  --uncertainty '0.87:hash-lookup-match-rate' \
  --invalidation-file /tmp/invalidation_conditions.json
```

Output (both calls succeed):

```
OK  session=etch-record-2026-08-01  event_id=abc-def-123
OK  governance_seq=1  governance_hash=sha256:xyz...
```

### Unchanged

- All non-governance flags behave identically to v0.1.0.
- Calls without any governance flag do NOT invoke the second HTTP
  endpoint; behavior is byte-identical to v0.1.0.
- Exit codes 0-4 unchanged (0 success, 1 config error, 2 MCP error,
  3 unexpected error, 4 rate limit).

## v0.1.0 — 2026-07-27

Initial public version. Single-call `record_event` CLI for signing
any event into an Etch audit chain from the command line.
