# Changelog

All notable changes to `etch-record` (the CLI helper for the Etch signed
audit chain).

## v0.8.0 — 2026-08-02

Wave 4 #15 8-category drift engine. Extends the governance object
with 3 new optional fields (mission / terminology / context) so the
server can populate an 8-dimension projection index. Drift detection
runs offline via `etch-chain-verify` (added server-side).

Server-side dependency: etch commit adding the multi-dim projection
(this release cycle's server change).

### Added

- `--mission <string>` — mission statement (e.g. "customer KYC
  compliance decisions"). Hashed server-side.
- `--terminology <t1,t2,...>` — comma-separated key terms. Set-hashed
  server-side.
- `--context-file <path>` — JSON object describing operating context.
  Any shape accepted; canonical-json-hashed server-side.

Any of the new flags (alone or with legacy governance flags) triggers
the governance sub-record call and populates the multi-dim index.

### Positioning

Wave 4 #15 is the largest single feature in the boundary plan (10
dev-days). Ships the full OHRP v2.0 8-category surface:
mission / assumption / confidence / evidence / scope / terminology /
authority / context. No observability vendor claims this surface.

Content angle for marketing: "8 drift dimensions with independent
comparators, per-decision on-chain evidence, offline verifier."

## v0.7.0 — 2026-08-02

Wave 2 #10. Adds three flags for recording an explicit halt event
on the Etch chain. AI kill-switch compliance for regulated
deployments — SR 11-7, EU AI Act Art 14, SS3/18.

Server-side dependency: etch commit that includes
`/v1/etch-chain/stop-condition` (this release cycle's server change).

### Added

- `--stop-condition-id <label>` — human-readable halt label.
- `--stop-condition-reason <text>` — free-text explanation.
- `--stop-condition-scope <session_id>` — optional session_id
  to constrain the halt. Omit for a project-wide halt.
- New module `etch_record.stop_condition_client` with
  `record_stop_condition`.
- New exit code `13` — stop-condition failed.

### Halt-violation detection

The offline verifier (`etch-chain-verify` in the etch package) now
walks stop_condition rows and flags any OSS events with timestamp >
halt.ts as violations. First-ship intentionally strict — no
deactivation semantics yet (that's Wave 5+). Regulators prefer
over-flagging to under-flagging.

## v0.6.0 — 2026-08-02

Wave 2 #8. Adds bulk import mode. `etch-record --import-format
<fmt> --import-file <path>` reads a file of external-format events
and POSTs them as a batch to `/v1/import`. Turns Datadog / Arize /
Langfuse / Mastra / OTel GenAI spans into ingest sources instead of
competitors.

Server-side dependency: etch commit `a8129e1` or later.

### Added

- `--import-format <otel-gen-ai | custom>` — format of the events
  in the file. `otel-gen-ai` maps OTel GenAI semantic-convention
  spans to `model_card_attestation` rows; `custom` is a generic
  passthrough where the caller supplies
  `{kind, payload, oss_event_id_ref}` per event.
- `--import-file <path>` — accepts `.jsonl` / `.ndjson` (one JSON
  object per line), `.json` array, or `.json` `{"events": [...]}`.
  Max 500 events per file — split larger batches.
- New module `etch_record.import_client` with `read_events_from_file`
  and `import_events`.
- New exit code `12` — bulk import failed (file parse error,
  transport failure, or server 400/500).

### Import-mode semantics

When either `--import-format` or `--import-file` is set, etch-record
switches to import mode:
- The positional description arg is IGNORED.
- Every Wave 1 sub-record flag is IGNORED.
- No MCP `record_event` call is made.
- The file's events go through the format adapter server-side and
  land on the Etch chain as per-event rows.

`--import-format` alone or `--import-file` alone is a usage error
(exit 2), never a silent partial invocation.

Output on success:

```
OK  imported=N  kinds={...}  seq_range=[first, last]
```

If any events were skipped by the adapter (unknown kind under
`custom`, span without `gen_ai.request.model` under `otel-gen-ai`),
the count is printed on stderr alongside the first skip's `{index,
reason}` object.

### Follow-ups

`langsmith`, `cloudtrail`, and `vercel-ai` format adapters will
extend the `--import-format` choice list; those are follow-up
releases after v0.6.0. The `custom` escape hatch covers everything
in the meantime.

## v0.5.0 — 2026-08-01

Wave 1 #4-#7 in one release. Adds ten new CLI flags across four
independent Etch chain sub-records: session risk score, autonomy
level, supersession DAG edge, and signed dissent. Every Wave 1
endpoint is now callable from etch-record.

Server-side dependency: etch commit `c355526` or later (adds all
four endpoints in one commit).

### The 1-to-8 call sequence

etch-record now supports up to eight sequential calls per
invocation. Each sub-record is triggered by its own flag set;
every layer is independent:

  1. record_event (MCP)              → OSS chain base event
  2. record_governance               → Wave 1 #1
  3. record_authority_receipt        → Wave 1 #2 (Ed25519)
  4. record_model_card_attestation   → Wave 1 #3
  5. record_session_risk_score       → Wave 1 #4
  6. record_autonomy_level           → Wave 1 #5
  7. record_supersession_edge        → Wave 1 #6
  8. record_signed_dissent           → Wave 1 #7 (Ed25519, reuses
                                                   #2 pubkey registry)

Exit codes: 5 governance, 6 authority, 7 attestation, 8 risk,
9 autonomy, 10 supersession, 11 dissent.

### Added flags

Wave 1 #4 session risk score:
  --risk-score <0.0-1.0>  --risk-vendor <slug>  --risk-basis <text>

Wave 1 #5 autonomy level:
  --autonomy-level <L0-L3 | custom>  --autonomy-scheme <standard-L0-L3 | buyer-custom>  --autonomy-rationale <text>

Wave 1 #6 supersession edge:
  --supersedes <oss_event_id>  --supersession-intent <compat|breaking|deprecation|correction|refinement>
  --supersession-depends-on <comma-separated>  --supersession-rationale <text>

Wave 1 #7 signed dissent (reuses Wave 1 #2 pubkey registration):
  --dissent-privkey-file <PEM>  --dissenter-id <string>  --dissent-rationale <text>

### Fixed

Wave 1 #3 attestation block used to `return` if no attestation flags
were set, which short-circuited past every Wave 1 #4-#7 downstream
layer. Rewritten as an independent `if attestation is not None: ...`
block to match every other Wave 1 layer. Regression tests added for
each of the four new items in the same "only THIS layer active"
shape.

### Deps

No new dependencies. cryptography (Ed25519) already required since
v0.3.0.

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
