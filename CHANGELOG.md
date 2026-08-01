# Changelog

All notable changes to `etch-record` (the CLI helper for the Etch signed
audit chain).

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
