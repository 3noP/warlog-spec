# Compatibility matrix

## Spec version × provider implementation

This file tracks which implementations **claim conformance** to which spec
versions. Conformance means: passes the conformance test suite in
`tests/conformance/` and round-trips all canonical examples without
semantic loss.

> **Status:** first public release at v0.1.0 (experimental, pre-v1.0).
> The conformance test suite ships at v0.1.0 with Level 1 (Read)
> operational, Level 2 (Write) covering 18 canonical productible
> types, and Level 4 (Provider) mock-vendor report validation. The
> matrix below tracks the reference implementations that
> ship in this same release.

## Where the schemas live

The canonical schemas live under `schemas/`, indexed by
`schemas/manifest.json`. During the J-day release, the public mirror
serves the same tree at
**`https://3noP.github.io/warlog-spec/schemas/<version>/`**.

- Pre-v1 : `<version>` = `draft`
- v1.0+ : `<version>` = `v1.0`, `v1.1`, …

For v0.1, the checked-in schema tree and manifest are the source of
truth. Remote GitHub Pages URLs are verified during the release smoke
sequence.

### Conformance matrix

| Implementation | Type | Language | Levels claimed | Spec versions | Last verified |
|----------------|------|----------|----------------|---------------|---------------|
| `warlog-spec` (Python) | reference | Python | 1, 2 (18/18 productible types via `warlog_spec.conformance.produce_all`), 4 (mock-vendor provider report) | `0.1.0` (draft) | 2026-05-25 |
| `@warlog/spec` (TypeScript) | reference | TypeScript | 1, 2 (18/18 productible types via `produceAll`, byte-equivalent to `warlog-spec`), 4 (mock-vendor provider report) | `0.1.0` (draft) | 2026-05-25 |
| `@warlog/mcp-proxy` | reference | TypeScript | Audit middleware — signs every intercepted MCP `tools/call` into the canonical HMAC chain. Not a Level 1-4 implementation per se ; the spec contract is consumed transitively via `@warlog/spec`. | `0.1.0` (draft) | 2026-05-21 |
| *(Warlog backend Levels 1, 2, 4 — backend repo is not part of this public release ; see `warlog-spec-py.integrate.audited` for the Pattern A reference runtime that exercises the trust-layer in ~200 SLOC)* | reference | Python | — | — | — |
| *(no external implementations yet — first OSS / MSSP partner welcome)* | external | — | — | — | — |

### Provider evidence backing Level 4 claim

The Level 4 claim is now backed by a deterministic mock-vendor report,
not by the Warlog product runtime. Reference packages emit the report
with:

```sh
warlog-spec provider-check --out ./provider-report.json
python warlog-spec/tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
```

The runner validates the embedded Provider ABI objects and verifies these
semantic checks: dry-run has no vendor mutation, apply succeeds, verify
confirms vendor state, replaying the same idempotency key does not create
a duplicate mutation, and unsupported actions are rejected with
`ConnectorError.category = policy`.

### Connector examples

Reference connectors shipped with the spec packages :

#### `warlog-spec-py/examples/`

| Connector | Vendor | Family | Actions |
|---|---|---|---|
| `echo_connector` | Warlog Demo EDR | device | host.isolate, host.unisolate, alert.acknowledge |
| `crowdstrike_falcon_connector` | CrowdStrike Falcon | edr | host.isolate / unisolate / restart / collect_artifacts, ip/domain/url/hash.block (8 actions) |
| `okta_user_response_connector` | Okta Identity | iam | user.disable, user.force_logout, user.reset_mfa, user.revoke_tokens, user.reset_password, user.expire_password, user.unlock, user.group_remove, user.delete (9 actions) |
| `palo_alto_panos_connector` | Palo Alto PAN-OS | network | ip/domain/url.block + unblock + session.terminate (7 actions) |
| `aws_response_connector` | AWS multi-service | iam/key/storage | iam.role_*, iam.credentials_*, key.*, bucket.*, host.* (14 actions) |
| `proofpoint_connector` | Proofpoint TAP/TRAP | email | email.quarantine/recall/release, email.block/unblock_sender (5 actions) |
| `zscaler_zia_connector` | Zscaler ZIA/ZPA | network | 7 actions purely from existing canon (negative-result audit) |
| `virustotal_enricher` | VirusTotal | enricher | EnrichmentAssessment producer (read-side) |

#### `warlog-spec-ts/examples/`

| Connector | Vendor | Family | Actions |
|---|---|---|---|
| `echo-connector` | Warlog Demo EDR | device | host.isolate, host.unisolate |
| `crowdstrike-falcon-connector` | CrowdStrike Falcon | edr | host.isolate, host.unisolate, host.collect_artifacts, file.quarantine, hash.block (5 actions) |
| `okta-user-response-connector` | Okta Identity | iam | user.disable, user.force_logout, user.reset_mfa, user.revoke_tokens, user.reset_password (5 actions) |

The TS connectors use the built-in `fetch` API, accept OAuth2 client
credentials (Falcon) or SSWS API token (Okta), and demonstrate the
GDPR pseudonymization gate at the connector level (Okta's
`resolveSubject` callback).

#### Out-of-tree (planned)

| Connector | Vendor | Status |
|---|---|---|
| SentinelOne Singularity | edr | planned |
| Microsoft Defender XDR | edr | planned |

### Verification method

- **Level 1 (Read)** : run `python warlog-spec/tests/conformance/runner.py
  --level 1`. Validates every example in `examples/` against its matching
  schema.
- **Level 2 (Write)** : implementation produces a conformant fixture for
  each of the 18 productible types and the runner validates them all.
  Reproduce from a clean checkout :

      python -m warlog_spec.conformance dump --out ./fixtures
      python warlog-spec/tests/conformance/runner.py \
          --level 2 --fixtures-dir ./fixtures

  At `0.1.0` : `warlog-spec` (Python) produces 18/18 fixtures, all
  validate, coverage 18/18. `@warlog/spec` (TypeScript) ditto, with
  byte-equivalent canonicalization on the pinned audit row (see
  `packages/warlog-spec-py/tests/test_canonical_row_bytes.py` and
  `packages/warlog-spec-ts/tests/audit-chain.test.ts` for the matching
  goldens).

  Bundle types (`TriageBundle`, `InvestigationBundle`, `ResponseBundle`,
  `IncidentBundle`) are intentionally NOT in the productible set — they
  are product-specific UI projections, not interop contract.
- **Level 3 (Full)** : both Level 1 and Level 2 against the same impl,
  across declared scope. `warlog-spec` qualifies — Level 1 passes
  against the canonical examples and Level 2 passes against its own
  produced fixtures. To formally claim Level 3, an implementation MUST
  also document its declared scope (which artifact types it covers).
- **Level 4 (Provider)** : emits a mock-vendor provider report and the
  conformance runner accepts it with `--level 4 --provider-report`. The
  claim covers Provider ABI lifecycle behavior only: authenticate,
  side-effect-free dry_run, idempotent apply, verify, and policy rejection
  for unsupported actions. It does not publish or standardize the Warlog
  runtime, approval workflow, audit persistence, or tenant policy engine.

### Reference implementations — claim details

- `warlog-spec` (Python, in `packages/warlog-spec-py/`) :
  - Pydantic models : `warlog_spec.provider_abi`, `warlog_spec.artifacts`,
    `warlog_spec.proposals`, `warlog_spec.pack_manifest`, `warlog_spec.enums`
  - Level 2 producer : `warlog_spec.conformance.produce_all` with 18
    factories (one per productible artifact type)
  - Self-test : `pytest packages/warlog-spec-py/tests/test_conformance_level_2.py`
    proves every factory output validates against the matching schema and
    that the producer covers exactly the 18 productible types
  - CLI : `python -m warlog_spec.conformance dump --out DIR/` writes
    one fixture per type into the layout the runner expects
  - Provider check : `python -m warlog_spec.conformance provider-check
    --out provider-report.json` emits the Level 4 mock-vendor evidence
    report consumed by the public runner
  - Integration helper : `warlog_spec.integrate.audited` decorator +
    `WarlogClient` + optional `ApprovalGate` Protocol. Pure-Python,
    in-process audit + signing for AI agent tool calls (sync + async).

- `@warlog/spec` (TypeScript, in `packages/warlog-spec-ts/`) :
  - Zod schemas + inferred types across the same surface (provider-abi,
    artifacts, proposals, pack-manifest, enums)
  - Level 2 producer : `produceAll()` from `@warlog/spec/conformance`
    covering the same 18 productible types
  - Provider check : `warlog-spec provider-check --out provider-report.json`
    emits the same Level 4 mock-vendor evidence report shape
  - Cross-language byte-equivalence : `tests/audit-chain.test.ts`
    compares `canonicalizeV1` output against the Python `_GOLDEN`
    byte-for-byte

- `@warlog/mcp-proxy` (TypeScript, in `packages/warlog-mcp-proxy/`) :
  - stdio JSON-RPC proxy that intercepts MCP `tools/call` messages
    between any MCP client (Claude Desktop, Cursor, Cline) and any
    backend MCP server, signs every intercepted call into a local
    HMAC chain, and forwards transparently
  - YAML mapping file maps MCP tool names to canonical
    `ResponseActionId` values, validated against the catalog at startup

## OCSF mapping status

How Warlog Spec artifacts map to OCSF event categories. Filled out as we
formalize the input adapter.

| Warlog artifact | OCSF source | Mapping status |
|-----------------|-------------|----------------|
| `TriggerSignalRef` | any OCSF event | implemented for Detection Finding reference mapper via stable payload hash |
| `ClassificationAssessment` | `Detection Finding` (cat 2004) | reference mapper implemented in Python and TypeScript |
| `IOC` (extracted) | `File Activity`, `Network Activity` indicators | draft |
| `NormalizedEntity` | OCSF `Actor`, `Endpoint`, `User` objects | draft |
| `MitreAssessment` | OCSF `attacks[]` field | implemented when `attacks[]` carries tactic / technique ids |
| `EnrichmentAssessment` | Detection Finding entities and observables | reference mapper implemented for related entities and matched IOCs |

The Warlog alert workflow envelope remains runtime-owned. The public mapper
projects OCSF into portable evidence artifacts; it does not standardize
queueing, alert persistence, correlation, deduplication, or tenant routing.

## STIX mapping status

| Warlog artifact | STIX 2.1 object | Mapping status |
|-----------------|-----------------|----------------|
| `IOC` | `Indicator` | draft |
| `KB Article (CONTEXT)` | `Report`, `Note` | draft |
| `KB Article (DOCTRINE)` | `Course of Action` | draft |
| `Case` | `Incident` (STIX 2.1 ext) | draft |

## Conformance level definitions

- **Level 1 — Read** : implementation can parse and validate spec artifacts.
- **Level 2 — Write** : implementation can produce conformant artifacts.
- **Level 3 — Full** : implementation supports both read & write across all
  artifact types declared in its scope.
- **Level 4 — Provider** : implementation emits a mock-vendor report that
  proves Provider ABI lifecycle behavior and passes
  `runner.py --level 4 --provider-report`.
- **Level 5 — Live validated** : Level 4 plus documented validation against
  a real tenant or lab environment. The v0.1 reference connectors do not
  claim this level.

Most adopters target Level 2 first (produce alerts that consumers can route
into Warlog or compatible workflow engines).

The static preview in `registry/index.json` mirrors these levels without
turning the v0.1 release into a hosted registry service or certification
program.
