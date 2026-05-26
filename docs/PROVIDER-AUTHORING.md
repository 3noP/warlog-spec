# Provider Authoring Contract

This page is the checklist for connector authors. It describes what a
Warlog Spec provider must do without requiring the Warlog backend.

## Required Surface

A response connector declares one `ConnectorCapability` and implements
the Provider ABI lifecycle:

1. `authenticate` proves credentials are usable.
2. `dry_run` validates the action can be attempted without side effects.
3. `apply` performs the vendor mutation and returns `ResponseActionResult`.
4. `verify` confirms the expected vendor-side state when the vendor API
   exposes a reliable read path.

The connector consumes `ResponseActionSpec` and produces
`ResponseActionResult` or `ConnectorError`. It does not need a Warlog
database, Warlog UI, or Warlog L2M runtime.

## Non-Negotiable Rules

- Declare every supported `ResponseActionId` in `ConnectorCapability`.
- Reject action IDs that are not declared by the connector.
- Forward `spec.idempotency_key` to the vendor when the vendor supports
  idempotency; otherwise keep a connector-side de-duplication map.
- Keep `dry_run` side-effect free.
- Map vendor auth, policy, quota, transient, conflict, and validation
  failures into `ConnectorError.category`.
- Preserve `selector_representation` and `selector_key_id` exactly as
  received in results and audit rows.
- Never resolve a `sha256_salted` selector outside the tenant boundary
  that owns the salt.
- Do not claim live validation unless the connector was exercised
  against a real tenant or reproducible lab environment.

## Subject Families And Scopes

`ResponseActionId` prefixes describe the action family. `ResponseSubject.kind`
describes the broad target surface carried on the wire. The current ABI keeps
the subject scope vocabulary intentionally compact:

| Action family | Subject scope | Common selector types |
| --- | --- | --- |
| `host.*`, `process.*`, `file.*`, `hash.*` | `endpoint` | `agent_id`, `hostname`, `instance_id`, `sha256` |
| `user.*`, `iam.*` | `identity` | `user_principal_name`, `user_id`, `iam_role`, `access_key_id` |
| `ip.*`, `domain.*`, `url.*`, `session.*`, `cert.*` | `network` or `pki` | `ip`, `domain`, `url`, `session_id`, `certificate_id` |
| `email.*` | `mail` | `message_id`, `mailbox`, `sender` |
| `key.*` | `pki` | `key_id`, `key_version` |
| `bucket.*`, `alert.*`, `case.*`, `playbook.*` | `platform` | `bucket_name`, `alert_id`, `case_id`, `playbook_id` |

Connectors MAY narrow the accepted `selector_type` values per action. They
should reject mismatches during `dry_run` with `ConnectorError.category =
policy`.

## Outcome Ownership

`ResponseActionResult` records connector execution. Connectors should return
`success`, `failure`, or `expired`. A failed result must include a
`ConnectorError`; a successful result must not include one.

`pending_approval` and `denied` are runtime/approval-gate outcomes. A provider
runner may surface them in `ResponseActionResult` when it stops before `apply`,
but a vendor connector's `apply` method should not invent those states on its
own.

## PII Doctrine

Identity, email, and IAM actions often target human identifiers. For
those families, `selector_value` should be `sha256_salted` when it
contains PII. The salt is tenant-side and rotatable. Rotating it makes
old hashes effectively non-reversible without mutating historical audit
rows.

Connectors that must call a vendor with a raw identifier should accept a
tenant-local resolver callback, as the Okta reference connector does.
The resolver is an operator concern and should not be embedded in the
public registry or package metadata.

## Approval Boundary

Approval policy is runtime-owned. A connector may expose default approval
metadata through `ConnectorCapability` and action catalog metadata, but
it should not silently bypass an approval decision. Runtimes and agent
wrappers are responsible for turning `ApprovalDescriptor` into an
operator workflow.

## Level 4 Mock-Provider Evidence

Level 4 is the provider-facing conformance claim. It does not require the
Warlog backend. A package or third-party implementation emits a provider
report after exercising a deterministic mock vendor:

```sh
warlog-spec provider-check --out ./provider-report.json
python tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
```

The runner validates the embedded `ConnectorCapability`,
`ResponseActionSpec`, `ResponseActionResult`, and `ConnectorError` against
the public schemas. It also checks that `dry_run` made no vendor mutation,
`apply` succeeded, `verify` observed the vendor state, replaying the same
`idempotency_key` did not create a second mutation, and an unsupported
action was rejected with `policy`.

This is mock-vendor evidence only. A live tenant, vendor sandbox, or
reproducible lab run is a separate Level 5 claim.

## Minimal Templates

- Python: `packages/warlog-spec-py/examples/echo_connector.py`
- TypeScript: `packages/warlog-spec-ts/examples/echo-connector.ts`

Use vendor-realistic examples only after the template is clear:

- Python Okta, CrowdStrike, Palo Alto, Proofpoint, Zscaler, AWS, VirusTotal
- TypeScript Okta and CrowdStrike