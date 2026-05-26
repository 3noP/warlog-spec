# warlog-spec — Python reference package

**Version**: `0.1.0` — first public release (experimental, pre-v1.0). Install with `pip install warlog-spec`.
**License**: Apache 2.0

The Python reference implementation of [Warlog Spec][spec] — the
canonical workflow contract for Security Operations. This package is
what you import when you build something that conforms to the spec :
a connector, a verifier, a third-party integration, a pack publisher.

Warlog Spec is the layer above OCSF. OCSF answers *"what happened?"*
(events, findings, indicators). Warlog Spec answers *"what do we do
about it?"* — typed proposals, response actions, signed audit chains,
pack manifests for distribution.

## What's inside

```
warlog_spec/
├── enums           12 canonical workflow enums (severity, status, verdict,
│                   source, category, priority, entity-type/role, IOC type)
├── provider_abi    ConnectorCapability, ResponseAction*, AuditRow,
│                   ConnectorError — the typed ABI for response actions
│                   (49 ResponseActionId values across 8 families:
│                   identity, device, network, email, iam, key, storage,
│                   workflow)
├── action_catalog  ACTION_CATALOG registry — per-action metadata
│                   (reversibility, default approval level, default
│                   reviewers, params_schema_ref). Single source of truth
│                   that drives runtime approval defaults. Helpers
│                   `actions_by_family`, `actions_by_reversibility`,
│                   `default_approval_for`, `load_params_schema`,
│                   `validate_params`, `to_json_manifest`.
├── artifacts       Read-side data canon — `ArtifactEnvelope` (the
│                   unified envelope every read-side artifact rides in),
│                   provenance/confidence/citation primitives, subject
│                   types `NormalizedEntity` and `ExtractedIOC`, and
│                   composed assessment shapes (`MitreAssessment`,
│                   `EnrichmentAssessment`). The contract for what an
│                   enricher PRODUCES — verb-less by design.
├── pack_manifest   PackManifest — distribution layer for detection rules,
│                   playbooks, KB articles, connectors
├── abi             AbiConnector ABC — the interface a connector implements
├── audit_chain     HMAC crypto primitives (canonicalize_v1, compute_signature,
│                   compute_genesis) for verifying audit chains
└── _schemas/       Bundled per-action JSON Schemas resolved via
    action-params/  importlib.resources at runtime (host.collect_artifacts,
                    user.group_remove, session.terminate, iam.role_detach,
                    iam.credentials_disable, key.schedule_deletion).
```

You'll typically import a handful of types :

```python
from warlog_spec import (
    AbiConnector,
    ConnectorAbiError,
    ConnectorCapability,
    ResponseActionId,
    ResponseActionSpec,
    ResponseActionResult,
    ExecutionOutcome,
    FailureCategory,
)
```

## Add audit to your AI agent in 3 lines

If you already have an AI agent making tool calls, the fastest path to a
trust-layer-compliant audit chain is the `@audited` decorator. It builds
and signs an `AuditRow` per call, pseudonymizes PII selectors per the
GDPR doctrine, and links every row by HMAC. Zero changes to your tool
logic.

```python
import os, uuid, hashlib
from warlog_spec import AiAgentRef, ComplianceScope, ResponseActionId
from warlog_spec.integrate import WarlogClient, agent_run, audited

# 1. One client per process, reads WARLOG_* env vars or build directly.
client = WarlogClient.from_env()

# 2. Decorate any tool — the decorator does everything else.
@audited(
    client=client,
    action_id=ResponseActionId.USER_REVOKE_TOKENS,
    subject_arg="user_email",
    compliance_scope=[ComplianceScope.GDPR, ComplianceScope.NIS2],
)
async def revoke_user_tokens(user_email: str) -> dict:
    """Revoke a user's active OAuth tokens following a fraud signal."""
    return await okta_client.users.sessions.delete(user_email)

# 3. Wrap an agent run with the AI Act traceability anchor — once per
#    incident / decision-cycle. Every @audited call inside picks the
#    actor/trigger from the ambient context.
async def handle_alert(alert):
    agent = AiAgentRef(
        model="claude-opus-4-7",
        model_version="2026-05-01",
        system_prompt_hash=hashlib.sha256(SYSTEM_PROMPT).hexdigest(),
        agent_run_id=str(uuid.uuid4()),
    )
    async with agent_run(
        client, agent=agent,
        actor_id="playbook.fraud_triage",
        alert_id=alert.id,
        alert_payload=alert.raw_bytes,
        compliance_scope=[ComplianceScope.GDPR],
    ):
        await revoke_user_tokens(user_email=alert.target_email)
```

The minimum env to set :

```sh
export WARLOG_TENANT_ID=acme-eu
export WARLOG_HMAC_SECRET=...      # HSM/KMS managed in prod
export WARLOG_PII_SALT=...         # rotatable salt for SHA256_SALTED pseudonyms
export WARLOG_AUDIT_LOG=./warlog-audit.jsonl
```

The decorator emits two signed `AuditRow`s per call (`dry_run` then
`apply`), chained by HMAC. If the wrapped function raises, the second
row records `outcome=failure` and the exception propagates unchanged.
On process restart, the JSONL persister recovers the last signature so
the chain has no phantom break.

### Block destructive actions with an approval gate

By default the decorator only audits. To turn it into an **active
shield** that intercepts and blocks destructive actions before they
hit the vendor, inject an `ApprovalGate` into the `WarlogClient` :

```python
from warlog_spec.integrate import (
    ApprovalDecision, ApprovalGate, ApprovalRequest, ApprovalRequired,
    WarlogClient, audited,
)

class SeniorOnlyForDestructive(ApprovalGate):
    """Block DESTRUCTIVE actions until a senior operator signs off."""
    def __init__(self, pending_store):
        self._store = pending_store  # SQLite / Redis / in-memory dict

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        if req.default_approval_level.value in ("senior", "manager"):
            # Persist a pending request your UI / Slack bot can resolve.
            request_id = self._store.create_pending(req)
            return ApprovalDecision(
                state="pending",
                rationale=f"{req.default_approval_level.value} approval required",
                request_id=request_id,
            )
        return ApprovalDecision(state="approved", rationale="auto policy")

client = WarlogClient(
    tenant_id="acme-eu",
    hmac_secret=hsm.get_secret("warlog-hmac-v3"),
    pii_salt=hsm.get_secret("warlog-salt-v3"),
    persister=JsonlFilePersister("/var/log/warlog/audit.jsonl"),
    approval_gate=SeniorOnlyForDestructive(pending_store=my_store),
)
```

Now the agent loop catches the typed exception and suspends :

```python
try:
    await revoke_user_tokens(user_email="alice@acme.example")
except ApprovalRequired as exc:
    # Decorator emitted a PENDING_APPROVAL row already.
    # Notify the operator, suspend the task, exit gracefully.
    await slack.notify(f"approval needed: {exc.request_id} "
                       f"(audit_id={exc.audit_id})")
    return SuspendForApproval(request_id=exc.request_id)
except ApprovalDenied as exc:
    # Decorator emitted a DENIED row. Action permanently refused
    # for this idempotency_key.
    raise PermanentlyRefused(reason=exc.rationale) from exc
```

When the operator resolves the pending request out-of-band, your code
re-invokes the same decorated function with the same arguments — the
decorator's deterministic `idempotency_key` ensures the gate sees the
same request and returns the now-resolved decision.

Doctrine : the gate is on the critical path of every audited call.
Keep it fast (< 10 ms). For HTTP-backed approval systems, front them
with an in-memory cache. The decorator emits the `APPROVAL` audit row
*after* the gate decides — even a denial leaves a signed,
cryptographically-linked record an auditor can inspect.

### Operating notes

- **Async gates are not supported.** ``ApprovalGate.request`` is
  synchronous by design. If you accidentally pass an ``async def
  request`` gate, the decorator detects the returned coroutine and
  raises a typed ``TypeError`` with a remediation hint — no obscure
  ``AttributeError`` on a coroutine downstream.

- **HMAC secret can be ephemeral (HSM / Vault / KMS pattern).** For
  ANSSI / OIV / classified deployments where a long-lived secret in
  process memory is unacceptable, pass a ``Callable[[], bytes]`` as
  ``hmac_secret``. The provider is invoked per signed row ; the bytes
  go out of scope at the end of the signing block. An RCE on the
  process at instant T only catches the secret bytes that were live
  during one signing operation, not the whole chain :

      def fetch_from_vault() -> bytes:
          # Talk to Vault Agent / AWS KMS / HashiCorp Vault over a
          # Unix socket. Return short-lived bytes that go out of scope.
          return vault_client.read_secret("warlog-hmac-v3")

      client = WarlogClient(
          tenant_id="acme-eu",
          hmac_secret=fetch_from_vault,  # callable, not bytes
          pii_salt=fetch_pii_salt(),     # same pattern for the salt
          persister=JsonlFilePersister("/var/log/warlog/audit.jsonl"),
      )

  Sub-millisecond Vault round-trips matter — the gate is on the hot
  path of every audited tool call.

- **Clock-drift detection.** The decorator emits a ``RuntimeWarning``
  if the wall clock and the monotonic clock diverge between two
  audit rows (NTP step, VM hypervisor freeze, manual operator
  adjustment). The HMAC chain stays cryptographically valid — the
  signature commits to the wall-clock timestamp regardless — but
  forensic ordering becomes suspect when the clock jumps. Set the
  tolerance via ``WarlogClient(clock_drift_tolerance_s=...)``
  (default 1.0 s). For real prevention, run a strict NTP daemon
  (``chronyd``, ``systemd-timesyncd``) on the host and configure it
  to alert / fail on a drift threshold tighter than the default.

- **Context propagation across async boundaries — read this carefully.**
  The ``@audited`` decorator relies on Python's ``contextvars`` to bind
  each call to its ``agent_run``, ``AiAgentRef``, and HMAC chain state.
  Different boundary types behave very differently :

  | Boundary | Propagates ? | What to do |
  |---|---|---|
  | ``await coro()`` in same task | yes (native) | nothing |
  | ``asyncio.to_thread`` / ``loop.run_in_executor`` | yes (stdlib copies context) | nothing |
  | Raw ``ThreadPoolExecutor.submit(fn, ...)`` | **no** | wrap with ``propagate_warlog_context`` |
  | ``ProcessPoolExecutor`` | **no, and no fix** | use Pattern C (MCP proxy) instead |
  | Celery / RQ / Dramatiq workers | **no, and no fix** | use Pattern C |
  | ``subprocess.Popen`` / ``multiprocessing.Process`` | **no, and no fix** | use Pattern C |
  | LangChain ``AsyncIteratorCallbackHandler`` token streams | depends on framework version | test, then either wrap or switch to Pattern C |

  For the raw ``ThreadPoolExecutor`` case, the wrapper is :

      from warlog_spec.integrate import propagate_warlog_context

      with agent_run(client, agent=...):
          wrapped = propagate_warlog_context(my_audited_tool)
          future = pool.submit(wrapped, "alice@acme.example")

  The helper snapshots the current context at the moment you call it
  (i.e. inside the ``agent_run`` block) and replays it inside the
  worker thread before invoking the audited function.

  For the cross-process cases (process pools, Celery, subprocess),
  there is no in-process fix : Python contextvars do not cross process
  boundaries. The robust pattern is **Pattern C : the ``@warlog/mcp-proxy``
  out-of-process interceptor.** The MCP proxy sits at the stdio boundary
  of an MCP server and signs every ``tools/call`` regardless of how the
  caller is structured internally. If your agent topology involves any
  of the "no, and no fix" rows above, default to Pattern C and accept
  the constraint that your agent must speak MCP. See
  ``packages/warlog-mcp-proxy/`` and ``THREAT-MODEL.md`` adversary A7
  for the full reasoning.

- **Non-serializable arguments.** The decorator's deterministic
  ``DecisionRef`` and ``idempotency_key`` survive arbitrary argument
  types — anything not JSON-serializable falls back to ``repr(value)``
  in the canonical hash. Your tools can take ``Path``, dataframes,
  API clients, custom objects ; the audit row will still be signed.

- **Chain truncation is an intrinsic limitation.** The HMAC chain is
  hash-linked forward — every row commits to the row before it, but
  no row commits to the row AFTER. An attacker who can write to the
  audit log file can delete the trailing N rows : when the process
  restarts, ``JsonlFilePersister.head_signature()`` reads the new
  last row and chains forward from there. The remaining (truncated)
  chain still verifies cryptographically — the deleted rows leave no
  trace because their hashes never reach the persister's head cache.

  This is a known limitation of any local-only audit chain. Two
  practical defenses :

  1. **Forward each row to a remote append-only sink in real-time.**
     Pipe ``audit.jsonl`` to ``rsyslog`` over TLS, Kafka, a SaaS
     append-only API, or an AWS S3 bucket with object-lock enabled.
     The remote observer has its own copy ; a local-only attacker
     can't redact what the observer already received. The Warlog
     spec is on-purpose agnostic about transport, so any one-way
     forwarder works.

  2. **Run anchors per agent_run (planned for v0.2).** A v0.2 RFC
     will define a CLEANUP-phase ``AuditRow`` emitted at
     ``agent_run`` exit, committing to the number of rows the run
     emitted. A truncation that removes the anchor surfaces as
     "agent_run started but never closed" ; a truncation that removes
     intra-run rows surfaces as "row count mismatch". Not in v0.1
     because it requires a schema additive change to ``ResponseActionId``
     (a ``run.complete`` canonical action) that we want to ratify by
     RFC.

  In v0.1, do (1).

- **Disk exhaustion is the operator's responsibility.** ``JsonlFilePersister``
  appends forever — there is no built-in rotation. An agent in a
  reasoning loop can fill a disk in minutes. The library refuses to
  fail silently (``appendFileSync``'s ``ENOSPC`` propagates as a real
  error and your tool call fails loud), but the agent stops too. Two
  mitigations are available out of the box, neither shipped in the
  package itself :

  1. **Ship to an external sink continuously, then rotate the local
     file safely.** This is the production-grade pattern and the one
     `THREAT-MODEL.md` (adversary A3) treats as mandatory. A log-shipper
     (Vector, Fluent Bit, rsyslog with the reliable forwarding protocol)
     tails ``audit.jsonl`` and forwards each line to your external
     witness (S3 Object Lock, Kafka, a separately-owned SIEM). Once each
     row is durably shipped, the local file is fair game for rotation
     via the ``create`` pattern :

         /var/log/warlog/audit.jsonl {
             daily
             rotate 7
             compress
             missingok
             notifempty
             create 0640 warlog warlog
             postrotate
                 systemctl kill -s HUP warlog-agent.service
             endscript
         }

     The agent catches ``SIGHUP`` and reopens its handle to the new
     file. The chain's ``head_signature`` is re-loaded from the last
     externally-witnessed row, not from the local file, so a rotation
     does not break the chain. The local file is now a buffer between
     the producer and the shipper, not the source of truth.

     **Do NOT use `copytruncate`.** It has a race-condition window
     between the copy and the truncate where rows can be lost. For a
     chain-based audit log, a lost row breaks every subsequent
     signature. See `THREAT-MODEL.md` adversary A3 and operating
     recommendation #7.

  2. **Custom database-backed persister.** Implement ``AuditPersister``
     against a database with TTL retention (SQLite + scheduled purge,
     PostgreSQL + ``DELETE WHERE ts < now() - interval '90d'``, etc.).
     The chain stays cryptographically intact as long as your purge
     deletes from the OLD end of the chain — never the head — and as
     long as you maintain the external witness invariant (a copy of
     each row lives somewhere the local DB attacker cannot rewrite).

  Either way, the operator MUST set up monitoring on disk usage. Tools
  like Datadog / Prometheus / a simple cron + ``df -h /var/log/warlog``
  catch the issue before the agent dies.

## Build a connector in 50 lines

A working connector is small. See [`examples/echo_connector.py`](examples/echo_connector.py) for the full
runnable file. The shape :

```python
from warlog_spec import (
    AbiConnector, ConnectorCapability, ConnectorAuthModel, ConnectorKind,
    AuthDescriptor, EgressDescriptor, ConnectorCompat,
    ResponseActionId, ResponseActionSpec, ResponseActionResult, ExecutionOutcome,
)

class EchoConnector(AbiConnector):
    capability = ConnectorCapability(
        connector_id="echo",
        connector_version="0.1.0",
        vendor="Echo Test",
        kind=ConnectorKind.OTHER,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY, scopes=[]),
        egress=EgressDescriptor(
            supports_response_actions=[ResponseActionId.ALERT_ACKNOWLEDGE]
        ),
        compat=ConnectorCompat(warlog_spec_min="1.0", warlog_spec_max="1.0"),
    )

    async def authenticate(self) -> None: ...
    async def dry_run(self, spec: ResponseActionSpec) -> None: ...
    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        # Your real vendor call goes here. Forward spec.idempotency_key
        # to the upstream API to dedupe duplicate apply attempts.
        return ResponseActionResult(
            execution_id="",  # the runtime stamps it
            action_id=spec.action_id,
            outcome=ExecutionOutcome.SUCCESS,
            subject=spec.subject,
        )
    async def verify(self, spec, result) -> bool: return True
```

A Warlog runtime — or any compatible orchestrator — instantiates your
connector and calls the four lifecycle methods. The runtime handles
audit chain, approval gate, idempotency cache, outbox emission of
`capability.executed`. Your connector handles the **vendor-specific**
work (HTTP calls, error categorization, idempotency token forwarding).

## OCSF Detection Finding mapper

The package includes a conservative inbound mapper for OCSF Detection
Finding events:

```python
from warlog_spec import map_ocsf_detection_finding

mapped = map_ocsf_detection_finding(ocsf_event)
assert mapped.trigger_signal.kind == "ocsf_event"
print(mapped.classification.classification.severity)
```

It emits existing public shapes only: `TriggerSignalRef`,
`ClassificationAssessment`, `EnrichmentAssessment`, and optional
`MitreAssessment` from OCSF `attacks[]`. The original OCSF payload is
hashed with stable sorted-key JSON and referenced by `TriggerSignalRef`;
raw ingestion, alert persistence, deduplication, and routing remain the
operator/runtime's responsibility.

## Level 4 mock-provider check

The package can emit a deterministic Provider ABI evidence report without
importing the Warlog backend:

```sh
warlog-spec provider-check --out ./provider-report.json
python ../../warlog-spec/tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
```

The check exercises `authenticate -> dry_run -> apply -> verify` against
`MockResponseVendor`, confirms `dry_run` has no side effect, verifies
idempotent replay of the same `idempotency_key`, and proves unsupported
actions are rejected with `policy`. It is Level 4 mock-vendor evidence,
not Level 5 live-tenant validation.

## Reference vendor connectors

Real connectors against real vendor APIs, written from public docs.
These live under [`examples/`](examples/) as copy-paste-ready templates
and are how we drive adoption — every entry is verifiable against the
vendor's published REST contract, not against a mock.

| File | Vendor | Actions covered | Auth model |
| --- | --- | --- | --- |
| `echo_connector.py` | (none — in-memory) | `alert.acknowledge` | API key |
| `okta_user_response_connector.py` | Okta | `user.disable`, `user.reset_mfa`, `user.force_logout`, `user.revoke_tokens`, `user.reset_password`, `user.expire_password`, `user.unlock`, `user.group_remove`, `user.delete` | API key (SSWS) |
| `crowdstrike_falcon_connector.py` | CrowdStrike Falcon | `host.isolate`, `host.unisolate`, `host.restart`, `host.collect_artifacts`, `ip.block`, `ip.unblock`, `domain.block`, `domain.unblock`, `url.block`, `url.unblock`, `hash.block`, `hash.unblock` | OAuth2 client credentials |
| `palo_alto_panos_connector.py` | Palo Alto Networks (PAN-OS) | `ip.block`, `ip.unblock`, `domain.block`, `domain.unblock`, `url.block`, `url.unblock`, `session.terminate` | API key (X-PAN-Key) |
| `zscaler_zia_connector.py` | Zscaler (ZIA + ZPA + Sandbox) | `url.block`, `url.unblock`, `domain.block`, `domain.unblock`, `hash.block`, `hash.unblock`, `session.terminate` | API key (obfuscated) |
| `proofpoint_connector.py` | Proofpoint (TAP + TRAP) | `email.quarantine`, `email.recall`, `email.release`, `email.block_sender`, `email.unblock_sender` | API key (Basic auth + Bearer) |
| `aws_response_connector.py` | Amazon Web Services (IAM + KMS + S3 + EC2) | `host.stop`/`host.start`/`host.delete`, `iam.role_detach`/`iam.role_attach`, `iam.credentials_disable`/`iam.credentials_enable`/`iam.credentials_rotate`, `key.disable`/`key.enable`/`key.rotate`/`key.schedule_deletion`, `bucket.lockdown`/`bucket.unlock` | AWS credential chain (boto3) |
| `virustotal_enricher.py` | VirusTotal v3 (read-side enricher) | produces `enrichment.ioc_reputation` for `ip` / `domain` / `url` / `hash_md5` / `hash_sha1` / `hash_sha256` | API key (`x-apikey` header) |

Each new vendor connector doubles as a canon audit. The current
catalog reflects two completed audits :

- **Identity** ([`08-identity-gap-audit.md`](../../docs/canon-migration/08-identity-gap-audit.md))
  — Okta-driven, identity family went from 3 to 9 actions (added
  `revoke_tokens`, `reset_password`, `expire_password`, `unlock`,
  `group_remove`, `delete`).
- **Device** ([`09-device-gap-audit.md`](../../docs/canon-migration/09-device-gap-audit.md))
  — CrowdStrike Falcon-driven, device family extended with
  `host.restart`, `host.collect_artifacts`, `hash.block`.
- **Network** ([`11-network-gap-audit.md`](../../docs/canon-migration/11-network-gap-audit.md))
  — Palo Alto PAN-OS-driven, network family extended with
  `ip.unblock`, `domain.unblock`, `url.unblock`, `hash.unblock`,
  and `session.terminate` (covers TCP/UDP flow + GlobalProtect VPN
  via `params['session_type']`).
- **Email** ([`12-email-gap-audit.md`](../../docs/canon-migration/12-email-gap-audit.md))
  — Proofpoint-driven, email family extended with
  `email.block_sender`, `email.unblock_sender`, `email.release`.
- **Zscaler audit (negative result)** ([`13-zscaler-no-extension.md`](../../docs/canon-migration/13-zscaler-no-extension.md))
  — ZIA + ZPA + Sandbox map cleanly onto existing canon ; ZPA app
  sessions covered by `session.terminate` w/ `params['session_type']='ztna'`.
  No new actions added. Negative results are evidence the canon is
  well-shaped.
- **Cloud** ([`15-cloud-gap-audit.md`](../../docs/canon-migration/15-cloud-gap-audit.md))
  — AWS-driven, cross-validated against Azure + GCP. Three new
  families : `iam` (`role_detach`, `credentials_disable`,
  `credentials_rotate`), `key` (`disable`, `rotate`, `schedule_deletion`),
  `storage` (`bucket.lockdown`). Device family extended with
  `host.stop` / `host.delete`. Catalog 35 → 44 actions.
- **Doctrine refinement** ([`16-doctrine-refinement.md`](../../docs/canon-migration/16-doctrine-refinement.md))
  — sharpens `DISRUPTIVE` definition (vendor-side reversal, not
  canon-inverse-presence), ships five inverse actions for symmetry
  (`host.start`, `iam.role_attach`, `iam.credentials_enable`,
  `key.enable`, `bucket.unlock`), reclassifies `key.rotate` to
  REVERSIBLE (cloud KMS is version-add, old data stays decryptable).
  Materially fixes the AWS connector's `key.rotate` and
  `iam.credentials_rotate` semantics. Catalog 44 → 49 actions.

Standards alignment is documented in
[`10-prior-art-mapping.md`](../../docs/canon-migration/10-prior-art-mapping.md) :
how Warlog Spec sits relative to OCSF (event schema, we consume),
STIX 2.1 (descriptive, we import), CACAO (playbook, calls us),
OpenC2 (wire protocol, we publish a mapping table for interop).
Same gap-audit template applies to the next vendor families
(Palo Alto network → Zscaler cloud SSE → Proofpoint email →
Azure/AWS cloud).

**Runtime-test status :** the vendor connectors are spec-conformant
and written against each vendor's published REST contract. They have
NOT been exercised against live tenants in this repository's CI yet —
each file's docstring is honest about that. PRs from anyone running
them against a live tenant are welcome and will move the connector
from "reference" to "validated".

The roadmap is to extend this catalog with one connector per common
SOC vendor class (SIEM ingest, IAM, mail security, network, ticketing).
The 49-action canonical catalog in `warlog_spec.action_catalog` is the
source of truth for which response primitives a connector can advertise.

## Verify your conformance

```sh
pip install warlog-spec[verify]
warlog-spec dump --out ./fixtures
python warlog-spec/tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
```

The `dump` subcommand writes one fixture per productible type in the
layout expected by the public conformance runner. `python -m
warlog_spec.conformance dump --out ./fixtures` is equivalent when you
prefer module execution.

## Crypto path : verify a Warlog audit chain

If you operate a Warlog deployment and want a third-party auditor to
verify the connector audit chain end-to-end without trusting our
runtime, use the standalone verifier :

```sh
warlog-verify ./audit.jsonl --secret-file ./secret.bin
# OK : 1247 rows, chain valid, no gaps, no tampering
```

The verifier accepts newline-delimited `JsonlFilePersister` records or
public `SignedAuditRow` objects. The secret file is read as raw bytes;
do not add a trailing newline unless that newline is part of the signing
secret.

For custom verifier integrations, the crypto path is also fully exposed :

```python
from warlog_spec.audit_chain import (
    canonicalize_v1, compute_signature, compute_genesis, AuditChainBroken,
)

# Walk the rows you exported from connector_audit_chain table,
# ordered by chain_seq. For each row :
expected_prev = compute_genesis(tenant_id, secret)
for row in rows_in_order:
    if row.prev_hash != expected_prev:
        raise AuditChainBroken(f"break at audit_id={row.audit_id}")
    recomputed = compute_signature(expected_prev, row.canonical_bytes, secret)
    if recomputed != row.signature:
        raise AuditChainBroken(f"signature drift at audit_id={row.audit_id}")
    expected_prev = row.signature
```

Note : the `canonical_bytes` you feed into `compute_signature` are the
bytes that were stored at write time — the spec persists them
explicitly so verification cannot be invalidated by Pydantic schema
evolution (see the spec doc on canonicalization-format versioning).

## Why this package exists

A spec without an installable, importable, working reference
implementation is a slide deck. This package is the line between
"thesis" and "standard" : you can `pip install warlog-spec`
today and write a connector against it. A second independent
implementation in TypeScript ([`@warlog/spec`](https://www.npmjs.com/package/@warlog/spec))
ships at the same version and produces byte-equivalent canonical
output — verified by a pinned golden test on both sides. A Go
implementation is on the roadmap once the spec reaches v1.0 stable.

## Versioning

The package versions independently of the ABI version. ABI version is
declared by `warlog_spec.ABI_VERSION` (currently `"1.0"`) and is the
authoritative compatibility surface ; the package version (`0.1.0`)
reflects implementation maturity of the Python reference. A connector
advertises which ABI range it supports via `ConnectorCompat`. See
[`CHANGELOG.md`](CHANGELOG.md) for the per-release history.

## License

Apache 2.0. The reference implementation libraries (this package)
follow Apache 2.0 to enable embedding in third-party connectors of
any license. The Warlog runtime that consumes this package follows
its own AGPL3 + commercial dual model.

[spec]: ../../warlog-spec/
