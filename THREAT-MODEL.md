# Threat Model

> **Status:** v0.1.0. This document is the source of truth for what
> Warlog Spec protects against, and what it deliberately does not.
> Read it before claiming a flaw. Most "vulnerabilities" in audit-log
> protocols are scope confusions, not protocol failures.

## TL;DR

Warlog Spec is an **audit log primitive** for AI agent actions. It produces
tamper-evident, cross-language-byte-equivalent, append-only signed records
of what an agent attempted, what was decided, and what happened. It is one
primitive in a defense-in-depth stack. It does not prevent bad agent
actions. It does not replace vendor-side audit. It does not defend against
a persistent root attacker on the producing host without an external
witness. Each of these is a deliberate scope decision, documented below
with the threat model that justifies it.

Prior art for the pattern: AWS CloudTrail Log File Integrity Validation
(HMAC chain), Sigstore (signed records of action attestations), Stripe
Ledger (pseudonymization at log time with separate detokenization vault),
Linux auditd (in-kernel append-only audit stream). Warlog Spec is the
projection of this established pattern onto the specific surface of AI
agent tool calls.

## Positioning

Warlog Spec **is**:

- A canonical schema for AI agent action records, approval decisions, and
  agent identity references.
- A cryptographic protocol for chaining those records into a tamper-evident
  stream (HMAC v0.1, asymmetric Ed25519 / RSASSA-PSS in RFC 0004).
- A byte-equivalent canonicalization rule that lets independent
  implementations produce identical signatures from identical inputs.
- A pseudonymization gate definition that hashes PII selectors at audit
  time.

Warlog Spec **is not**:

- An EDR, XDR, runtime sandbox, or memory-hardening tool.
- A network policy engine or egress filter.
- A SOAR or workflow orchestrator.
- A replacement for vendor-side audit (CloudTrail, Okta System Log,
  Falcon, etc.).
- A prevention layer against hallucinated, prompt-injected, or otherwise
  semantically wrong agent actions.

Used in isolation, Warlog Spec answers two questions:

1. *What did the agent attempt, with which model identity, against which
   target, and what was the outcome?*
2. *Can I prove the answer to a third party who does not trust me or my
   vendor?*

It does not answer *"did the agent do the right thing?"* or *"how do I
stop the agent from doing the wrong thing?"*. Other layers of the stack
answer those.

## Assets

The artifacts whose integrity matters:

1. **`SignedAuditRow`** — the canonical record of each agent action.
2. **The HMAC chain (or asymmetric chain in RFC 0004)** — the
   linked-signature property that makes the row stream tamper-evident.
3. **The `ApprovalDecision` artifact** — the record that an action was
   denied, deferred, or granted by a specific principal at a specific
   time.
4. **The `AiAgentRef`** — the binding between an action and the specific
   model, model version, system prompt hash, and tools manifest hash that
   produced it. This is the EU AI Act Article 12 traceability evidence.
5. **The `decision_ref` graph** — the link from each action back to the
   `TriageProposal` / `NextStepProposal` / etc. that authorized it.

## Adversary models

### A1 — Read-only external attacker (post-incident cold log access)

**Capability.** Reads the JSONL audit file or audit DB rows after the
fact, without root on the producing host. Wants to modify or delete a
row to hide their tracks.

**Protected.** Modification of any past row recomputes its
`canonical_bytes_n`, which invalidates `sig_n`, which invalidates every
`sig_{n+k}` for k ≥ 1. `verify_chain(rows, secret)` detects this
deterministically. Deletion of a row creates a gap in the chain that the
verifier detects.

### A2 — Malicious insider with write access but no key access

**Capability.** Can append rows to the JSONL file (or insert into the
audit table) but cannot retrieve the HMAC secret. Wants to forge a row
claiming the agent did or did not perform a given action.

**Protected.** Without the secret, the insider cannot produce a valid
`sig_n` that chains correctly to `sig_{n-1}`. Any forged row fails
`verify_chain` immediately.

### A3 — Persistent root attacker on the producing host

**Capability.** Owns the process. Can read the HMAC secret (or
impersonate the IAM role used to reach KMS), modify any past row,
recompute every subsequent signature, and overwrite the file.

**Not protected by the HMAC chain alone.** This is a fundamental
limitation of any symmetric-key local audit-log system. The mitigations
are external to the chain itself:

- **External witness (mandatory for production).** Export each
  `SignedAuditRow` in near-real-time to an immutable store (S3 Object
  Lock, GCS Bucket Lock, Kafka with infinite retention on a separately-
  owned cluster, a separate audit DB owned by a different principal). A
  root attacker on the producing host cannot rewrite history on the
  external witness. This is exactly the pattern AWS CloudTrail uses : the
  HMAC chain integrity check is the *local* property, the S3 Object Lock
  bucket is the *durable* property.
- **Asymmetric signatures with key rotation (RFC 0004, ratified).** Ed25519
  or RSASSA-PSS signatures, with active signing keys rotated periodically
  and past private keys destroyed. A root attacker who steals the current
  signing key cannot forge past rows : the keys that signed them no
  longer exist anywhere. This gives the equivalent of forward secrecy for
  the audit chain.

An implementation claiming Level 4 (Provider) conformance SHOULD pair the
HMAC chain with at least one of these mitigations. The spec does not
mandate either. The operator's threat model dictates the choice.

### A4 — Hallucinated or prompt-injected agent action

**Capability.** The agent has legitimate API credentials to a vendor
(Okta, CrowdStrike, AWS). A prompt injection or model hallucination
causes it to call `user.disable` on the wrong target.

**Not prevented by Warlog Spec. This is by design.** Warlog Spec records
the call. It does not adjudicate whether the call was "correct".
Prevention of bad agent actions is the responsibility of:

- **The `ApprovalGate` layer.** The `ApprovalGate` Protocol in
  `warlog_spec.integrate` lets operators require human-in-the-loop
  confirmation for destructive action classes. The catalog defines
  `defaultApprovalLevel` per action. Warlog blocks and records the
  denial deterministically.
- **The vendor-side authorization.** Okta, CrowdStrike, etc. enforce
  their own RBAC. Warlog does not bypass it.
- **The agent framework's own safety layers.** Tool allowlists,
  constitutional AI, output filtering, etc.

What Warlog **does** guarantee for A4: if the action was executed, there
is a signed row binding it to the specific model identifier, model
version, prompt hash, and tools manifest hash that produced it. This
satisfies EU AI Act Article 12 (logging requirements) and provides the
attribution evidence for post-incident legal, insurance, and regulatory
response.

The framing matters: **audit is not prevention**. Thirty years of
compliance doctrine (SOX, HIPAA, PCI-DSS, DORA, EU AI Act) rest on this
distinction. An audit log that does not prevent a bad action is not
broken any more than a flight data recorder is broken because it did not
prevent the crash.

### A5 — Compromised vendor API

**Capability.** The vendor (Okta, CrowdStrike) is itself compromised, or
returns false success/error responses.

**Not in scope.** Warlog records what the agent attempted and what
response was received. If the vendor lies, Warlog records the lie
faithfully. Mitigation is vendor diversity, vendor-side audit
cross-checking in your SIEM, and the operator's incident response.

### A6 — Time-tampering attacker

**Capability.** Root on the host. Manipulates the system clock between
two audit row writes to backdate or forward-date entries.

**Partially protected.** Each row carries `started_at` / `completed_at`
as UTC wall-clock timestamps. The reference Python integration also
tracks `time.monotonic_ns()` internally between consecutive row writes ;
if wall-clock progress and monotonic-clock progress diverge beyond the
configured tolerance, it emits a warning. The monotonic reading is not
part of the public `AuditRow` wire format. It is not a hard failure :
legitimate NTP adjustment on VMs, VM migration events, and Windows
datetime resolution quirks produce the same signal.

The drift detection is defense-in-depth, not a primary guarantee. The
primary protection against backdated audit rows is the **external
witness** (A3 mitigation): the witness records its own receive
timestamp, which the producing host cannot manipulate.

The drift signal is operationally useful for: forensic post-mortem
("was there clock-skew at this time?"), correlation with NTP daemon
logs, detection of VM migration windows.

It does **not** detect long-gap manipulation. If the agent writes row N
at T, then writes nothing for 4 hours, then writes row N+1, the drift
detector sees only the cumulative delta and cannot distinguish a
legitimate gap from a tampered one. The external witness defeats this
attack because it records its own receive timestamps independently.

### A7 — Framework-induced context loss (async / threadpool / subprocess)

**Capability.** Not adversarial. The agent framework (LangChain, CrewAI,
Autogen, etc.) spawns workers in ways that drop the Python `contextvars`
context or Node `AsyncLocalStorage`, causing decorator-based audit
(Pattern A) to lose the `agent_run`, `AiAgentRef`, and chain state.

**Mitigated, not eliminated, in Pattern A.** The Python integration
ships `propagate_warlog_context`, which snapshots the context at wrap
time and re-applies it inside the worker. It handles `ThreadPoolExecutor`.
It does not handle `ProcessPoolExecutor` (processes do not share Python
memory), Celery workers, or arbitrary `subprocess` spawning.

**Eliminated in Pattern C (`@warlog/mcp-proxy`).** The MCP proxy
intercepts `tools/call` messages at the stdio boundary of the MCP server,
outside the agent process entirely. No in-process context propagation
is required. Operators with complex distributed agent topologies SHOULD
use Pattern C, accepting the constraint that the agent must speak MCP.

This is a **scope tradeoff**, not a flaw. Pattern A optimizes for the
three-line-integration developer experience that brings the audit
primitive into reach for a junior Python or Node developer. Pattern C
optimizes for out-of-process robustness in any-language agent stacks.
The spec covers both, and the integrator chooses the pattern that
matches their topology.

### A8 — In-memory PII exfiltration before pseudonymization

**Capability.** Root attacker dumps process memory between the moment
the agent constructs `disable_user("alice@corp.com")` and the moment the
connector serializes the API request.

**Not protected.** Warlog's GDPR pseudonymization gate hashes selectors
before they reach the **audit row**. It does not hash them before they
reach the **vendor API**: the vendor needs the cleartext value to act.
During this window, the cleartext PII is in process memory.

This is true of every system that calls an external API with a
human-readable identifier. The mitigations are external:

- **Process memory hardening.** Containers, seccomp, ASLR, restricted
  `ptrace` access, gVisor / Firecracker isolation.
- **Key escrow for re-identification.** The salt for SHA256_SALTED
  pseudonyms is held in a separate vault with auditable read access. A
  forensic analyst with proper legal authority reverses the
  pseudonymization via the vault. The audit chain remains anonymous to
  any party without vault access.
- **Vendor-side tokenization where supported.** Where the vendor exposes
  opaque user IDs instead of email addresses (e.g., Okta user IDs,
  Stripe tokens, AWS principal IDs), pass those instead of cleartext.
  The connector layer is the appropriate place to enforce this.

Warlog provides the pseudonymization primitive. The full GDPR + forensic
architecture is the integrator's responsibility, with these patterns
documented as recommendations.

### A9 — Replay or reordering of audit rows

**Capability.** Attacker captures legitimate rows and replays them in a
different order, duplicates them, or splices them into a chain from a
different `agent_run`.

**Protected against reordering and splicing.** The HMAC chain encodes
the linear sequence via `prev_sig`. The `agent_run_id` field in
`AiAgentRef` binds each row to a specific run. Reordering breaks the
chain. Splicing from another run produces a row whose `prev_sig` does
not match the chain it is inserted into.

**Replay** of an exact full chain segment from row N to row M is
detectable at the **witness layer** (A3 mitigation), which records its
own monotonic receive timestamp and rejects duplicate ranges. Without an
external witness, an attacker with full write access can in principle
replay a chain segment. This is the same threat model as A3.

## Properties guaranteed (cumulative)

Given a spec-conformant implementation paired with an external witness:

1. **Append-only** at the witness layer.
2. **Tamper-evident** : any modification of a past row is detected by
   `verify_chain`.
3. **Non-repudiation of the agent's action** : each row binds the action
   to a specific model identity, prompt hash, and tool manifest hash.
4. **Cross-implementation reproducibility** : two independent
   implementations of the spec (Python `warlog-spec`, TypeScript
   `@warlog/spec`) produce byte-equivalent canonical bytes for the same
   row. A third-party auditor with the spec text alone can reproduce
   signatures without trusting either implementation.
5. **EU AI Act Article 12 conformance pattern** : every agent action is
   logged with the system that produced it.
6. **GDPR Article 30 + Article 17 conformance pattern** : pseudonymization
   at log time, optional salt destruction or vault rotation for
   right-to-be-forgotten, with documented re-identification vault
   pattern for legitimate forensic access.

## Properties NOT guaranteed

Explicit non-goals. If you need any of these, pair Warlog Spec with a
separate system that provides them:

1. **Prevention of unauthorized agent actions.** Use vendor-side RBAC,
   network egress filtering, and the Warlog `ApprovalGate` for destructive
   action classes.
2. **Protection against a persistent root attacker on the producing host
   without an external witness.** Use S3 Object Lock or equivalent.
3. **Forward secrecy with the v0.1 symmetric HMAC profile.** Use the
   RFC 0004 asymmetric profile with key rotation and past-key destruction.
4. **Protection against in-memory PII exfiltration before the API call.**
   Use process memory hardening and vendor-side tokenization.
5. **Protection against the vendor lying about the response.** Use
   vendor diversity and cross-vendor correlation in your SIEM.
6. **Replacement of vendor-side audit (CloudTrail, Okta System Log,
   Falcon).** Warlog records the agent's intent and cognitive context ;
   the vendor records its own execution. Both are necessary. Neither
   replaces the other.
7. **Real-time prevention of hallucinated agent actions.** The
   `ApprovalGate` blocks specific action classes by policy ; it does not
   detect semantic incorrectness of well-formed requests.

## Operating recommendations

For a production deployment claiming Level 4 (Provider) conformance:

1. **Pair the local JSONL audit file with an external witness.** Ship
   each row to S3 Object Lock (or GCS Bucket Lock, or a Kafka topic on a
   separately-owned cluster) within seconds of write. Run periodic
   `verify_chain` on the witness copy. This is the single most important
   operational control. Without it, A3 is not mitigated.
2. **Configure `ApprovalGate` for the destructive action classes.** The
   action catalog ships with `defaultApprovalLevel` per action.
   Operators should treat any action with `defaultApprovalLevel >= L3`
   as approval-required by default in production.
3. **Use the asymmetric profile (RFC 0004) for new deployments.** The
   v0.1 HMAC profile is for backward compatibility and small-scale
   pilots. Production should target Ed25519 with key rotation.
4. **Pair Pattern A with `propagate_warlog_context`** if you use
   `ThreadPoolExecutor`. Use **Pattern C** (MCP proxy) if your agent
   topology involves processes, Celery, or untrusted third-party tool
   code that the agent invokes.
5. **Run the audit producer under seccomp and restricted `ptrace`** to
   reduce A8 (in-memory PII) exposure.
6. **Hold pseudonymization salts in a separate vault** with audit on
   read access. Define a retention policy aligned with your forensic
   investigation timeline (90 days minimum is a defensible baseline) and
   your GDPR right-to-be-forgotten SLA (typically 30 days).
7. **Do NOT use `logrotate copytruncate` on the JSONL file.** It has a
   race-condition window between the copy and the truncate that can
   lose rows and break the chain. Use a shipping daemon (Vector, Fluent
   Bit, rsyslog with the reliable forwarding protocol) that tails the
   file and ships externally. Rotate the local file with `logrotate
   create` + `SIGHUP`-driven file reopening, or simply size-based
   rotation by the application itself.

## Scope of the spec vs. scope of the implementation

The spec defines:

- The canonical schemas for audit rows, approval decisions, AI agent
  refs, and the rest of the artifact catalog.
- The HMAC chain construction (v0.1) and the asymmetric signature scheme
  (RFC 0004).
- The canonicalization rules that produce cross-implementation
  byte-equivalence.
- The pseudonymization gate semantics.

The spec does **not** define:

- The persister backend (file, DB, message queue — implementation choice).
- The external witness mechanism (S3 Object Lock, Kafka, ledger DB,
  separate WORM appliance — implementation choice).
- The key management mechanism (in-memory secret, environment variable,
  AWS KMS, HashiCorp Vault, hardware HSM — implementation choice).
- The agent framework integration (decorator, MCP proxy, sidecar —
  two patterns shipped as reference, more possible).

This separation is deliberate. The spec is the **contract**. Operators
choose the implementation appropriate to their threat model and
operational constraints. A standard that mandates a specific
implementation locks out the operators whose constraints differ. We do
not want to be that standard.

## Reporting a real vulnerability

If you find a flaw not covered by this document, please follow the
disclosure process in the parent project's `SECURITY.md`. We will
update this threat model with confirmed findings and credit the reporter.

Out-of-scope criticisms — *"the HMAC chain doesn't prevent root
attackers"*, *"the agent can hallucinate"*, *"the vendor could lie"* —
will be referenced back to this document. We do not claim to defend
against threats this document explicitly lists as not covered. A
standard that pretends to defend against every threat in the universe
defends against none of them rigorously.
