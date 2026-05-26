# Ecosystem positioning

Where Warlog Spec sits relative to existing security standards. The
short answer : **we consume, we translate, we extend — we do not
replace**. The audit chain + decision artifacts (the trust layer) is
the only surface we believe is new ; everything else is meant to
interoperate with what your stack already speaks.

## Summary table

| Standard | What it does | What Warlog Spec does with it | Direction |
|---|---|---|---|
| **OCSF** (Splunk / AWS / Cisco / IBM) | Schemas for security event telemetry (raw signals) | We **consume** OCSF events. Each event becomes a `TriggerSignalRef` in an `AuditRow`. The OCSF payload is hashed (content_hash) and the hash is embedded in the audit chain. | consume |
| **STIX 2.1** (OASIS) | Threat intelligence object model (Indicator, Report, Course of Action, Incident, …) | We **import** STIX bundles into `ExtractedIOC`, `EnrichmentAssessment`, and KB articles. STIX `Course of Action` maps to our `PlaybookCandidate`. STIX `Incident` correlates to a case in your runtime ; the spec does not standardize incident-shape (UI projection layer, out of scope). | translate |
| **OpenC2** (OASIS) | Command-and-control language for response actions | We **map** ~half our `ResponseActionId` catalog to OpenC2 atoms (`deny`, `contain`, `delete`, …). Connectors MAY wrap an OpenC2 endpoint behind the ABI ; we are not OpenC2-conformant by construction. | translate (partial) |
| **CACAO** (OASIS) | Cyber playbook representation language | We **complement** CACAO. A `PlaybookCandidateProposal` references a playbook by id ; that id MAY resolve to a CACAO document. Warlog playbooks themselves are simpler than CACAO and target the Warlog runtime, not portable execution. | complement |
| **OSCAL** (NIST) | Open Security Controls Assessment Language — formalizes compliance frameworks, controls, profiles | We **complement** OSCAL. A `RiskArbitration` references the policy / control via `policyRef` ; that ref MAY resolve to an OSCAL profile or control id. OSCAL formalizes the *catalog* ; Warlog Spec formalizes the *runtime acknowledgment* of a control's acceptance. | complement |
| **Sigma** (SigmaHQ) | Detection rule language | We **compile** Sigma rules into an internal `DetectionRuleIR` (out of scope for this spec) — the rule's runtime hit becomes an `AuditRow.triggerSignalRef` with `kind=ocsf_event`. | consume |
| **MITRE ATT&CK** | Adversary tactics + techniques taxonomy | We **embed** ATT&CK ids in `MitreAssessment.mitre.tactics` / `.techniques`. No translation needed — we use the canonical identifiers verbatim. | embed |
| **MITRE D3FEND** | Defensive techniques + countermeasures | We **embed** D3FEND ids in `KbEnrichment.d3fend[]`. | embed |
| **MITRE CAPEC / CWE** | Attack patterns + weakness enumeration | We **embed** their ids in `KbEnrichment.capec[]` / `.cwe[]`. | embed |

## What's new in Warlog Spec

Three concepts have no direct equivalent in the standards above :

1. **Cryptographic decision-to-execution chain.** An `AuditRow` ties a
   signed `DecisionRef` (proposal, arbitration, approval) to a signed
   `TriggerSignalRef` (upstream signal) to the actual `ResponseActionId`
   that ran. OpenC2 has the action verb but no doctrine on what
   authorized it. OSCAL has the control but no runtime trace of when
   it was applied. STIX has the incident shape but not the per-action
   audit row.

2. **Compliance scope tagging at action time.** `complianceScope` on
   each `AuditRow` ("nis2", "dora", "pci_dss_v4", …) is what lets a
   regulated tenant filter audit history by jurisdiction without
   parsing free-form metadata. OSCAL formalizes the framework ; we
   formalize the *act's membership* in a framework.

3. **EU AI Act traceability for automated decisions.** `AiAgentRef`
   (model, modelVersion, systemPromptHash, agentRunId) inside
   `AutomationActor` makes an autonomous-agent action auditable to
   the model identity and pinned system prompt. No equivalent in
   OCSF / STIX / OpenC2.

## Per-standard detail

### OCSF (Open Cybersecurity Schema Framework)

**Their scope.** Normalized schemas for security telemetry : Detection
Findings, Authentication, Network Activity, File Activity, … OCSF
answers "what happened on the wire" with a vendor-neutral event
shape.

**Our position.** OCSF is upstream of warlog-spec. An OCSF event
hitting our pipeline gets stamped into a `TriggerSignalRef` :

```json
{
  "kind": "ocsf_event",
  "sourceId": "ocsf-event-01HK7Z8M9XQYR4VTBN2WJC5ABC",
  "contentHash": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"
}
```

The `sourceId` references the original event ; the `contentHash` is
sha256 of the canonical-bytes serialization of the OCSF payload. A
verifier fetches the event by id and confirms the hash matches —
proving the AuditRow was triggered by that specific event, not a
substituted one.

OCSF defines the event shape ; warlog-spec defines the audit-row
shape that points back at it. The two are complementary by design.

The reference packages include a first inbound mapper for OCSF
Detection Finding events:

- Python: `warlog_spec.ocsf.map_ocsf_detection_finding(event)`
- TypeScript: `mapOcsfDetectionFinding(event)` from `@warlog/spec`

The mapper emits existing Warlog Spec shapes only: `TriggerSignalRef`,
`ClassificationAssessment`, `EnrichmentAssessment`, and, when OCSF
`attacks[]` is present, `MitreAssessment`. It hashes the original OCSF
payload with stable sorted-key JSON and carries that hash in the
`TriggerSignalRef`. It does not publish a Warlog alert runtime envelope,
queue, dedup store, or tenant routing policy.

### STIX 2.1

**Their scope.** Threat intelligence object graph : Indicators,
Reports, Notes, Courses of Action, Incidents, Identities,
Relationships.

**Our position.** STIX is a richer threat-intel envelope than we
need at runtime, so we **translate inbound** :

| STIX object | warlog-spec destination |
|---|---|
| `indicator` | `ExtractedIOC` (with the same `ioc_type` enum) |
| `report` / `note` | KB article (out of spec scope, internal to the runtime) |
| `course-of-action` | `PlaybookCandidate.playbookId` references it externally |
| `incident` | correlates to a case in your runtime ; the incident-shape itself is operator-specific UI projection, out of spec scope |
| `identity` (actor) | `AuditActor` (Human) or `ArbitrationAuthority` (in `RiskArbitration`) |

We do not produce STIX outbound today. A future RFC may add a STIX
outbound projection (proposed `case-return-summary → STIX Note`).

### OpenC2

**Their scope.** Command-and-control language for security operations.
Atoms like `contain`, `deny`, `delete`, `query`, `set`, `update`
with targets and actuator profiles.

**Our position.** We translate **outbound** when a connector wraps
an OpenC2 endpoint :

| Warlog `ResponseActionId` | OpenC2 atom + actuator |
|---|---|
| `host.isolate` | `contain` on `device` (SLPF / endpoint actuator) |
| `host.unisolate` | `allow` on `device` |
| `ip.block` / `domain.block` / `url.block` | `deny` on `ipv4_net` / `domain_name` / `uri` |
| `ip.unblock` / `domain.unblock` / `url.unblock` | `allow` on same targets |
| `file.delete` / `file.quarantine` | `delete` / `contain` on `file` |
| `process.kill` | `delete` on `process` |
| `user.disable` / `user.force_logout` | `set` on `user_account` (status) |
| `email.quarantine` | `contain` on `email` |

About half the catalog has a clean OpenC2 mapping ; the cloud-family
actions (`iam.*`, `key.*`, `bucket.*`) and the case-management actions
(`alert.acknowledge`, `case.update_status`) are outside OpenC2's
target taxonomy. A vendor-neutral connector layer is the point —
adopters MAY wrap their OpenC2 endpoint as a warlog-spec connector
without restating the action vocabulary.

### CACAO

**Their scope.** Cyber playbook representation language — a portable
JSON document describing a step-by-step incident response procedure.

**Our position.** Complementary. Warlog playbooks target the Warlog
runtime ; CACAO targets portability across orchestrators. A
`PlaybookCandidateProposal.candidatePlaybooks[].playbookId` MAY
resolve to a CACAO document in a tenant-specific registry.

A future RFC may add a CACAO inbound importer (CACAO playbook ID →
Warlog playbook id mapping). Not in scope today.

### OSCAL (NIST)

**Their scope.** Open Security Controls Assessment Language. Profiles
that pick controls from a framework catalog (NIST 800-53, ISO 27001,
PCI DSS, …) and document how each control is assessed.

**Our position.** Complementary, with a clean integration point.
A `RiskArbitration.policyRef` carries a `policyKind` + `policyId` +
optional `version`. We do **not** define what that policyId points
at ; an operator MAY make it an OSCAL profile id, an internal SOP
reference, a confluence page id, or any other format their substrate
uses.

```json
{
  "policyKind": "oscal_profile",
  "policyId": "https://oscal.example.org/profiles/nis2-2026.json#sa-12",
  "version": "2026.04"
}
```

OSCAL formalizes *the catalog of controls and their assessment* ;
warlog-spec formalizes *the runtime trace of a control's acceptance*.
You can have warlog-spec without OSCAL (just put a confluence id in
`policyId`). You can have OSCAL without warlog-spec (just document
controls without an audit chain). Together you get a closed loop :
OSCAL says what the control is, warlog-spec says when it was applied.

### Sigma

**Their scope.** YAML-based detection rule language with a community-
maintained corpus of ~3000+ rules.

**Our position.** Consume. A Sigma rule hit produces an alert via our
internal `DetectionRuleIR` (out of spec scope). The resulting alert
becomes the `triggerSignalRef.sourceId` on every `AuditRow` for
actions taken in response to that alert.

### MITRE ATT&CK / D3FEND / CAPEC / CWE

**Their scope.** Adversary techniques (ATT&CK), defensive techniques
(D3FEND), attack patterns (CAPEC), software weaknesses (CWE) —
canonical identifier systems.

**Our position.** Embed. We use their identifiers verbatim :

- `MitreAssessment.mitre.tactics[]` carries ATT&CK tactic ids (TA0002, TA0007, …)
- `MitreAssessment.mitre.techniques[]` carries technique ids (T1059.001, T1078.004, …)
- `KbEnrichment.d3fend[].id` carries D3FEND defensive technique ids
- `KbEnrichment.capec[].id` carries CAPEC attack pattern ids
- `KbEnrichment.cwe[].id` carries CWE weakness ids

No translation needed. The MITRE ecosystem is the shared vocabulary
of the entire industry ; we adopt it as-is.

## Open questions

- **STIX 2.2 (when it ships).** Re-evaluate the inbound projections
  if the object model changes materially.
- **OpenC2 v1.1 actuator profiles.** Track new actuator profiles (e.g.
  for cloud IAM) and refresh the mapping table.
- **OCSF v2.x event categories.** New categories may unlock more
  granular `triggerSignalRef.kind` enum values (today : `ocsf_event`
  is a single kind ; a future RFC could subdivide).
- **CACAO playbook importer.** A bidirectional projection
  (CACAO playbook ↔ Warlog playbook) is on the roadmap but not yet
  scoped.
