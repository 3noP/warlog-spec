---
RFC: 0002
Title: AiAgentRef extensions for multi-agent and tool-using compositions
Author: Warlog Spec maintainers
Status: Accepted, Implemented
Created: 2026-05-20
Requires: 0001
Supersedes:
Superseded-By:
---

# RFC-0002 — AiAgentRef extensions for multi-agent and tool-using compositions

## Abstract

`AiAgentRef` v1 (RFC 0001) captures a single-model agent : one model
identity, one system prompt hash, one run id. Real autonomous SOC
agents in 2026 use multi-step compositions (planner → executor →
critic), call MCP tools and SDK functions, and ground their
decisions with retrieval. This RFC extends `AiAgentRef` with four
additional fields — `subAgents`, `toolsManifestHash`,
`retrievalContextRef`, `compositionKind` — so audit rows produced by
those agents stay auditable end-to-end. The extension is additive ;
existing single-agent rows remain valid without change.

## Motivation

The article that motivates warlog-spec is explicit about the
hallucination-of-action risk : an agent navigates a vector space of
intentions and a small input perturbation flips the trajectory. The
v1 `AiAgentRef` lets an auditor reconstruct *which model with which
system prompt* signed off on an action. That's the **single-agent
attribution surface**.

What it does NOT capture, in 2026 :

1. **Multi-agent compositions.** A planner emits a sub-plan ; an
   executor calls connectors based on it ; a critic verifies the
   outcome. The "actor" of the final apply step is the executor, but
   the actual *authority chain* spans three model instances. An
   auditor reading only the executor's `AiAgentRef` does not see that
   the plan was issued by a different model with a different system
   prompt.

2. **Tool / MCP server identity.** An autonomous agent that calls
   `kubectl`, an internal CMDB SDK, an MCP server exposing the
   tenant's secret manager — the agent's behaviour depends on the
   exact tool surface available at decision time. Two runs with the
   same model + system prompt but different tool manifests produce
   different actions. The auditor has to know the manifest.

3. **Retrieval context.** A RAG-grounded agent's decision depends
   on the documents it retrieved at decision time. Without a
   reference to that context (typically a frozen retrieval snapshot
   or vector-store query), the auditor cannot reproduce the agent's
   reasoning.

4. **Composition taxonomy.** "What kind of agent system was this ?"
   is a question an EU AI Act auditor will ask. A soft enum lets
   tenants tag their patterns without inventing fields per pattern.

This RFC closes those four gaps with optional, additive fields. v1
single-agent rows remain valid ; producers opt into the richer
attribution as their architecture grows.

## Specification

### Extended `AiAgentRef` shape

Four new optional fields land alongside the v1 shape :

| Field | Type | Required | Purpose |
|---|---|---|---|
| `subAgents` | `list[AiAgentRef]` | no | When this row was emitted by an orchestrator-composed agent, the chain of sub-agents that participated. Recursive — a sub-agent can itself have sub-agents. Empty / absent means "single agent". |
| `toolsManifestHash` | `str` (sha256 hex, 64 chars) | no | sha256 of the canonical-bytes serialization of the tool / MCP-server manifest available to the agent at decision time. Reproducible only via a frozen manifest snapshot. |
| `retrievalContextRef` | `str` | no | Opaque reference to the retrieval context (RAG snapshot, vector-store query id, document set hash) the agent had at decision time. Operator-defined format. |
| `compositionKind` | enum | no | Taxonomy tag : `single` (default behaviour, equivalent to absence), `orchestrator` (this agent dispatches sub-agents), `delegated` (this agent received a delegated sub-task from a parent), `tool_using` (this agent's decisions are dominated by tool calls), `retrieval_augmented` (this agent's decisions are dominated by retrieved context), `composite` (mix). Open via additive minor RFCs. |

### Example : single-agent (unchanged)

```json
{
  "model": "claude-opus-4-7",
  "modelVersion": "2026-04-15-build-c7d2e1",
  "systemPromptHash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "agentRunId": "run-7e2f1c44-9a8d-4c63-b0a1-3f5e8d7c9b21",
  "reasoningArtifactRef": "s3://warlog-reasoning/2026/05/run-7e2f1c44.json"
}
```

This is still a valid `AiAgentRef`. The four new fields default to
`null` / absent.

### Example : orchestrator emitting an action via an executor

The executor's `AiAgentRef` (the one embedded in the apply-phase
`AuditRow.actor.agent`) :

```json
{
  "model": "claude-opus-4-7",
  "modelVersion": "2026-04-15-build-c7d2e1",
  "systemPromptHash": "<executor-prompt-hash>",
  "agentRunId": "run-executor-001",
  "reasoningArtifactRef": "s3://warlog-reasoning/run-executor-001.json",
  "compositionKind": "delegated",
  "toolsManifestHash": "<manifest-hash>",
  "subAgents": [
    {
      "model": "claude-opus-4-7",
      "modelVersion": "2026-04-15-build-c7d2e1",
      "systemPromptHash": "<planner-prompt-hash>",
      "agentRunId": "run-planner-001",
      "reasoningArtifactRef": "s3://warlog-reasoning/run-planner-001.json",
      "compositionKind": "orchestrator"
    }
  ]
}
```

An auditor walking this row can :

1. Verify the executor's identity against its model registry.
2. Recompute the system-prompt hashes from the frozen prompt corpus.
3. Resolve the planner's reasoning artifact and confirm it issued
   the sub-plan the executor acted on.
4. Recompute the tools-manifest hash against the manifest snapshot
   and confirm no out-of-band tool was injected at decision time.

### Recursion bounds

`subAgents` is recursive. Producers SHOULD keep the chain shallow
(typical depth : 1-3). Consumers MUST tolerate arbitrary depth but
MAY enforce a tenant-configured maximum (recommended : 8) and reject
the row with a `POLICY` failure when exceeded — a 50-deep agent
chain is almost certainly a producer bug.

### Canonicalization

The canonicalize_v1 format absorbs the new fields naturally
(sorted-keys JSON walks them via the existing recursive sort). When
all four new fields are absent on a row, the canonical bytes are
identical to the v1 single-agent canonical bytes — the extension
is byte-stable backward.

## Design rationale

**Why nest `subAgents` recursively rather than flatten the chain ?**
Flat lists lose the parent-child semantics. An orchestrator that
dispatches three peer sub-agents reads identically to a deep linear
chain when flattened. The recursion makes the topology legible at
the audit-walking step.

**Why a hash of the tools manifest rather than the manifest inline ?**
Tool manifests can be large (an MCP catalog with 100+ tools, each
with 200-byte schemas). Inlining them in every audit row blows up
the chain. The hash references a frozen-once-per-agent-version
manifest stored tenant-side ; the auditor fetches once and verifies
many rows against the same snapshot.

**Why `compositionKind` as a soft enum rather than derived from
field presence ?** Two reasons. (1) An agent that uses a single
tool isn't necessarily "tool_using" in the architectural sense — the
producer's intent matters. (2) Future composition patterns (swarm,
hierarchical, recursive-self-improvement) need a stable extension
point. The enum is the explicit dial.

**Why optional ?** v1 single-agent rows already exist (RFC 0001
shipped, implementations live). Making the new fields REQUIRED
would break every existing producer. Optional + default-absent
means rows produced before this RFC validate unchanged.

## Alternatives considered

### A. Don't extend `AiAgentRef` — make a separate `AgentCompositionRef`

Pros : keeps `AiAgentRef` minimal. Cons : (1) auditors have to
correlate two refs per row to reconstruct the chain ; (2) the
existing `AutomationActor` would need to embed two refs instead of
one, growing the actor shape. Rejected because compositions are
fundamentally agent metadata, not separate decoration.

### B. Inline the tool manifest in `AiAgentRef`

Pros : self-contained — no external lookup. Cons : (1) bloats every
audit row (often by 5-50x) ; (2) the same manifest content gets
re-serialized in N rows, wasting storage and breaking the "lean
chain" doctrine. Rejected in favour of the hash + tenant-side
snapshot store.

### C. Use a single free-form `composition: dict` field

Pros : maximum extensibility — any future shape lands without an
RFC. Cons : opacity defeats the audit purpose. An auditor reading
`composition = { "foo": "bar", "ts_at": 42 }` can't verify
anything. Typed fields are what makes the trust layer trustable.

### D. Mandatory parent-id rather than embedded `subAgents`

Pros : flat storage model (each agent run has a `parentRunId`).
Cons : the audit chain holds the `AuditRow` only ; reconstructing
the agent topology requires joining against a separate agent-runs
table that the spec doesn't formalize. The embedded approach keeps
the chain self-contained.

## Backward compatibility

Additive. All four new fields default to absent. v1 single-agent
`AiAgentRef` instances continue to validate against the extended
schema. `canonicalize_v1` produces byte-identical output for v1
rows that omit the new fields.

Producers MAY upgrade incrementally :

1. Start emitting `compositionKind: "single"` (a no-op tag).
2. Add `toolsManifestHash` when the tool manifest is frozen.
3. Add `retrievalContextRef` when retrieval context is captured.
4. Add `subAgents` when an orchestrator topology is implemented.

Consumers MUST tolerate the new fields when present. A consumer that
ignores them surfaces the row as a v1 single-agent row, which is
correct behaviour (the v1 attribution remains valid).

## Reference implementation

- `warlog-spec-py` : extended `AiAgentRef` in
  `packages/warlog-spec-py/src/warlog_spec/provider_abi.py`.
- `@warlog/spec` : extended Zod schema in
  `packages/warlog-spec-ts/src/provider-abi.ts`.
- Schemas regenerated under `warlog-spec/schemas/provider-abi/`.
- Tests : `tests/test_smoke.py` covers single-agent (v1) + multi-agent
  (v2) round-trip. TS `tests/abi.test.ts` extended with composition
  validation.

## Open questions

- **Tool-call trace embedding.** Should an individual tool call
  invocation (call site + arguments + result) be addressable from
  `AiAgentRef` ? Today it's bundled into the opaque
  `reasoningArtifactRef`. A future RFC may formalize a
  `toolCallTrace[]` shape.
- **Cross-vendor agent identity.** When an agent runs on Anthropic
  but uses tool servers hosted by OpenAI, the `model` field is
  single-vendor. A future RFC may add a `vendorIdentity` field.
- **Agent provenance for non-LLM automation.** Rule engines, ML
  classifiers, and finite-state automation are tagged as
  `AutomationActor` but `AiAgentRef.model` defaults to the LLM
  taxonomy. A future RFC may carve out a sibling shape.

## References

- RFC-0001 — the v1 `AiAgentRef` shape this RFC extends.
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) Art. 12.
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — the canonical tool-server interface this RFC's `toolsManifestHash` typically references.
- `warlog-spec/docs/ECOSYSTEM-MAPPING.md` — how `AiAgentRef` interacts with the ecosystem standards.
