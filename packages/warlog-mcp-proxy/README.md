# @warlog/mcp-proxy

> Transparent audit middleware for the Model Context Protocol (MCP).
> Sits between any MCP client (Claude Desktop, Cursor, Cline) and any
> MCP server (okta-mcp, falcon-mcp, slack-mcp, ...), signing mapped
> `tools/call` requests with the Warlog trust-layer contract and
> enforcing optional approval policy before forwarding.

## What it does

`warlog-mcp-proxy wrap` spawns an MCP backend as a subprocess and
proxies the stdio JSON-RPC stream. Every mapped `tools/call` is
intercepted ; its parameters are mapped to a canonical
`ResponseActionId` from the Warlog spec ; the subject identifier is
pseudonymized (per the GDPR doctrine) ; optional static approval
policy is enforced ; signed `AuditRow` entries are appended to the
local HMAC chain ; then the original message is forwarded to the
backend only when the Warlog decision authorizes it.

The agent (Claude, Cursor, your custom MCP client) is unaware of the
proxy. The backend (okta-mcp, falcon-mcp) is unaware of the proxy.
For authorized calls, the backend receives the original message. For
pending or denied approval decisions, the backend is never called and
the MCP client receives a JSON-RPC error.

## Why this exists

Modern AI assistants ship with capability-granting tools (delete a
user, isolate a host, send an email). When the agent is Claude Desktop
or Cursor, the operator does not own the agent's runtime — they cannot
inject a Python decorator around every tool call. The MCP proxy is the
**operator-side** seam for adding cryptographic audit to actions the
agent issues against MCP backends.

For self-hosted AI agents in Python, see the in-process decorator at
[`warlog_spec.integrate`](https://github.com/3noP/warlog-spec/tree/main/packages/warlog-spec-py)
instead — same audit contract, zero subprocess.

## Install

```sh
npm install -g @warlog/mcp-proxy
# or run on demand
npx @warlog/mcp-proxy wrap --mapping /etc/warlog/okta-actions.yml -- uvx okta-mcp
```

## Usage

### 1. Write a mapping file

The mapping file is the static, versioned source of truth that pins
each MCP tool name to a canonical Warlog `action_id`. See
[`examples/okta-actions.yml`](examples/okta-actions.yml) for a
runnable Okta example.

```yaml
# /etc/warlog/okta-actions.yml
spec_version: "1.0"
tenant_id: "acme-eu"
connector_id: "mcp.okta_proxy"
selector_key_id: "tenant:acme-eu:salt:v3"

tool_mappings:
  okta_delete_user_session:
    action_id: "user.revoke_tokens"
    subject_param: "user_id"
    compliance_scope: ["gdpr", "nis2"]
    approval:
      required: true
      state: "pending"
      level: "senior"
      rationale: "Senior analyst approval required before token revocation."
```

Doctrine : automatic fuzzy-matching of tool names to action_ids is
intentionally not supported. If a sensitive action lands in your audit
chain with the wrong canonical id, the signature is valid but the
semantics are wrong — and an RSSI cannot reconstruct what really
happened. The proxy refuses to guess.

### 2. Wire it into Claude Desktop / Cursor / Cline

See [`examples/claude-desktop-config.jsonc`](examples/claude-desktop-config.jsonc)
for a full configuration. The shape :

```jsonc
{
  "mcpServers": {
    "okta-audited": {
      "command": "npx",
      "args": [
        "-y", "@warlog/mcp-proxy", "wrap",
        "--mapping", "/etc/warlog/okta-actions.yml",
        "--strict",
        "--",
        "uvx", "okta-mcp"
      ],
      "env": {
        "WARLOG_HMAC_SECRET": "...",
        "WARLOG_PII_SALT": "...",
        "WARLOG_AGENT_MODEL": "claude-opus-4-7",
        "WARLOG_AGENT_MODEL_VERSION": "2026-05-01",
        "WARLOG_AGENT_SYSTEM_PROMPT_HASH": "<64 hex chars>",
        "WARLOG_AGENT_RUN_ID": "claude-desktop-session-uuid",
        "WARLOG_ACTOR_ID": "claude.desktop.session",
        "WARLOG_AUDIT_LOG": "/var/log/warlog/mcp-audit.jsonl"
      }
    }
  }
}
```

### 3. Restart the MCP client, do tool calls normally

Every state-changing tool call now appends a signed `AuditRow` to
`/var/log/warlog/mcp-audit.jsonl`. Verify the chain with any
@warlog/spec-compatible verifier — the format is the same byte-stable
HMAC chain produced by `warlog_spec.audit_chain` in Python and
`@warlog/spec` audit-chain primitives in TypeScript.

## Approval gate

Mapped tools may declare a local, synchronous approval policy. This is
the MCP equivalent of the Python reference gate's blocking behavior,
adapted to the proxy's constraint that the audit chain must stay
synchronous.

```yaml
tool_mappings:
  okta_disable_user:
    action_id: "user.disable"
    subject_param: "user_id"
    compliance_scope: ["gdpr", "nis2"]
    approval:
      required: true
      state: "pending"   # approved | denied | pending
      level: "senior"    # none | analyst | senior | manager
      rationale: "Senior analyst approval required before disabling an identity."
```

Approval behavior:

| Mapping policy | Audit rows | Backend call |
|---|---|---|
| no `approval` block, or `required: false` | `apply/success` intent row | forwarded |
| `state: approved` | `approval/success`, then `apply/success` | forwarded |
| `state: pending` | `approval/pending_approval` | blocked with JSON-RPC `-32010` |
| `state: denied` | `approval/denied` | blocked with JSON-RPC `-32011` |

When a call is pending, the JSON-RPC error includes `auditId` and
`requestId`. The proxy is stateless: it does not poll for a later human
decision and it does not resume the blocked MCP request. Operators have
two supported patterns:

1. CLI/static policy: the human reviews the signed approval row, updates
  the YAML policy to `approved` or `denied`, restarts the MCP client or
  proxy so the frozen mapping is reloaded, then retries the tool call.
2. Embedded policy: programmatic users inject a synchronous
  `ApprovalGate` backed by SQLite, Redis, or a SOAR queue. On retry,
  the gate looks up the same deterministic `idempotencyKey` / returned
  `requestId` and returns the current human decision.

The CLI gate is intentionally static: it reads this decision from the
mapping file and applies it synchronously. Programmatic users can pass
their own synchronous `ApprovalGate` to `Auditor` to consult SQLite,
Redis, or an in-process policy cache, mirroring the Python reference
pattern. A networked async approval service would require a mutex around
the HMAC critical section described below. Until that runtime service
exists, this proxy favors a reviewable Git-controlled policy over a
hidden side channel.

## Strict vs loose mode

Without `--strict`, the proxy forwards unmapped tools without signing
them (and writes a warning to stderr). Use this in development.

With `--strict`, the proxy refuses unmapped tools with a JSON-RPC
error response. Use this in production — sensitive tools MUST be in
the mapping or they don't run.

## Required environment variables

| Variable | Purpose |
|---|---|
| `WARLOG_HMAC_SECRET` | HMAC key for the audit chain. Hold in HSM/KMS in prod. |
| `WARLOG_PII_SALT` | Per-tenant rotatable salt for `sha256_salted` subjects. |
| `WARLOG_AGENT_MODEL` | AI agent model id (e.g. `claude-opus-4-7`). |
| `WARLOG_AGENT_MODEL_VERSION` | Pinned model version (e.g. `2026-05-01`). |
| `WARLOG_AGENT_SYSTEM_PROMPT_HASH` | SHA-256 of the canonical system prompt, 64 hex chars. |
| `WARLOG_AGENT_RUN_ID` | UUID identifying this agent session. |
| `WARLOG_ACTOR_ID` | Stable id for the originating playbook / automation. |

Optional :

| Variable | Default | Purpose |
|---|---|---|
| `WARLOG_AUDIT_LOG` | `./warlog-mcp-audit.jsonl` | JSONL append-only audit file. |
| `WARLOG_AGENT_TOOLS_MANIFEST_HASH` | absent | SHA-256 of the canonical tool manifest the agent had at decision time. |
| `WARLOG_ALERT_ID` | absent | Upstream alert id that triggered the agent session. |
| `WARLOG_ALERT_PAYLOAD` | absent | Base64 of the raw alert bytes (used for `content_hash`). |

The proxy refuses to start if any required variable is unset or empty
— it will NEVER fall back to a default secret. A forgeable audit
chain is worse than no audit chain.

## Operational doctrine

### HMAC chain integrity is load-bearing on synchronous audit

The proxy's `Auditor.audit()` is intentionally synchronous. Node.js's
single-threaded event loop guarantees that parallel `tools/call`
requests arriving in the same I/O burst are processed strictly in
sequence — no two audits ever interleave their (head-signature →
sign → append) critical section.

If you fork this code and add `await` anywhere in the audit path
(e.g. to talk to an HTTP approval service), you MUST also wrap the
critical section in a mutex. Otherwise concurrent audits will read
the same `prev_hash`, compute conflicting signatures, and corrupt
the chain. The same `verify()` that catches a malicious byte-flip
will catch this race — but only after the damage is done. Keep the
audit synchronous, or guard it explicitly.

### Backend stdout buffering

The proxy spawns the backend with `PYTHONUNBUFFERED=1` in its
environment. This disables Python's stdout buffering when it would
otherwise hold a partial JSON-RPC message in an internal buffer
(triggered when the runtime detects stdout is not a TTY, which is
exactly our case). Without this, Python MCP backends deadlock the
proxy by withholding a full line.

Backends in other languages : Node MCP servers respect piped stdio's
natural line buffering and are fine. Go MCP servers using `bufio.Writer`
typically need an explicit `.Flush()` after each message — talk to
the operator if you adopt a Go backend and see freezes.

### One persister per audit log file

The current `JsonlAuditPersister` does not lock the file across
processes. Running two proxies that both write to the same audit log
file may interleave bytes mid-line on Linux when JSONL entries
exceed `PIPE_BUF` (4096 bytes on most kernels) — which our entries
typically do. Use one audit log per running proxy, or wrap the
persister with a file-lock library if multi-process is required.

## License

Apache 2.0. Same as `@warlog/spec` and `warlog-spec`.
