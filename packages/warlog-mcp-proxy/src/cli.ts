#!/usr/bin/env node
/**
 * warlog-mcp-proxy CLI.
 *
 * Usage :
 *   warlog-mcp-proxy wrap --mapping <file.yml> [--strict] -- <backend-cmd> [args...]
 *
 * Environment variables :
 *   WARLOG_HMAC_SECRET   (required) — HMAC key for the audit chain
 *   WARLOG_PII_SALT      (required) — salt for sha256_salted subject pseudonyms
 *   WARLOG_AUDIT_LOG     (optional, defaults to ./warlog-mcp-audit.jsonl)
 *   WARLOG_AGENT_MODEL                — AI agent model id (e.g. ``claude-opus-4-7``)
 *   WARLOG_AGENT_MODEL_VERSION        — pinned model version
 *   WARLOG_AGENT_RUN_ID               — UUID for this agent run cycle
 *   WARLOG_AGENT_SYSTEM_PROMPT_HASH   — sha256(system prompt), 64 hex chars
 *   WARLOG_AGENT_TOOLS_MANIFEST_HASH  — sha256(tools manifest), 64 hex chars (optional)
 *   WARLOG_ACTOR_ID                   — id of the playbook / automation (e.g. ``playbook.fraud_triage``)
 *   WARLOG_ALERT_ID                   — upstream alert id (optional)
 *   WARLOG_ALERT_PAYLOAD              — base64 of the raw alert bytes (optional)
 *
 * Example (Claude Desktop config) :
 *
 *   {
 *     "mcpServers": {
 *       "okta-audited": {
 *         "command": "npx",
 *         "args": [
 *           "@warlog/mcp-proxy", "wrap",
 *           "--mapping", "/etc/warlog/okta-actions.yml",
 *           "--",
 *           "uvx", "okta-mcp"
 *         ],
 *         "env": {
 *           "WARLOG_HMAC_SECRET": "...",
 *           "WARLOG_PII_SALT": "...",
 *           "WARLOG_AUDIT_LOG": "/var/log/warlog/audit.jsonl",
 *           "WARLOG_AGENT_MODEL": "claude-opus-4-7",
 *           "WARLOG_AGENT_MODEL_VERSION": "2026-05-01",
 *           "WARLOG_AGENT_RUN_ID": "...",
 *           "WARLOG_AGENT_SYSTEM_PROMPT_HASH": "..."
 *         }
 *       }
 *     }
 *   }
 */

import { createHash } from "node:crypto";

import type { AiAgentRef, TriggerSignalRef } from "@warlog/spec";

import { Auditor } from "./auditor.js";
import { loadMappingFile } from "./mapping.js";
import { JsonlAuditPersister } from "./persister.js";
import { runProxy } from "./proxy.js";

interface ParsedArgs {
  command: "wrap";
  mappingPath: string;
  strict: boolean;
  backend: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  if (argv.length < 1 || argv[0] !== "wrap") {
    throw new Error("Usage: warlog-mcp-proxy wrap --mapping <file.yml> [--strict] -- <backend...>");
  }
  const rest = argv.slice(1);
  let mappingPath: string | null = null;
  let strict = false;
  let sepIdx = -1;

  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!;
    if (token === "--") {
      sepIdx = i;
      break;
    }
    if (token === "--mapping") {
      mappingPath = rest[i + 1] ?? null;
      i++;
      continue;
    }
    if (token === "--strict") {
      strict = true;
      continue;
    }
    throw new Error(`Unrecognized argument '${token}'`);
  }

  if (!mappingPath) {
    throw new Error("--mapping <file.yml> is required");
  }
  if (sepIdx < 0) {
    throw new Error("Missing '--' separator before the backend command");
  }
  const backend = rest.slice(sepIdx + 1);
  if (backend.length === 0) {
    throw new Error("Backend command is empty after '--'");
  }

  return { command: "wrap", mappingPath, strict, backend };
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) {
    throw new Error(
      `Required environment variable '${name}' is not set ; warlog-mcp-proxy refuses to start ` +
        `with default secrets (the audit chain would be forgeable).`,
    );
  }
  return v;
}

function buildAgentRef(): AiAgentRef {
  const sysHash = requireEnv("WARLOG_AGENT_SYSTEM_PROMPT_HASH");
  if (!/^[0-9a-f]{64}$/.test(sysHash)) {
    throw new Error(
      "WARLOG_AGENT_SYSTEM_PROMPT_HASH must be a 64-character lowercase hex SHA-256 digest",
    );
  }
  const toolsHashRaw = process.env.WARLOG_AGENT_TOOLS_MANIFEST_HASH;
  if (toolsHashRaw && !/^[0-9a-f]{64}$/.test(toolsHashRaw)) {
    throw new Error(
      "WARLOG_AGENT_TOOLS_MANIFEST_HASH, when set, must be a 64-char lowercase hex SHA-256 digest",
    );
  }
  return {
    model: requireEnv("WARLOG_AGENT_MODEL"),
    modelVersion: requireEnv("WARLOG_AGENT_MODEL_VERSION"),
    systemPromptHash: sysHash,
    agentRunId: requireEnv("WARLOG_AGENT_RUN_ID"),
    reasoningArtifactRef: null,
    subAgents: [],
    toolsManifestHash: toolsHashRaw ?? null,
    retrievalContextRef: null,
    compositionKind: null,
  };
}

function buildTrigger(): TriggerSignalRef {
  const alertId = process.env.WARLOG_ALERT_ID ?? "";
  const payloadB64 = process.env.WARLOG_ALERT_PAYLOAD;
  if (!alertId) {
    return { kind: "manual", sourceId: "", contentHash: "" };
  }
  const bytes = payloadB64 ? Buffer.from(payloadB64, "base64") : Buffer.from("");
  const hash = createHash("sha256").update(bytes).digest("hex");
  return { kind: "alert", sourceId: alertId, contentHash: hash };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const mapping = loadMappingFile(args.mappingPath);

  const hmacSecret = Buffer.from(requireEnv("WARLOG_HMAC_SECRET"), "utf-8");
  const piiSalt = Buffer.from(requireEnv("WARLOG_PII_SALT"), "utf-8");
  const auditLog = process.env.WARLOG_AUDIT_LOG ?? "./warlog-mcp-audit.jsonl";

  const persister = new JsonlAuditPersister(auditLog);
  const auditor = new Auditor({
    mapping,
    persister,
    hmacSecret,
    piiSalt,
    context: {
      agent: buildAgentRef(),
      trigger: buildTrigger(),
      actorId: requireEnv("WARLOG_ACTOR_ID"),
    },
  });

  process.stderr.write(
    `[warlog-mcp] wrapping backend [${args.backend.join(" ")}] ; mapping=${args.mappingPath} ; ` +
      `audit=${auditLog} ; strict=${args.strict}\n`,
  );

  const code = await runProxy({
    backend: args.backend,
    auditor,
    strict: args.strict,
  });
  process.exit(code);
}

main().catch((err) => {
  process.stderr.write(`[warlog-mcp] fatal: ${err.message ?? err}\n`);
  process.exit(1);
});
