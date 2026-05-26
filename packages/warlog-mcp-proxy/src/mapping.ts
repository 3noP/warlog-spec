/**
 * MCP tool name ↔ Warlog action_id mapping.
 *
 * The mapping is loaded from a YAML file at startup and frozen for the
 * proxy's lifetime. Dynamic fuzzy-matching is intentionally not supported :
 * a security-operations team must be able to audit a static, versioned
 * file to certify what the proxy will sign.
 */

import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";

import { ApprovalLevel, ResponseActionId } from "@warlog/spec";
import type { ApprovalLevelValue, ComplianceScopeValue, ResponseActionIdValue } from "@warlog/spec";

// Re-exported by this module so consumers don't need to import the
// granular value-type variants from @warlog/spec themselves.
export type { ComplianceScopeValue as ComplianceScope } from "@warlog/spec";

export interface ToolMapping {
  /** Canonical Warlog action this MCP tool maps to. */
  actionId: ResponseActionIdValue;
  /** Name of the JSON-RPC ``params.arguments`` key holding the subject. */
  subjectParam: string;
  /** Compliance perimeters this action touches. */
  complianceScope: ComplianceScopeValue[];
  /** Optional synchronous approval policy for this tool mapping. */
  approval: ApprovalPolicy | null;
}

export interface ApprovalPolicy {
  /** Static decision applied by the proxy before forwarding. */
  state: "approved" | "denied" | "pending";
  /** Operator-facing approval level used in audit/error messages. */
  level: ApprovalLevelValue;
  /** Human-readable policy rationale. */
  rationale: string;
}

export interface MappingFile {
  /** Tenant identity for the audit chain (e.g. ``acme-eu``). */
  tenantId: string;
  /** Connector id surfaced on each emitted AuditRow. */
  connectorId: string;
  /** Connector version surfaced on each emitted AuditRow. */
  connectorVersion: string;
  /** Selector_key_id surfaced on pseudonymized subjects. */
  selectorKeyId: string;
  /** Per-tool mapping table — keyed by MCP tool name. */
  toolMappings: Map<string, ToolMapping>;
}

const ALLOWED_COMPLIANCE: Set<string> = new Set([
  "nis2",
  "dora",
  "pci_dss_v4",
  "sox",
  "hds",
  "secnumcloud",
  "hipaa",
  "gdpr",
  "iso_27001",
]);

interface RawMappingFile {
  spec_version?: string;
  tenant_id?: string;
  connector_id?: string;
  connector_version?: string;
  selector_key_id?: string;
  tool_mappings?: Record<string, RawToolMapping>;
}

interface RawToolMapping {
  action_id?: string;
  subject_param?: string;
  compliance_scope?: string[];
  approval?: RawApprovalPolicy;
}

interface RawApprovalPolicy {
  required?: boolean;
  state?: string;
  level?: string;
  rationale?: string;
}

/** Parse + validate a YAML mapping file. Throws on any inconsistency. */
export function loadMappingFile(path: string): MappingFile {
  const text = readFileSync(path, "utf-8");
  const raw = parseYaml(text) as RawMappingFile | null;
  if (!raw || typeof raw !== "object") {
    throw new Error(`Mapping file ${path} did not parse as a YAML object`);
  }

  if (!raw.tenant_id) {
    throw new Error(`Mapping file ${path} missing required field 'tenant_id'`);
  }
  if (!raw.connector_id) {
    throw new Error(`Mapping file ${path} missing required field 'connector_id'`);
  }
  if (!raw.selector_key_id) {
    throw new Error(`Mapping file ${path} missing required field 'selector_key_id'`);
  }
  if (!raw.tool_mappings || typeof raw.tool_mappings !== "object") {
    throw new Error(`Mapping file ${path} missing required object 'tool_mappings'`);
  }

  const validActions = new Set<string>(ResponseActionId.options);
  const mappings = new Map<string, ToolMapping>();
  for (const [toolName, entry] of Object.entries(raw.tool_mappings)) {
    if (!entry.action_id) {
      throw new Error(`tool_mappings[${toolName}] missing 'action_id'`);
    }
    if (!validActions.has(entry.action_id)) {
      throw new Error(
        `tool_mappings[${toolName}].action_id = '${entry.action_id}' is not a canonical ResponseActionId`,
      );
    }
    if (!entry.subject_param) {
      throw new Error(`tool_mappings[${toolName}] missing 'subject_param'`);
    }
    const scopes: ComplianceScopeValue[] = [];
    for (const c of entry.compliance_scope ?? []) {
      if (!ALLOWED_COMPLIANCE.has(c)) {
        throw new Error(
          `tool_mappings[${toolName}].compliance_scope contains unknown value '${c}'`,
        );
      }
      scopes.push(c as ComplianceScopeValue);
    }
    mappings.set(toolName, {
      actionId: entry.action_id as ResponseActionIdValue,
      subjectParam: entry.subject_param,
      complianceScope: scopes,
      approval: parseApprovalPolicy(path, toolName, entry.approval),
    });
  }

  return {
    tenantId: raw.tenant_id,
    connectorId: raw.connector_id,
    connectorVersion: raw.connector_version ?? "0.1.0",
    selectorKeyId: raw.selector_key_id,
    toolMappings: mappings,
  };
}

function parseApprovalPolicy(
  path: string,
  toolName: string,
  approval: RawApprovalPolicy | undefined,
): ApprovalPolicy | null {
  if (approval === undefined) return null;
  if (typeof approval !== "object" || approval === null) {
    throw new Error(`tool_mappings[${toolName}].approval in ${path} must be an object`);
  }
  if (approval.required === false) return null;

  const state = approval.state ?? "pending";
  if (state !== "approved" && state !== "denied" && state !== "pending") {
    throw new Error(
      `tool_mappings[${toolName}].approval.state must be one of approved, denied, pending`,
    );
  }

  const level = approval.level ?? "senior";
  if (!ApprovalLevel.options.includes(level as ApprovalLevelValue)) {
    throw new Error(`tool_mappings[${toolName}].approval.level is not a valid ApprovalLevel`);
  }

  return {
    state,
    level: level as ApprovalLevelValue,
    rationale: approval.rationale ?? `${level} approval required before forwarding MCP tool '${toolName}'`,
  };
}
