/**
 * Tests for the YAML mapping loader.
 *
 * The mapping file is the static, versioned source of truth that an
 * RSSI can review in Git — these tests pin every validation invariant
 * we promise the operator.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadMappingFile } from "../src/mapping.js";

let tmp: string;

beforeEach(() => {
  tmp = join(tmpdir(), `warlog-mcp-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tmp, { recursive: true });
});

afterEach(() => {
  // Best-effort cleanup ; we don't fail the test on rm errors.
});

function write(name: string, body: string): string {
  const path = join(tmp, name);
  writeFileSync(path, body, "utf-8");
  return path;
}

const VALID = `
spec_version: "1.0"
tenant_id: "acme-eu"
connector_id: "mcp.okta_proxy"
connector_version: "0.1.0"
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
      rationale: "senior approval required for destructive identity action"
  okta_disable_user:
    action_id: "user.disable"
    subject_param: "user_id"
    compliance_scope: ["gdpr"]
`;

describe("loadMappingFile", () => {
  it("parses a valid mapping file", () => {
    const path = write("ok.yml", VALID);
    const file = loadMappingFile(path);
    expect(file.tenantId).toBe("acme-eu");
    expect(file.connectorId).toBe("mcp.okta_proxy");
    expect(file.connectorVersion).toBe("0.1.0");
    expect(file.selectorKeyId).toBe("tenant:acme-eu:salt:v3");
    expect(file.toolMappings.size).toBe(2);
    const mapping = file.toolMappings.get("okta_delete_user_session");
    expect(mapping?.actionId).toBe("user.revoke_tokens");
    expect(mapping?.subjectParam).toBe("user_id");
    expect(mapping?.complianceScope).toEqual(["gdpr", "nis2"]);
    expect(mapping?.approval).toEqual({
      state: "pending",
      level: "senior",
      rationale: "senior approval required for destructive identity action",
    });
    expect(file.toolMappings.get("okta_disable_user")?.approval).toBeNull();
  });

  it("rejects missing tenant_id", () => {
    const path = write("no-tenant.yml", VALID.replace(/tenant_id: ".*"\n/, ""));
    expect(() => loadMappingFile(path)).toThrow(/tenant_id/);
  });

  it("rejects missing connector_id", () => {
    const path = write("no-conn.yml", VALID.replace(/connector_id: ".*"\n/, ""));
    expect(() => loadMappingFile(path)).toThrow(/connector_id/);
  });

  it("rejects missing selector_key_id", () => {
    const path = write("no-sel.yml", VALID.replace(/selector_key_id: ".*"\n/, ""));
    expect(() => loadMappingFile(path)).toThrow(/selector_key_id/);
  });

  it("rejects an action_id that is not in the canonical catalog", () => {
    const path = write(
      "bad-action.yml",
      VALID.replace('"user.revoke_tokens"', '"user.frobnicate"'),
    );
    expect(() => loadMappingFile(path)).toThrow(/canonical ResponseActionId/);
  });

  it("rejects an unknown compliance scope value", () => {
    const path = write("bad-scope.yml", VALID.replace('["gdpr", "nis2"]', '["gdpr", "ccpa"]'));
    expect(() => loadMappingFile(path)).toThrow(/compliance_scope.*ccpa/);
  });

  it("rejects missing subject_param on a mapping", () => {
    const path = write(
      "no-subject.yml",
      VALID.replace(/subject_param: "user_id"\n    compliance_scope/, "compliance_scope"),
    );
    expect(() => loadMappingFile(path)).toThrow(/subject_param/);
  });

  it("defaults required approval to pending senior", () => {
    const path = write(
      "approval-default.yml",
      VALID.replace(
        /approval:\n      required: true\n      state: "pending"\n      level: "senior"\n      rationale: "senior approval required for destructive identity action"\n/,
        "approval:\n      required: true\n",
      ),
    );
    const file = loadMappingFile(path);
    expect(file.toolMappings.get("okta_delete_user_session")?.approval).toEqual({
      state: "pending",
      level: "senior",
      rationale:
        "senior approval required before forwarding MCP tool 'okta_delete_user_session'",
    });
  });

  it("treats approval.required=false as no approval policy", () => {
    const path = write(
      "approval-disabled.yml",
      VALID.replace(
        /approval:\n      required: true\n      state: "pending"\n      level: "senior"\n      rationale: "senior approval required for destructive identity action"\n/,
        "approval:\n      required: false\n",
      ),
    );
    const file = loadMappingFile(path);
    expect(file.toolMappings.get("okta_delete_user_session")?.approval).toBeNull();
  });

  it("rejects an unknown approval state", () => {
    const path = write("bad-approval-state.yml", VALID.replace('state: "pending"', 'state: "maybe"'));
    expect(() => loadMappingFile(path)).toThrow(/approval\.state/);
  });

  it("rejects an unknown approval level", () => {
    const path = write("bad-approval-level.yml", VALID.replace('level: "senior"', 'level: "root"'));
    expect(() => loadMappingFile(path)).toThrow(/approval\.level/);
  });
});
