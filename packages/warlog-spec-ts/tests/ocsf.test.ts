import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalizeOcsfEvent, mapOcsfDetectionFinding } from "../src/ocsf.js";
import { TriggerSignalRef } from "../src/provider-abi.js";

const SAMPLE_DETECTION_FINDING = {
  class_name: "Detection Finding",
  class_uid: 2004,
  uid: "ocsf-event-001",
  time_dt: "2026-05-25T12:00:00Z",
  severity: "High",
  confidence_score: 87,
  type_name: "Process Activity: Malicious PowerShell",
  message: "Suspicious encoded PowerShell execution from Office parent.",
  finding: {
    title: "Encoded PowerShell from Office",
    desc: "Suspicious execution chain with external payload URL.",
  },
  attacks: [{ tactic_id: "TA0002", technique_id: "T1059.001" }],
  device: { hostname: "WIN-001", uid: "agent-001" },
  actor: { user: { name: "alice@warlog.demo" } },
  process: { name: "powershell.exe", cmd_line: "powershell -enc ..." },
  src_endpoint: { ip: "10.0.0.5" },
  observables: [
    { type_name: "URL", value: "https://evil.example/payload" },
    {
      type_name: "SHA256 Hash",
      value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
  ],
};

describe("OCSF Detection Finding mapper", () => {
  it("hashes stable canonical JSON", () => {
    const expected = createHash("sha256")
      .update(JSON.stringify(sortKeysDeep(SAMPLE_DETECTION_FINDING)), "utf-8")
      .digest("hex");

    expect(createHash("sha256").update(canonicalizeOcsfEvent(SAMPLE_DETECTION_FINDING)).digest("hex")).toBe(expected);
  });

  it("maps to Warlog trigger, classification, enrichment, and MITRE artifacts", () => {
    const mapped = mapOcsfDetectionFinding(SAMPLE_DETECTION_FINDING);

    expect(() => TriggerSignalRef.parse(mapped.triggerSignal)).not.toThrow();
    expect(mapped.triggerSignal.kind).toBe("ocsf_event");
    expect(mapped.triggerSignal.sourceId).toBe("ocsf-event-001");
    expect(mapped.triggerSignal.contentHash).toBe(mapped.sourceContentHash);

    expect(mapped.classification.classification.category).toBe("execution");
    expect(mapped.classification.classification.severity).toBe("high");
    expect(mapped.classification.classification.verdict).toBe("suspicious");
    expect(mapped.classification.classification.shouldEscalate).toBe(true);

    expect(mapped.mitre?.mitre.tactics).toEqual(["TA0002"]);
    expect(mapped.mitre?.mitre.techniques).toEqual(["T1059.001"]);

    const entities = new Set(
      mapped.enrichment.payload.relatedEntities.map(
        (entity) => `${entity.entityType}:${entity.value}`,
      ),
    );
    expect(entities).toContain("host:WIN-001");
    expect(entities).toContain("user:alice@warlog.demo");
    expect(entities).toContain("process:powershell.exe");

    const iocs = new Set(
      mapped.enrichment.payload.matchedIocs.map((ioc) => `${ioc.iocType}:${ioc.value}`),
    );
    expect(iocs).toContain("url:https://evil.example/payload");
    expect(iocs).toContain(
      "hash_sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("falls back for invalid OCSF timestamps without losing the source hash", () => {
    const event = { uid: "bad-time", time_dt: "not-a-date", severity: "Low" };

    const mapped = mapOcsfDetectionFinding(event);

    expect(mapped.classification.envelope.generatedAt).toBe("1970-01-01T00:00:00.000Z");
    expect(mapped.triggerSignal.contentHash).toBe(mapped.sourceContentHash);
  });
});

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    output[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
  }
  return output;
}